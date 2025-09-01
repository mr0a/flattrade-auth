import { createHash } from 'crypto';
import { authenticator } from 'otplib';
import { AUTH_CONSTANTS, ERRORS, STATUS } from './constants';
import { BaseApiResponse, ApiTokenResponse, RequestCodeResponse, FlattradeAuthResponse } from './types';

export class FlattradeAuth {
  /**
   * Static method to get authentication token from Flattrade API
   * @param account_id - Flattrade account ID
   * @param password - Account password
   * @param api_key - API key
   * @param totpSecret - TOTP secret for 2FA
   * @param authSecret - Authentication secret
   * @returns Promise<string> - Authentication token
   */
  static async getAPIAuthToken({
    account_id,
    password,
    api_key,
    totpSecret,
    authSecret
  }: {
    account_id: string;
    password: string;
    api_key: string;
    totpSecret: string;
    authSecret: string;
  }): Promise<FlattradeAuthResponse> {
    if (!account_id || !password || !api_key || !totpSecret || !authSecret) {
      throw new Error('All credentials are required');
    }

    const sidToken = await this.getSid();
    const { requestCode } = await this.getRequestCode(account_id, password, api_key, totpSecret, sidToken);

    const hash = createHash(AUTH_CONSTANTS.HASH_ALGORITHM);
    hash.update(api_key + requestCode + authSecret);
    const body = {
      api_key: api_key,
      request_code: requestCode,
      api_secret: hash.digest('hex'),
    };
    const token = await this.requestCodeToAuthToken(body);
    return {
      account_id: account_id,
      token
    };
  }

  /**
   * Private method to handle API response errors
   */
  private static handleApiResponseError(
    response: Response,
    responseJson: Partial<BaseApiResponse>,
    defaultErrorMessage: string = ERRORS.UNKNOWN_ERROR
  ): void {
    if (!response.ok || (responseJson && responseJson.stat && responseJson.stat !== STATUS.OK)) {
      const errorMessage = responseJson?.emsg || response.statusText || defaultErrorMessage;
      const finalMessage = `API Error: ${errorMessage} (Status: ${response.status}${responseJson?.stat ? `, API Stat: ${responseJson.stat}` : ''})`;
      throw new Error(finalMessage);
    }
    if (responseJson && responseJson.stat && responseJson.stat !== STATUS.OK && !responseJson.emsg) {
      throw new Error(`API Error: Received status ${responseJson.stat} without specific error message. (HTTP Status: ${response.status})`);
    }
  }

  /**
   * Private method to convert request code to auth token
   */
  private static async requestCodeToAuthToken(body: {
    api_key: string;
    request_code: string;
    api_secret: string;
  }): Promise<string> {
    const response = await fetch(AUTH_CONSTANTS.API_TOKEN_URL, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json' },
    });

    let responseJson: ApiTokenResponse;
    try {
      responseJson = await response.json() as ApiTokenResponse;
    } catch (e: any) {
      if (!response.ok) {
        throw new Error(`API Error: ${response.status} ${response.statusText}. Failed to parse JSON response.`);
      }
      throw new Error(`API Error: Successfully fetched but failed to parse JSON response. Original error: ${e.message}`);
    }

    this.handleApiResponseError(response, responseJson, "Error fetching API token");

    if (!responseJson.token) {
      throw new Error('API Error: Token not found in successful response.');
    }
    return responseJson.token;
  }

  /**
   * Private method to get request code
   */
  private static async getRequestCode(
    account_id: string,
    password: string,
    api_key: string,
    totpSecret: string,
    sidToken: string
  ): Promise<{ response: Response; requestCode: string }> {
    const body = {
      UserName: account_id,
      APIKey: api_key,
      Password: createHash(AUTH_CONSTANTS.HASH_ALGORITHM).update(password).digest('hex'),
      PAN_DOB: authenticator.generate(totpSecret),
      Sid: sidToken,
      Source: 'AUTHPAGE',
    };

    const response = await fetch(AUTH_CONSTANTS.AUTH_DIRECT_URL, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json' },
    });

    let responseJson: RequestCodeResponse;
    try {
      responseJson = await response.json() as RequestCodeResponse;
    } catch (e: any) {
      if (!response.ok) {
        throw new Error(`API Error: ${response.status} ${response.statusText}. Failed to parse JSON response for request code.`);
      }
      throw new Error(`API Error: Successfully fetched but failed to parse JSON response for request code. Original error: ${e.message}`);
    }

    this.handleApiResponseError(response, responseJson, "Error fetching request code");

    if (!responseJson.RedirectURL) {
      throw new Error(responseJson.emsg || 'API Error: RedirectURL is missing in successful response for request code.');
    }

    const parsedUrl = new URL(responseJson.RedirectURL);
    const urlParams = new URLSearchParams(parsedUrl.search);
    const requestCode = urlParams.get('code');

    if (requestCode === null) {
      throw new Error(responseJson.emsg || 'API Error: Request code not found in RedirectURL.');
    }
    return { response, requestCode };
  }

  /**
   * Private method to get SID token
   */
  private static async getSid(): Promise<string> {
    const sidTokenResponse = await fetch(AUTH_CONSTANTS.SID_URL, {
      headers: {
        'Referer': AUTH_CONSTANTS.BASE_URL,
      },
      method: 'POST',
    });

    if (!sidTokenResponse.ok) {
      let errorDetails = sidTokenResponse.statusText;
      try {
        const textError = await sidTokenResponse.text();
        if (textError) errorDetails = textError;
      } catch (e) {
        // Ignore error from .text() if response already errored
      }
      throw new Error(`API Error: Failed to fetch SID token. Status: ${sidTokenResponse.status}, Details: ${errorDetails}`);
    }

    const sidToken = await sidTokenResponse.text();
    if (!sidToken) {
      throw new Error('API Error: SID token received is empty.');
    }
    return sidToken;
  }
}