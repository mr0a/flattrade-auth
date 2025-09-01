import { FlattradeAuth } from '../flattrade-auth';
import { authenticator } from 'otplib';
import { AUTH_CONSTANTS, STATUS } from '../constants';
import { ApiTokenResponse, RequestCodeResponse } from '../types';

// Mock the otplib
jest.mock('otplib');

// Mock fetch globally
global.fetch = jest.fn();

describe('FlattradeAuth', () => {
  const mockCredentials = {
    account_id: 'test_account',
    password: 'test_password',
    api_key: 'test_api_key',
    totpSecret: 'test_totp_secret',
    authSecret: 'test_auth_secret'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (authenticator.generate as jest.Mock).mockReturnValue('123456');
    (fetch as jest.Mock).mockClear();
  });

  describe('getAPIAuthToken', () => {
    describe('Validation Errors', () => {
      it('should throw error when account_id is missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: '',
            password: 'test',
            api_key: 'test',
            totpSecret: 'test',
            authSecret: 'test'
          })
        ).rejects.toThrow('All credentials are required');
      });

      it('should throw error when password is missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: 'test',
            password: '',
            api_key: 'test',
            totpSecret: 'test',
            authSecret: 'test'
          })
        ).rejects.toThrow('All credentials are required');
      });

      it('should throw error when api_key is missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: 'test',
            password: 'test',
            api_key: '',
            totpSecret: 'test',
            authSecret: 'test'
          })
        ).rejects.toThrow('All credentials are required');
      });

      it('should throw error when totpSecret is missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: 'test',
            password: 'test',
            api_key: 'test',
            totpSecret: '',
            authSecret: 'test'
          })
        ).rejects.toThrow('All credentials are required');
      });

      it('should throw error when authSecret is missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: 'test',
            password: 'test',
            api_key: 'test',
            totpSecret: 'test',
            authSecret: ''
          })
        ).rejects.toThrow('All credentials are required');
      });

      it('should throw error when all credentials are missing', async () => {
        await expect(
          FlattradeAuth.getAPIAuthToken({
            account_id: '',
            password: '',
            api_key: '',
            totpSecret: '',
            authSecret: ''
          })
        ).rejects.toThrow('All credentials are required');
      });
    });

    describe('Valid Response', () => {
      it('should successfully return auth token for valid credentials', async () => {
        const mockSidResponse = 'mock_sid_token';
        const mockRequestCode = 'mock_request_code';
        const mockToken = 'mock_auth_token';

        // Mock getSid response
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            text: () => Promise.resolve(mockSidResponse),
          })
        );

        // Mock getRequestCode response
        const mockRequestCodeResponse: RequestCodeResponse = {
          stat: STATUS.OK,
          RedirectURL: `https://example.com/redirect?code=${mockRequestCode}&other=param`
        };
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockRequestCodeResponse),
          })
        );

        // Mock requestCodeToAuthToken response
        const mockTokenResponse: ApiTokenResponse = {
          stat: STATUS.OK,
          token: mockToken
        };
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockTokenResponse),
          })
        );

        const result = await FlattradeAuth.getAPIAuthToken(mockCredentials);
        
        const response = {
          account_id: mockCredentials.account_id,
          token: mockToken
        };
        expect(result).toEqual(response);
        expect(fetch).toHaveBeenCalledTimes(3);
        
        // Verify getSid call
        expect(fetch).toHaveBeenNthCalledWith(1, AUTH_CONSTANTS.SID_URL, {
          headers: {
            'Referer': AUTH_CONSTANTS.BASE_URL,
          },
          method: 'POST',
        });

        // Verify getRequestCode call
        expect(fetch).toHaveBeenNthCalledWith(2, AUTH_CONSTANTS.AUTH_DIRECT_URL, {
          method: 'POST',
          body: expect.stringContaining(mockCredentials.account_id),
          headers: { 'Content-Type': 'application/json' },
        });

        // Verify requestCodeToAuthToken call
        expect(fetch).toHaveBeenNthCalledWith(3, AUTH_CONSTANTS.API_TOKEN_URL, {
          method: 'POST',
          body: expect.stringContaining(mockCredentials.api_key),
          headers: { 'Content-Type': 'application/json' },
        });
      });
    });

    describe('API Errors', () => {
      describe('getSid Errors', () => {
        it('should throw error when getSid fails with HTTP error', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: false,
              status: 500,
              statusText: 'Internal Server Error',
              text: () => Promise.resolve('Server Error Details'),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Failed to fetch SID token. Status: 500, Details: Server Error Details');
        });

        it('should throw error when getSid returns empty response', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve(''),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: SID token received is empty.');
        });

        it('should handle text() error gracefully', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: false,
              status: 404,
              statusText: 'Not Found',
              text: () => Promise.reject(new Error('Text parsing failed')),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Failed to fetch SID token. Status: 404, Details: Not Found');
        });
      });

      describe('getRequestCode Errors', () => {
        beforeEach(() => {
          // Mock successful getSid
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve('mock_sid_token'),
            })
          );
        });

        it('should throw error when getRequestCode fails with HTTP error', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: false,
              status: 401,
              statusText: 'Unauthorized',
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: 401 Unauthorized. Failed to parse JSON response for request code.');
        });

        it('should throw error when getRequestCode returns invalid JSON', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.reject(new Error('Invalid JSON')),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Successfully fetched but failed to parse JSON response for request code. Original error: Invalid JSON');
        });

        it('should throw error when API returns Not_Ok status', async () => {
          const mockErrorResponse: RequestCodeResponse = {
            stat: STATUS.NOT_OK,
            emsg: 'Invalid credentials',
            RedirectURL: ''
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              status: 200,
              json: () => Promise.resolve(mockErrorResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Invalid credentials (Status: 200, API Stat: Not_Ok)');
        });

        it('should throw error when RedirectURL is missing', async () => {
          const mockResponse: RequestCodeResponse = {
            stat: STATUS.OK,
            RedirectURL: ''
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve(mockResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: RedirectURL is missing in successful response for request code.');
        });

        it('should throw error when request code is not found in RedirectURL', async () => {
          const mockResponse: RequestCodeResponse = {
            stat: STATUS.OK,
            RedirectURL: 'https://example.com/redirect?other=param'
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve(mockResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Request code not found in RedirectURL.');
        });
      });

      describe('requestCodeToAuthToken Errors', () => {
        beforeEach(() => {
          // Mock successful getSid
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve('mock_sid_token'),
            })
          );

          // Mock successful getRequestCode
          const mockRequestCodeResponse: RequestCodeResponse = {
            stat: STATUS.OK,
            RedirectURL: 'https://example.com/redirect?code=mock_request_code'
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve(mockRequestCodeResponse),
            })
          );
        });

        it('should throw error when requestCodeToAuthToken fails with HTTP error', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: false,
              status: 400,
              statusText: 'Bad Request',
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: 400 Bad Request. Failed to parse JSON response.');
        });

        it('should throw error when requestCodeToAuthToken returns invalid JSON', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.reject(new Error('JSON parse error')),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Successfully fetched but failed to parse JSON response. Original error: JSON parse error');
        });

        it('should throw error when API returns Not_Ok status', async () => {
          const mockErrorResponse: ApiTokenResponse = {
            stat: STATUS.NOT_OK,
            emsg: 'Invalid API secret',
            token: ''
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              status: 200,
              json: () => Promise.resolve(mockErrorResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Invalid API secret (Status: 200, API Stat: Not_Ok)');
        });

        it('should throw error when token is missing from successful response', async () => {
          const mockResponse: ApiTokenResponse = {
            stat: STATUS.OK,
            token: ''
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve(mockResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Token not found in successful response.');
        });

        it('should handle API response with status Not_Ok but no error message', async () => {
          const mockResponse = {
            stat: STATUS.NOT_OK,
            token: ''
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              status: 200,
              statusText: '',
              json: () => Promise.resolve(mockResponse),
            })
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('API Error: Error fetching API token (Status: 200, API Stat: Not_Ok)');
        });
      });

      describe('Network and Unexpected Errors', () => {
        it('should handle network errors during getSid', async () => {
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.reject(new Error('Network error'))
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('Network error');
        });

        it('should handle network errors during getRequestCode', async () => {
          // Mock successful getSid
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve('mock_sid_token'),
            })
          );

          // Mock network error for getRequestCode
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.reject(new Error('Connection timeout'))
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('Connection timeout');
        });

        it('should handle network errors during requestCodeToAuthToken', async () => {
          // Mock successful getSid
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve('mock_sid_token'),
            })
          );

          // Mock successful getRequestCode
          const mockRequestCodeResponse: RequestCodeResponse = {
            stat: STATUS.OK,
            RedirectURL: 'https://example.com/redirect?code=mock_request_code'
          };
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve(mockRequestCodeResponse),
            })
          );

          // Mock network error for requestCodeToAuthToken
          (fetch as jest.Mock).mockImplementationOnce(() =>
            Promise.reject(new Error('Service unavailable'))
          );

          await expect(FlattradeAuth.getAPIAuthToken(mockCredentials))
            .rejects.toThrow('Service unavailable');
        });
      });
    });

    describe('Edge Cases', () => {
      it('should handle RedirectURL with multiple query parameters', async () => {
        const mockSidResponse = 'mock_sid_token';
        const mockRequestCode = 'complex_request_code_123';
        const mockToken = 'mock_auth_token';

        // Mock getSid response
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            text: () => Promise.resolve(mockSidResponse),
          })
        );

        // Mock getRequestCode response with complex URL
        const mockRequestCodeResponse: RequestCodeResponse = {
          stat: STATUS.OK,
          RedirectURL: `https://example.com/redirect?param1=value1&code=${mockRequestCode}&param2=value2&param3=value3`
        };
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockRequestCodeResponse),
          })
        );

        // Mock requestCodeToAuthToken response
        const mockTokenResponse: ApiTokenResponse = {
          stat: STATUS.OK,
          token: mockToken
        };
        (fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockTokenResponse),
          })
        );

        const result = await FlattradeAuth.getAPIAuthToken(mockCredentials);
        expect(result).toEqual({
          account_id: mockCredentials.account_id,
          token: mockToken
        });
      });

      it('should handle special characters in credentials', async () => {
        const specialCredentials = {
          account_id: 'test@account.com',
          password: 'p@ssw0rd!@#',
          api_key: 'api-key-123',
          totpSecret: 'secret_with_underscores',
          authSecret: 'auth-secret-456'
        };

        const mockSidResponse = 'mock_sid_token';
        const mockRequestCode = 'mock_request_code';
        const mockToken = 'mock_auth_token';

        // Mock all three API calls
        (fetch as jest.Mock)
          .mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              text: () => Promise.resolve(mockSidResponse),
            })
          )
          .mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve({
                stat: STATUS.OK,
                RedirectURL: `https://example.com/redirect?code=${mockRequestCode}`
              }),
            })
          )
          .mockImplementationOnce(() =>
            Promise.resolve({
              ok: true,
              json: () => Promise.resolve({
                stat: STATUS.OK,
                token: mockToken
              }),
            })
          );

        const result = await FlattradeAuth.getAPIAuthToken(specialCredentials);
        expect(result).toEqual({
          account_id: specialCredentials.account_id,
          token: mockToken
        });
      });
    });
  });
});