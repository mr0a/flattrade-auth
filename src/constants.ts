export const AUTH_CONSTANTS = Object.freeze({
  BASE_URL: 'https://auth.flattrade.in/',
  AUTH_DIRECT_URL: 'https://authapi.flattrade.in/ftauth',
  SID_URL: 'https://authapi.flattrade.in/auth/session',
  API_TOKEN_URL: 'https://authapi.flattrade.in/trade/apitoken',
  HASH_ALGORITHM: 'sha256',
});

export const ERRORS = Object.freeze({
  UNKNOWN_ERROR: 'An unknown error occurred',
  TOKEN_NOT_FOUND: 'Token not found in response',
  REQUEST_CODE_NOT_FOUND: 'Request code not found in redirect URL',
  INVALID_RESPONSE: 'Invalid API response format',
  NETWORK_ERROR: 'Network request failed',
});

export const STATUS = Object.freeze({
  OK: 'Ok',
  NOT_OK: 'Not_Ok',
});