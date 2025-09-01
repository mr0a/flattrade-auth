export interface BaseApiResponse {
  stat: string; // 'Ok' or 'Not_Ok'
  emsg?: string; // Error message if stat is 'Not_Ok'
}

export interface ApiTokenResponse extends BaseApiResponse {
  token: string; // Present if stat is 'Ok'
}

export interface RequestCodeResponse extends BaseApiResponse {
  RedirectURL: string; // Contains the request code if stat is 'Ok'
}

export interface FlattradeAuthResponse {
  account_id: string;
  token: string;
}