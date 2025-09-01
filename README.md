# Flattrade Auth Library

A TypeScript library for authenticating with Flattrade's API using OAuth 2.0 flow.

## Installation

```bash
npm install flattrade-auth
```

## Usage

```typescript
import { FlattradeAuth } from 'flattrade-auth';

const { account_id, token } = await FlattradeAuth.getAPIAuthToken({
  account_id: 'your_account_id',
  password: 'your_password',
  api_key: 'your_api_key',
  totpSecret: 'your_totp_secret',
  authSecret: 'your_auth_secret'
});
```

## API

### `FlattradeAuth.getAPIAuthToken(params)`

Returns a Promise that resolves to an object containing the authentication token and account ID.

**Parameters:**
- `params` (object): Configuration object with the following properties:
  - `account_id` (string): Your Flattrade account ID
  - `password` (string): Your account password
  - `api_key` (string): Your API key
  - `totpSecret` (string): Your TOTP secret for 2FA
  - `authSecret` (string): Your authentication secret

**Returns:** `Promise<FlattradeAuthResponse>` - Object containing:
- `account_id` (string): The authenticated account ID
- `token` (string): The authentication token

## Development

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run tests
npm test
```

## License

GNU Affero General Public License v3.0 (AGPL-3.0)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.