import { RefreshToken } from '../modules/auth/entities/refresh-token.entity.js';
import { OauthAccount } from '../modules/users/entities/oauth-account.entity.js';
import { User } from '../modules/users/entities/user.entity.js';

export const entities = [User, OauthAccount, RefreshToken];
