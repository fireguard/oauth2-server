import { Client } from './ClientInterface';
import { User } from './UserInterface';

/**
 * An interface representing the refresh token and associated data.
 */
export interface RefreshToken {
  refreshToken: string;
  refreshTokenExpiresAt?: Date;
  scope?: string;
  client: Client;
  user: User;
  [key: string]: any;
}
