import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { Client } from '../interfaces/ClientInterface';
import { Token } from '../interfaces/TokenInterface';
import { User } from '../interfaces/UserInterface';

const modelAttributes = [
  'accessToken',
  'accessTokenExpiresAt',
  'client',
  'refreshToken',
  'refreshTokenExpiresAt',
  'scope',
  'user',
];

export class TokenModel implements Token {
  accessToken: string;
  accessTokenExpiresAt?: Date;
  refreshToken?: string;
  refreshTokenExpiresAt?: Date;
  scope?: string;
  client: Client;
  user: User;
  customAttributes: {};
  accessTokenLifetime: number;
  constructor(data: any = {}, options: any = {}) {
    if (!data.accessToken) {
      throw new InvalidArgumentException('Missing parameter: `accessToken`');
    }

    if (!data.client) {
      throw new InvalidArgumentException('Missing parameter: `client`');
    }

    if (!data.user) {
      throw new InvalidArgumentException('Missing parameter: `user`');
    }

    if (
      data.accessTokenExpiresAt &&
      !(data.accessTokenExpiresAt instanceof Date)
    ) {
      throw new InvalidArgumentException(
        'Invalid parameter: `accessTokenExpiresAt`',
      );
    }

    if (
      data.refreshTokenExpiresAt &&
      !(data.refreshTokenExpiresAt instanceof Date)
    ) {
      throw new InvalidArgumentException(
        'Invalid parameter: `refreshTokenExpiresAt`',
      );
    }

    this.accessToken = data.accessToken;
    this.accessTokenExpiresAt = data.accessTokenExpiresAt;
    this.client = data.client;
    this.refreshToken = data.refreshToken;
    this.refreshTokenExpiresAt = data.refreshTokenExpiresAt;
    this.scope = data.scope;
    this.user = data.user;

    if (options && options.allowExtendedTokenAttributes) {
      this.customAttributes = {};

      for (const key in data) {
        if (data.hasOwnProperty(key) && modelAttributes.indexOf(key) < 0) {
          this.customAttributes[key] = data[key];
        }
      }
    }
    const msInS = 1000;
    if (this.accessTokenExpiresAt) {
      this.accessTokenLifetime = Math.floor(
        (this.accessTokenExpiresAt.getTime() - new Date().getTime()) / msInS,
      );
    }
  }
}
