import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidGrantException } from '../exceptions/InvalidGrantException';
import { InvalidRequestException } from '../exceptions/InvalidRequestException';
import { ServerException } from '../exceptions/ServerException';
import { Client } from '../interfaces/ClientInterface';
import { RefreshToken } from '../interfaces/RefreshTokenInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import * as is from '../validators/IsValidator';
import { AbstractGrantType } from './AbstractGrantType';

export class RefreshTokenGrantType extends AbstractGrantType {
  constructor(options: any = {}) {
    super(options);

    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    if (!options.model.getRefreshToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getRefreshToken()`',
      );
    }

    if (!options.model.revokeToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `revokeToken()`',
      );
    }

    if (!options.model.saveToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `saveToken()`',
      );
    }
  }

  /**
   * Handle refresh token grant.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-6
   */

  async handle(request: Request, client: Client) {
    if (!request) {
      throw new InvalidArgumentException('Missing parameter: `request`');
    }

    if (!client) {
      throw new InvalidArgumentException('Missing parameter: `client`');
    }

    const token = await this.getRefreshToken(request, client);
    await this.revokeToken(token);

    return this.saveToken(token.user, client, token.scope);
  }

  /**
   * Get refresh token.
   */

  async getRefreshToken(request: Request, client: Client) {
    if (!request.body.refresh_token) {
      throw new InvalidRequestException('Missing parameter: `refresh_token`');
    }

    if (!is.vschar(request.body.refresh_token)) {
      throw new InvalidRequestException('Invalid parameter: `refresh_token`');
    }

    const token = await this.model.getRefreshToken(request.body.refresh_token);

    if (!token) {
      throw new InvalidGrantException('Invalid grant: refresh token is invalid');
    }

    if (!token.client) {
      throw new ServerException(
        'Server error: `getRefreshToken()` did not return a `client` object',
      );
    }

    if (!token.user) {
      throw new ServerException(
        'Server error: `getRefreshToken()` did not return a `user` object',
      );
    }

    if (token.client.id !== client.id) {
      throw new InvalidGrantException('Invalid grant: refresh token is invalid');
    }

    if (
      token.refreshTokenExpiresAt &&
      !(token.refreshTokenExpiresAt instanceof Date)
    ) {
      throw new ServerException(
        'Server error: `refreshTokenExpiresAt` must be a Date instance',
      );
    }

    if (
      token.refreshTokenExpiresAt &&
      token.refreshTokenExpiresAt < new Date()
    ) {
      throw new InvalidGrantException('Invalid grant: refresh token has expired');
    }

    return token;
  }

  /**
   * Revoke the refresh token.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-6
   */

  async revokeToken(token: RefreshToken) {
    if (this.alwaysIssueNewRefreshToken === false) {
      return token;
    }

    const status = await this.model.revokeToken(token);
    if (!status) {
      throw new InvalidGrantException('Invalid grant: refresh token is invalid');
    }

    return token;
  }

  /**
   * Save token.
   */

  async saveToken(user: User, client: Client, scope: string) {
    const fns = [
      this.generateAccessToken(client, user, scope),
      this.generateRefreshToken(client, user, scope),
      this.getAccessTokenExpiresAt(),
      this.getRefreshTokenExpiresAt(),
    ];

    const [
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
    ] = await Promise.all(fns as any);

    const token: any = {
      accessToken,
      accessTokenExpiresAt,
      scope,
    };

    if (this.alwaysIssueNewRefreshToken !== false) {
      token.refreshToken = refreshToken;
      token.refreshTokenExpiresAt = refreshTokenExpiresAt;
    }

    const savedToken = await this.model.saveToken(token, client, user);

    return savedToken;
  }
}
