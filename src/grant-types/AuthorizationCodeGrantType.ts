import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidGrantException } from '../exceptions/InvalidGrantException';
import { InvalidRequestException } from '../exceptions/InvalidRequestException';
import { ServerException } from '../exceptions/ServerException';
import { Client } from '../interfaces/ClientInterface';
import { Token } from '../interfaces/TokenInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import * as is from '../validators/IsValidator';
import { AbstractGrantType } from './AbstractGrantType';

export class AuthorizationCodeGrantType extends AbstractGrantType {
  constructor(options: any = {}) {
    super(options);
    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    if (!options.model.getAuthorizationCode) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getAuthorizationCode()`',
      );
    }

    if (!options.model.revokeAuthorizationCode) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `revokeAuthorizationCode()`',
      );
    }

    if (!options.model.saveToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `saveToken()`',
      );
    }
  }

  /**
   * Handle authorization code grant.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
   */

  async handle(request: Request, client) {
    if (!request) {
      throw new InvalidArgumentException('Missing parameter: `request`');
    }

    if (!client) {
      throw new InvalidArgumentException('Missing parameter: `client`');
    }
    const code = await this.getAuthorizationCode(request, client);
    this.validateRedirectUri(request, code);
    await this.revokeAuthorizationCode(code);

    return this.saveToken(
      code.user,
      client,
      code.authorizationCode,
      code.scope,
    );
  }

  /**
   * Get the authorization code.
   */

  async getAuthorizationCode(request: Request, client) {
    if (!request.body.code) {
      throw new InvalidRequestException('Missing parameter: `code`');
    }

    if (!is.vschar(request.body.code)) {
      throw new InvalidRequestException('Invalid parameter: `code`');
    }

    const code = await this.model.getAuthorizationCode(request.body.code);
    if (!code) {
      throw new InvalidGrantException(
        'Invalid grant: authorization code is invalid',
      );
    }

    if (!code.client) {
      throw new ServerException(
        'Server error: `getAuthorizationCode()` did not return a `client` object',
      );
    }

    if (!code.user) {
      throw new ServerException(
        'Server error: `getAuthorizationCode()` did not return a `user` object',
      );
    }

    if (code.client.id !== client.id) {
      throw new InvalidGrantException(
        'Invalid grant: authorization code is invalid',
      );
    }

    if (!(code.expiresAt instanceof Date)) {
      throw new ServerException(
        'Server error: `expiresAt` must be a Date instance',
      );
    }

    if (code.expiresAt < new Date()) {
      throw new InvalidGrantException(
        'Invalid grant: authorization code has expired',
      );
    }

    if (code.redirectUri && !is.uri(code.redirectUri)) {
      throw new InvalidGrantException(
        'Invalid grant: `redirect_uri` is not a valid URI',
      );
    }

    return code;
  }

  /**
   * Validate the redirect URI.
   *
   * "The authorization server MUST ensure that the redirect_uri parameter is
   * present if the redirect_uri parameter was included in the initial
   * authorization request as described in Section 4.1.1, and if included
   * ensure that their values are identical."
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
   */

  validateRedirectUri = (request: Request, code) => {
    if (!code.redirectUri) {
      return;
    }

    const redirectUri = request.body.redirect_uri || request.query.redirect_uri;

    if (!is.uri(redirectUri)) {
      throw new InvalidRequestException(
        'Invalid request: `redirect_uri` is not a valid URI',
      );
    }

    if (redirectUri !== code.redirectUri) {
      throw new InvalidRequestException(
        'Invalid request: `redirect_uri` is invalid',
      );
    }
  };

  /**
   * Revoke the authorization code.
   *
   * "The authorization code MUST expire shortly after it is issued to mitigate
   * the risk of leaks. [...] If an authorization code is used more than once,
   * the authorization server MUST deny the request."
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
   */

  async revokeAuthorizationCode(code) {
    const status = await this.model.revokeAuthorizationCode(code);
    if (!status) {
      throw new InvalidGrantException(
        'Invalid grant: authorization code is invalid',
      );
    }

    return code;
  }

  /**
   * Save token.
   */

  async saveToken(
    user: User,
    client: Client,
    authorizationCode: string,
    scope: string,
  ) {
    const fns = [
      this.validateScope(user, client, scope),
      this.generateAccessToken(client, user, scope),
      this.generateRefreshToken(client, user, scope),
      this.getAccessTokenExpiresAt(),
      this.getRefreshTokenExpiresAt(),
    ];

    const [
      accessScope,
      accessToken,
      refreshToken,
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
    ] = await Promise.all(fns as any);

    const token: Token = {
      accessToken,
      authorizationCode,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      scope: accessScope,
    } as any;

    return this.model.saveToken(token, client, user);
  }
}
