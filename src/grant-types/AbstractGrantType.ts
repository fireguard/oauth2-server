import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidScopeException } from '../exceptions/InvalidScopeException';
import { Client } from '../interfaces/ClientInterface';
import { Model } from '../interfaces/ModelInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import * as tokenUtil from '../utils/TokenUtil';
import * as is from '../validators/IsValidator';

export class AbstractGrantType {
  accessTokenLifetime: number;
  model: Model;
  refreshTokenLifetime: number;
  alwaysIssueNewRefreshToken: boolean;

  constructor(options: any = {}) {
    if (!options.accessTokenLifetime) {
      throw new InvalidArgumentException(
        'Missing parameter: `accessTokenLifetime`',
      );
    }

    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    this.accessTokenLifetime = options.accessTokenLifetime;
    this.model = options.model;
    this.refreshTokenLifetime = options.refreshTokenLifetime;
    this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken;
  }

  /**
   * Generate access token.
   */

  async generateAccessToken(client?: Client, user?: User, scope?: string) {
    if (this.model.generateAccessToken) {
      const token = await this.model.generateAccessToken(client, user, scope);

      return token || tokenUtil.GenerateRandomToken();
    }

    return tokenUtil.GenerateRandomToken();
  }

  /**
   * Generate refresh token.
   */

  async generateRefreshToken(client?: Client, user?: User, scope?: string) {
    if (this.model.generateRefreshToken) {
      const token = await this.model.generateRefreshToken(client, user, scope);

      return token || tokenUtil.GenerateRandomToken();
    }

    return tokenUtil.GenerateRandomToken();
  }

  /**
   * Get access token expiration date.
   */

  getAccessTokenExpiresAt() {
    const expires = new Date();
    expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);

    return expires;
  }

  /**
   * Get refresh token expiration date.
   */

  getRefreshTokenExpiresAt() {
    const expires = new Date();
    expires.setSeconds(expires.getSeconds() + this.refreshTokenLifetime);

    return expires;
  }

  /**
   * Get scope from the request body.
   */

  getScope = (request: Request) => {
    if (!is.nqschar(request.body.scope)) {
      throw new InvalidArgumentException('Invalid parameter: `scope`');
    }

    return request.body.scope;
  };

  /**
   * Validate requested scope.
   */
  async validateScope(user: User, client: Client, scope: string) {
    if (this.model.validateScope) {
      const sc = await this.model.validateScope(user, client, scope);
      if (!sc) {
        throw new InvalidScopeException(
          'Invalid scope: Requested scope is invalid',
        );
      }

      return sc;
    }

    return scope;
  }
}
