import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidGrantException } from '../exceptions/InvalidGrantException';
import { InvalidRequestException } from '../exceptions/InvalidRequestException';
import { Client } from '../interfaces/ClientInterface';
import { Token } from '../interfaces/TokenInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import * as is from '../validators/IsValidator';
import { AbstractGrantType } from './AbstractGrantType';

export class PasswordGrantType extends AbstractGrantType {
  constructor(options: any = {}) {
    super(options);

    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    if (!options.model.getUser) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getUser()`',
      );
    }

    if (!options.model.saveToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `saveToken()`',
      );
    }
  }

  /**
   * Retrieve the user from the model using a username/password combination.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
   */

  async handle(request, client) {
    if (!request) {
      throw new InvalidArgumentException('Missing parameter: `request`');
    }

    if (!client) {
      throw new InvalidArgumentException('Missing parameter: `client`');
    }

    const scope = this.getScope(request);
    const user = await this.getUser(request);

    return this.saveToken(user, client, scope);
  }

  /**
   * Get user using a username/password combination.
   */

  async getUser(request: Request) {
    if (!request.body.username) {
      throw new InvalidRequestException('Missing parameter: `username`');
    }

    if (!request.body.password) {
      throw new InvalidRequestException('Missing parameter: `password`');
    }

    if (!is.uchar(request.body.username)) {
      throw new InvalidRequestException('Invalid parameter: `username`');
    }

    if (!is.uchar(request.body.password)) {
      throw new InvalidRequestException('Invalid parameter: `password`');
    }

    const user = await this.model.getUser(
      request.body.username,
      request.body.password,
    );
    if (!user) {
      throw new InvalidGrantException(
        'Invalid grant: user credentials are invalid',
      );
    }

    return user;
  }

  /**
   * Save token.
   */

  async saveToken(user: User, client: Client, scope: string) {
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

    const token = {
      accessToken,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      scope: accessScope,
    } as Token;

    return this.model.saveToken(token, client, user);
  }
}
