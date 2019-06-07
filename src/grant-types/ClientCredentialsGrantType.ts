import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidGrantException } from '../exceptions/InvalidGrantException';
import { Client } from '../interfaces/ClientInterface';
import { Token } from '../interfaces/TokenInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import { AbstractGrantType } from './AbstractGrantType';

export class ClientCredentialsGrantType extends AbstractGrantType {
  constructor(options: any = {}) {
    super(options);
    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    if (!options.model.getUserFromClient) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getUserFromClient()`',
      );
    }

    if (!options.model.saveToken) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `saveToken()`',
      );
    }
  }

  /**
   * Handle client credentials grant.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.4.2
   */

  async handle(request: Request, client: Client) {
    if (!request) {
      throw new InvalidArgumentException('Missing parameter: `request`');
    }

    if (!client) {
      throw new InvalidArgumentException('Missing parameter: `client`');
    }

    const scope = this.getScope(request);
    const user = await this.getUserFromClient(client);

    return this.saveToken(user, client, scope);
  }

  /**
   * Retrieve the user using client credentials.
   */

  async getUserFromClient(client: Client) {
    const user = await this.model.getUserFromClient(client);
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
      this.getAccessTokenExpiresAt(),
    ];

    const [accessScope, accessToken, accessTokenExpiresAt] = await Promise.all(
      fns as any,
    );

    const token = {
      accessToken,
      accessTokenExpiresAt,
      scope: accessScope,
    } as Token;

    return this.model.saveToken(token, client, user);
  }
}
