import * as auth from 'basic-auth';
import { has } from 'lodash';
import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidClientException } from '../exceptions/InvalidClientException';
import { InvalidRequestException } from '../exceptions/InvalidRequestException';
import { OAuthException } from '../exceptions/OAuthException';
import { ServerException } from '../exceptions/ServerException';
import { UnauthorizedClientException } from '../exceptions/UnauthorizedClientException';
import { UnsupportedGrantTypeException } from '../exceptions/UnsupportedGrantTypeException';
import { AuthorizationCodeGrantType } from '../grant-types/AuthorizationCodeGrantType';
import { ClientCredentialsGrantType } from '../grant-types/ClientCredentialsGrantType';
import { PasswordGrantType } from '../grant-types/PasswordGrantType';
import { RefreshTokenGrantType } from '../grant-types/RefreshTokenGrantType';
import { TokenModel } from '../models/TokenModel';
import { Request } from '../Request';
import { Response } from '../Response';
import { BearerTokenType } from '../token-types/BearerTokenType';
import * as is from '../validators/IsValidator';
/**
 * Grant types.
 */
const grantTypes = {
  authorization_code: AuthorizationCodeGrantType,
  client_credentials: ClientCredentialsGrantType,
  password: PasswordGrantType,
  refresh_token: RefreshTokenGrantType,
};

export class TokenHandler {
  accessTokenLifetime: any;
  grantTypes: any;
  model: any;
  refreshTokenLifetime: any;
  allowExtendedTokenAttributes: any;
  requireClientAuthentication: any;
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

    if (!options.refreshTokenLifetime) {
      throw new InvalidArgumentException(
        'Missing parameter: `refreshTokenLifetime`',
      );
    }

    if (!options.model.getClient) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getClient()`',
      );
    }

    this.accessTokenLifetime = options.accessTokenLifetime;
    this.grantTypes = { ...grantTypes, ...options.extendedGrantTypes };
    this.model = options.model;
    this.refreshTokenLifetime = options.refreshTokenLifetime;
    this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
    this.requireClientAuthentication =
      options.requireClientAuthentication || {};
    this.alwaysIssueNewRefreshToken =
      options.alwaysIssueNewRefreshToken !== false;
  }

  /**
   * Token Handler.
   */

  async handle(request: Request, response: Response) {
    if (!(request instanceof Request)) {
      throw new InvalidArgumentException(
        'Invalid argument: `request` must be an instance of Request',
      );
    }

    if (!(response instanceof Response)) {
      throw new InvalidArgumentException(
        'Invalid argument: `response` must be an instance of Response',
      );
    }

    if (request.method !== 'POST') {
      // return Promise.reject(
      throw new InvalidRequestException('Invalid request: method must be POST');
      // );
    }

    if (!request.is('application/x-www-form-urlencoded')) {
      throw new InvalidRequestException(
        'Invalid request: content must be application/x-www-form-urlencoded',
      );
    }
    try {
      const client = await this.getClient(request, response);
      const data = await this.handleGrantType(request, client);
      const model = new TokenModel(data, {
        allowExtendedTokenAttributes: this.allowExtendedTokenAttributes,
      });
      const tokenType = this.getTokenType(model);
      this.updateSuccessResponse(response, tokenType);

      return data;
    } catch (e) {
      if (!(e instanceof OAuthException)) {
        e = new ServerException(e);
      }
      this.updateErrorResponse(response, e);
      throw e;
    }
  }

  /**
   * Get the client from the model.
   */

  async getClient(request, response) {
    const credentials = this.getClientCredentials(request);
    const grantType = request.body.grant_type;

    if (!credentials.clientId) {
      throw new InvalidRequestException('Missing parameter: `client_id`');
    }

    if (
      this.isClientAuthenticationRequired(grantType) &&
      !credentials.clientSecret
    ) {
      throw new InvalidRequestException('Missing parameter: `client_secret`');
    }

    if (!is.vschar(credentials.clientId)) {
      throw new InvalidRequestException('Invalid parameter: `client_id`');
    }

    if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
      throw new InvalidRequestException('Invalid parameter: `client_secret`');
    }
    try {
      const client = await this.model.getClient(
        credentials.clientId,
        credentials.clientSecret,
      );
      if (!client) {
        throw new InvalidClientException('Invalid client: client is invalid');
      }

      if (!client.grants) {
        throw new ServerException('Server error: missing client `grants`');
      }

      if (!(client.grants instanceof Array)) {
        throw new ServerException('Server error: `grants` must be an array');
      }

      return client;
    } catch (e) {
      // Include the "WWW-Authenticate" response header field if the client
      // attempted to authenticate via the "Authorization" request header.
      //
      // @see https://tools.ietf.org/html/rfc6749#section-5.2.
      if (e instanceof InvalidClientException && request.get('authorization')) {
        response.set('WWW-Authenticate', 'Basic realm="Service"');

        throw new InvalidClientException(e, { code: 401 });
      }

      throw e;
    }
  }

  /**
   * Get client credentials.
   *
   * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
   * the `client_id` and `client_secret` can be embedded in the body.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
   */

  getClientCredentials(request) {
    const credentials = auth(request);
    const grantType = request.body.grant_type;

    if (credentials) {
      return {
        clientId: credentials.name,
        clientSecret: credentials.pass,
      };
    }

    if (request.body.client_id && request.body.client_secret) {
      return {
        clientId: request.body.client_id,
        clientSecret: request.body.client_secret,
      };
    }

    if (!this.isClientAuthenticationRequired(grantType)) {
      if (request.body.client_id) {
        return { clientId: request.body.client_id };
      }
    }

    throw new InvalidClientException(
      'Invalid client: cannot retrieve client credentials',
    );
  }

  /**
   * Handle grant type.
   */

  async handleGrantType(request: Request, client) {
    const grantType = request.body.grant_type;

    if (!grantType) {
      throw new InvalidRequestException('Missing parameter: `grant_type`');
    }

    if (!is.nchar(grantType) && !is.uri(grantType)) {
      throw new InvalidRequestException('Invalid parameter: `grant_type`');
    }

    if (!has(this.grantTypes, grantType)) {
      throw new UnsupportedGrantTypeException(
        'Unsupported grant type: `grant_type` is invalid',
      );
    }

    if (!client.grants.includes(grantType)) {
      throw new UnauthorizedClientException(
        'Unauthorized client: `grant_type` is invalid',
      );
    }

    const accessTokenLifetime = this.getAccessTokenLifetime(client);
    const refreshTokenLifetime = this.getRefreshTokenLifetime(client);
    const Type = this.grantTypes[grantType];

    const options = {
      accessTokenLifetime,
      model: this.model,
      refreshTokenLifetime,
      alwaysIssueNewRefreshToken: this.alwaysIssueNewRefreshToken,
    };

    return new Type(options).handle(request, client);
  }

  /**
   * Get access token lifetime.
   */

  getAccessTokenLifetime(client) {
    return client.accessTokenLifetime || this.accessTokenLifetime;
  }

  /**
   * Get refresh token lifetime.
   */

  getRefreshTokenLifetime(client) {
    return client.refreshTokenLifetime || this.refreshTokenLifetime;
  }

  /**
   * Get token type.
   */

  getTokenType = model => {
    return new BearerTokenType(
      model.accessToken,
      model.accessTokenLifetime,
      model.refreshToken,
      model.scope,
      model.customAttributes,
    );
  };

  /**
   * Update response when a token is generated.
   */

  updateSuccessResponse = (response, tokenType) => {
    response.body = tokenType.valueOf();

    response.set('Cache-Control', 'no-store');
    response.set('Pragma', 'no-cache');
  };

  /**
   * Update response when an error is thrown.
   */

  updateErrorResponse = (response, error) => {
    response.body = {
      error: error.name,
      error_description: error.message,
    };

    response.status = error.code;
  };

  /**
   * Given a grant type, check if client authentication is required
   */
  isClientAuthenticationRequired = grantType => {
    if (Object.keys(this.requireClientAuthentication).length > 0) {
      return typeof this.requireClientAuthentication[grantType] !== 'undefined'
        ? this.requireClientAuthentication[grantType]
        : true;
    }

    return true;
  };
}
