import { has } from 'lodash';
import { format, parse, UrlWithParsedQuery } from 'url';
import { AccessDeniedException } from '../exceptions/AccessDeniedException';
import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';
import { InvalidClientException } from '../exceptions/InvalidClientException';
import { InvalidRequestException } from '../exceptions/InvalidRequestException';
import { InvalidScopeException } from '../exceptions/InvalidScopeException';
import { OAuthException } from '../exceptions/OAuthException';
import { ServerException } from '../exceptions/ServerException';
import { UnauthorizedClientException } from '../exceptions/UnauthorizedClientException';
import { UnsupportedResponseTypeException } from '../exceptions/UnsupportedResponseTypeException';
import { AuthenticateHandler } from './AuthenticateHandler';
import { AuthorizationCode } from '../interfaces/AuthorizationCodeInterface';
import { Client } from '../interfaces/ClientInterface';
import { Model } from '../interfaces/ModelInterface';
import { User } from '../interfaces/UserInterface';
import { Request } from '../Request';
import { Response } from '../Response';
import { CodeResponseType } from '../response-types/CodeResponseType';
import * as tokenUtil from '../utils/TokenUtil';
import * as is from '../validators/IsValidator';

const responseTypes = {
  code: CodeResponseType,
  // token: require('../response-types/token-response-type')
};

export class AuthorizeHandler {
  allowEmptyState: boolean;
  authenticateHandler: any;
  authorizationCodeLifetime: number;
  model: Model;
  constructor(options: any = {}) {
    if (options.authenticateHandler && !options.authenticateHandler.handle) {
      throw new InvalidArgumentException(
        'Invalid argument: authenticateHandler does not implement `handle()`',
      );
    }

    if (!options.authorizationCodeLifetime) {
      throw new InvalidArgumentException(
        'Missing parameter: `authorizationCodeLifetime`',
      );
    }

    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    if (!options.model.getClient) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `getClient()`',
      );
    }

    if (!options.model.saveAuthorizationCode) {
      throw new InvalidArgumentException(
        'Invalid argument: model does not implement `saveAuthorizationCode()`',
      );
    }

    this.allowEmptyState = options.allowEmptyState;
    this.authenticateHandler =
      options.authenticateHandler || new AuthenticateHandler(options);
    this.authorizationCodeLifetime = options.authorizationCodeLifetime;
    this.model = options.model;
  }

  /**
   * Authorize Handler.
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

    if (request.query.allowed === 'false') {
      throw new AccessDeniedException(
        'Access denied: user denied access to application',
      );
    }

    const fns = [
      this.getAuthorizationCodeLifetime(),
      this.getClient(request),
      this.getUser(request, response),
    ];

    const [expiresAt, client, user] = await Promise.all(fns);
    const uri = this.getRedirectUri(request, client);
    let scope: any;
    let state: any;
    let ResponseType: any;

    try {
      scope = this.getScope(request);
      const authorizationCode = await this.generateAuthorizationCode(
        client,
        user,
        scope,
      );
      state = this.getState(request);
      ResponseType = this.getResponseType(request);
      const code = await this.saveAuthorizationCode(
        authorizationCode,
        expiresAt,
        scope,
        client,
        uri,
        user,
      );
      const responseType = new ResponseType(code.authorizationCode);
      const redirectUri = this.buildSuccessRedirectUri(uri, responseType);
      this.updateResponse(response, redirectUri, state);

      return code;
    } catch (e) {
      if (!(e instanceof OAuthException)) {
        e = new ServerException(e);
      }
      const redirectUri = this.buildErrorRedirectUri(uri, e);
      this.updateResponse(response, redirectUri, state);
      throw e;
    }
  }

  /**
   * Generate authorization code.
   */

  generateAuthorizationCode(client, user, scope) {
    if (this.model.generateAuthorizationCode) {
      return this.model.generateAuthorizationCode(client, user, scope);
    }

    return tokenUtil.GenerateRandomToken();
  }

  /**
   * Get authorization code lifetime.
   */

  getAuthorizationCodeLifetime() {
    const expires = new Date();

    expires.setSeconds(expires.getSeconds() + this.authorizationCodeLifetime);

    return expires;
  }

  /**
   * Get the client from the model.
   */

  async getClient(request: Request) {
    const clientId = request.body.client_id || request.query.client_id;

    if (!clientId) {
      throw new InvalidRequestException('Missing parameter: `client_id`');
    }

    if (!is.vschar(clientId)) {
      throw new InvalidRequestException('Invalid parameter: `client_id`');
    }

    const redirectUri = request.body.redirect_uri || request.query.redirect_uri;

    if (redirectUri && !is.uri(redirectUri)) {
      throw new InvalidRequestException(
        'Invalid request: `redirect_uri` is not a valid URI',
      );
    }

    const client = await this.model.getClient(clientId);
    if (!client) {
      throw new InvalidClientException(
        'Invalid client: client credentials are invalid',
      );
    }

    if (!client.grants) {
      throw new InvalidClientException('Invalid client: missing client `grants`');
    }

    if (!client.grants.includes('authorization_code')) {
      throw new UnauthorizedClientException(
        'Unauthorized client: `grant_type` is invalid',
      );
    }

    if (!client.redirectUris || client.redirectUris.length === 0) {
      throw new InvalidClientException(
        'Invalid client: missing client `redirectUri`',
      );
    }

    if (redirectUri && !client.redirectUris.includes(redirectUri)) {
      throw new InvalidClientException(
        'Invalid client: `redirect_uri` does not match client value',
      );
    }

    return client;
  }

  /**
   * Get scope from the request.
   */

  getScope = (request: Request) => {
    const scope = request.body.scope || request.query.scope;

    if (!is.nqschar(scope)) {
      throw new InvalidScopeException('Invalid parameter: `scope`');
    }

    return scope;
  };

  /**
   * Get state from the request.
   */

  getState(request) {
    const state = request.body.state || request.query.state;

    if (!this.allowEmptyState && !state) {
      throw new InvalidRequestException('Missing parameter: `state`');
    }

    if (!is.vschar(state)) {
      throw new InvalidRequestException('Invalid parameter: `state`');
    }

    return state;
  }

  /**
   * Get user by calling the authenticate middleware.
   */

  async getUser(request: Request, response: Response) {
    if (this.authenticateHandler instanceof AuthenticateHandler) {
      const data = await this.authenticateHandler.handle(request, response);

      return data.user;
    }

    const user = await this.authenticateHandler.handle(request, response);
    if (!user) {
      throw new ServerException(
        'Server error: `handle()` did not return a `user` object',
      );
    }

    return user;
  }

  /**
   * Get redirect URI.
   */

  getRedirectUri = (request: Request, client) => {
    return (
      request.body.redirect_uri ||
      request.query.redirect_uri ||
      client.redirectUris[0]
    );
  };

  /**
   * Save authorization code.
   */

  async saveAuthorizationCode(
    authorizationCode: string,
    expiresAt: Date,
    scope: string,
    client: Client,
    redirectUri: string,
    user: User,
  ) {
    const code = {
      authorizationCode,
      expiresAt,
      redirectUri,
      scope,
    } as AuthorizationCode;

    return this.model.saveAuthorizationCode(code, client, user);
  }

  /**
   * Get response type.
   */

  getResponseType = (request: Request) => {
    const responseType =
      request.body.response_type || request.query.response_type;

    if (!responseType) {
      throw new InvalidRequestException('Missing parameter: `response_type`');
    }

    if (!has(responseTypes, responseType)) {
      throw new UnsupportedResponseTypeException(
        'Unsupported response type: `response_type` is not supported',
      );
    }

    return responseTypes[responseType];
  };

  /**
   * Build a successful response that redirects the user-agent to the client-provided url.
   */

  buildSuccessRedirectUri = (
    redirectUri: string,
    responseType: CodeResponseType,
  ) => {
    return responseType.buildRedirectUri(redirectUri);
  };

  /**
   * Build an error response that redirects the user-agent to the client-provided url.
   */

  buildErrorRedirectUri = (redirectUri: string, error: Error) => {
    const uri = parse(redirectUri, true);

    uri.query = {
      error: error.name,
    };

    if (error.message) {
      uri.query.error_description = error.message;
    }

    return uri;
  };

  /**
   * Update response with the redirect uri and the state parameter, if available.
   */

  updateResponse = (
    response: Response,
    redirectUri: UrlWithParsedQuery,
    state: string,
  ) => {
    redirectUri.query = redirectUri.query || {};

    if (state) {
      redirectUri.query.state = state;
    }

    response.redirect(format(redirectUri));
  };
}
