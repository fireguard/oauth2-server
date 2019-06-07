import { AccessDeniedException } from './exceptions/AccessDeniedException';
import { InsufficientScopeException } from './exceptions/InsufficientScopeException';
import { InvalidArgumentException } from './exceptions/InvalidArgumentException';
import { InvalidClientException } from './exceptions/InvalidClientException';
import { InvalidGrantException } from './exceptions/InvalidGrantException';
import { InvalidRequestException } from './exceptions/InvalidRequestException';
import { InvalidScopeException } from './exceptions/InvalidScopeException';
import { InvalidTokenException } from './exceptions/InvalidTokenException';
import { OAuthException } from './exceptions/OAuthException';
import { ServerException } from './exceptions/ServerException';
import { UnauthorizedClientException } from './exceptions/UnauthorizedClientException';
import { UnauthorizedRequestException } from './exceptions/UnauthorizedRequestException';
import { UnsupportedGrantTypeException } from './exceptions/UnsupportedGrantTypeException';
import { UnsupportedResponseTypeException } from './exceptions/UnsupportedResponseTypeException';
import { AbstractGrantType } from './grant-types/AbstractGrantType';
import { AuthenticateHandler } from './handlers/AuthenticateHandler';
import { AuthorizeHandler } from './handlers/AuthorizeHandler';
import { TokenHandler } from './handlers/TokenHandler';
import { Request } from './Request';
import { Response } from './Response';

export class OAuth2Server {
  options: any;
  constructor(options: any = {}) {
    if (!options.model) {
      throw new InvalidArgumentException('Missing parameter: `model`');
    }

    this.options = options;
  }

  /**
   * Authenticate a token.
   */
  authenticate(request: Request, response?: Response, scope?: string);
  // tslint:disable-next-line:unified-signatures
  authenticate(request: Request, response?: Response, options?: any);

  async authenticate(
    request: Request,
    response?: Response,
    options?: string | any,
  ) {
    let opt = options;
    if (typeof opt === 'string') {
      opt = { scope: opt };
    }

    opt = {
      addAcceptedScopesHeader: true,
      addAuthorizedScopesHeader: true,
      allowBearerTokensInQueryString: false,
      ...this.options,
      ...opt,
    };

    return new AuthenticateHandler(opt).handle(request, response);
  }

  /**
   * Authorize a request.
   */

  async authorize(request: Request, response: Response, options?: any) {
    const defaultLifeTime = 300;
    const opts = {
      allowEmptyState: false,
      authorizationCodeLifetime: defaultLifeTime,
      ...this.options,
      ...options,
    };

    return new AuthorizeHandler(opts).handle(request, response);
  }

  /**
   * Create a token.
   */

  async token(request: Request, response: Response, options?: any) {
    const opts = {
      accessTokenLifetime: 60 * 60, // 1 hour.
      refreshTokenLifetime: 60 * 60 * 24 * 14, // 2 weeks.
      allowExtendedTokenAttributes: false,
      requireClientAuthentication: {},
      ...this.options,
      ...options,
    };

    return new TokenHandler(opts).handle(request, response);
  }

  static Request = Request;
  static Response = Response;
  static AbstractGrantType = AbstractGrantType;
  static AccessDeniedError = AccessDeniedException;
  static InsufficientScopeError = InsufficientScopeException;
  static InvalidArgumentError = InvalidArgumentException;
  static InvalidClientError = InvalidClientException;
  static InvalidGrantError = InvalidGrantException;
  static InvalidRequestError = InvalidRequestException;
  static InvalidScopeError = InvalidScopeException;
  static InvalidTokenError = InvalidTokenException;
  static OAuthError = OAuthException;
  static ServerError = ServerException;
  static UnauthorizedClientError = UnauthorizedClientException;
  static UnauthorizedRequestError = UnauthorizedRequestException;
  static UnsupportedGrantTypeError = UnsupportedGrantTypeException;
  static UnsupportedResponseTypeError = UnsupportedResponseTypeException;
}
