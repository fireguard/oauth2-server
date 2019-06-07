import { OAuthException } from './OAuthException';

/**
 * Constructor.
 *
 * "If the request lacks any authentication information (e.g., the client
 * was unaware that authentication is necessary or attempted using an
 * unsupported authentication method), the resource server SHOULD NOT
 * include an error code or other error information."
 *
 * @see https://tools.ietf.org/html/rfc6750#section-3.1
 */

export class UnauthorizedRequestException extends OAuthException {
  constructor(message?: string | Error, properties?: any) {
    super(message, { code: 401, name: 'unauthorized_request', ...properties });
  }
}
