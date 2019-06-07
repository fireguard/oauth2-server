import { OAuthException } from './OAuthException';

/**
 * Constructor.
 *
 * "The requested scope is invalid, unknown, or malformed."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 */
export class InvalidScopeException extends OAuthException {
  constructor(message?: string | Error, properties?: any) {
    super(message, { code: 400, name: 'invalid_scope', ...properties });
  }
}
