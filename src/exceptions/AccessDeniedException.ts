import { OAuthException } from './OAuthException';

/**
 * Constructor.
 *
 * "The resource owner or authorization server denied the request"
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 */
export class AccessDeniedException extends OAuthException {
  constructor(message?: string | Error, properties?: any) {
    super(message, { code: 400, name: 'access_denied', ...properties });
  }
}
