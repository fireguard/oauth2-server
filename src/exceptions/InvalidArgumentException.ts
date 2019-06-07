import { OAuthException } from './OAuthException';

export class InvalidArgumentException extends OAuthException {
  constructor(message?: string | Error, properties?: any) {
    super(message, { code: 500, name: 'invalid_argument', ...properties });
  }
}
