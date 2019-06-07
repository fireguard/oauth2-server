import { parse } from 'url';
import { InvalidArgumentException } from '../exceptions/InvalidArgumentException';

export class CodeResponseType {
  code: any;
  constructor(code: number) {
    if (!code) {
      throw new InvalidArgumentException('Missing parameter: `code`');
    }
    this.code = code;
  }

  /**
   * Build redirect uri.
   */

  buildRedirectUri(redirectUri: string) {
    if (!redirectUri) {
      throw new InvalidArgumentException('Missing parameter: `redirectUri`');
    }

    const uri = parse(redirectUri, true);

    uri.query.code = this.code;
    uri.search = undefined;

    return uri;
  }
}
