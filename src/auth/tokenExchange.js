import { hasText, isObject } from 'stac-js/src/utils.js';
import OIDC from './oidc';
import AuthUtils from '../components/auth/utils';

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
const ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
// Exchange again this many seconds before the exchanged credentials expire
const RENEW_MARGIN = 60;

/**
 * OAuth 2.0 Token Exchange (RFC 8693) as defined by the `tokenExchange` flow
 * of the STAC Authentication extension.
 *
 * The user signs in through the OpenID Connect scheme referenced via the
 * scheme's `auth:refs`. The token obtained there is exchanged at the `tokenUrl`
 * for the credentials that are sent along with the requests.
 *
 * Expects the options to be resolved by `AuthUtils.resolveAuth`, i.e.
 * a single entry in `auth:refs`, the referenced scheme in `auth:schemes`
 * and optionally the URL of the STAC document in `resource`.
 */
export default class TokenExchange extends OIDC {

  constructor(router, options, changeListener, appConfig = {}) {
    super(router, TokenExchange.getIdentityScheme(options), changeListener, appConfig);
    this.options = options;
    this.renewTimer = null;
    this.trusted = AuthUtils.isTrustedTokenUrl(options.flows.tokenExchange.tokenUrl, appConfig);
  }

  receivesCredentials(url) {
    // The exchanged credentials are only meant for the assets and links
    // that reference the scheme, regardless of whether they are external.
    return AuthUtils.matchesUrlPrefix(url, this.options.urlPrefixes);
  }

  static getIdentityScheme(options) {
    const ref = options['auth:refs'][0];
    return options['auth:schemes'][ref];
  }

  get flow() {
    return this.options.flows.tokenExchange;
  }

  getSubjectTokenType() {
    // Without subjectTokenType, the type follows from the openIdConnect scheme
    return this.flow.subjectTokenType || ID_TOKEN;
  }

  getSubjectToken(user) {
    return this.getSubjectTokenType() === ACCESS_TOKEN ? user.access_token : user.id_token;
  }

  async exchange(user) {
    if (!this.trusted) {
      throw new Error(`The token exchange URL ${this.flow.tokenUrl} is not allowed.`);
    }
    const params = new URLSearchParams({
      grant_type: GRANT_TYPE,
      subject_token: this.getSubjectToken(user),
      subject_token_type: this.getSubjectTokenType()
    });
    if (hasText(this.options.resource)) {
      params.set('resource', this.options.resource);
    }
    const scopes = isObject(this.flow.scopes) ? Object.keys(this.flow.scopes) : [];
    if (scopes.length > 0) {
      params.set('scope', scopes.join(' '));
    }

    // Don't follow redirects, they could forward the token to another URL
    const response = await fetch(this.flow.tokenUrl, { method: 'POST', body: params, redirect: 'error' });
    let data = null;
    try {
      data = await response.json();
    } catch {
      // Handled below
    }
    if (!response.ok) {
      // RFC 6749, section 5.2
      if (isObject(data) && hasText(data.error)) {
        throw new Error(data.error_description || data.error);
      }
      throw new Error(`The token exchange failed with status ${response.status}.`);
    }
    if (!isObject(data) || !hasText(data.access_token)) {
      throw new Error('The token exchange did not return an access token.');
    }
    return data;
  }

  async resume() {
    try {
      return await super.resume();
    } catch (error) {
      console.warn('Resuming the token exchange failed', error);
      return false;
    }
  }

  async close() { // eslint-disable-line require-await
    // Keep the identity session so that the exchange for another
    // STAC document doesn't require the user to log in again.
    this.clearRenewal();
  }

  async setUser(user = null) {
    this.user = user;
    this.clearRenewal();
    if (!user) {
      await this.changeListener(false);
      return;
    }
    let token;
    try {
      token = await this.exchange(user);
    } catch (error) {
      await this.changeListener(false);
      throw error;
    }
    this.scheduleRenewal(token.expires_in);
    await this.changeListener(true, token.access_token);
  }

  scheduleRenewal(expiresIn) {
    if (typeof expiresIn !== 'number' || expiresIn <= 0) {
      return;
    }
    const delay = Math.max(expiresIn - RENEW_MARGIN, expiresIn / 2);
    this.renewTimer = setTimeout(() => this.renew(), delay * 1000);
  }

  clearRenewal() {
    if (this.renewTimer) {
      clearTimeout(this.renewTimer);
      this.renewTimer = null;
    }
  }

  async renew() {
    this.renewTimer = null;
    try {
      await this.setUser(await this.manager.getUser());
    } catch (error) {
      console.warn('Renewing the exchanged credentials failed', error);
    }
  }

}
