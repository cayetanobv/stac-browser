import { isObject, size } from 'stac-js/src/utils.js';
import { STAC, STACReference } from 'stac-js';
import Auth from '../../auth/index.js';

export default class AuthUtils {

  static resolveAuth(obj) {
    if (obj instanceof STACReference) {
      const refs = obj.getMetadata('auth:refs');
      const schemes = obj.getMetadata('auth:schemes');
      if (size(refs) > 0 && size(schemes) > 0) {
        return refs
          .filter(ref => isObject(schemes[ref]))
          .flatMap(ref => AuthUtils.resolveInput(ref, schemes, obj));
      }
    }
    return [];
  }

  static isTokenExchange(method) {
    return method.type === 'oauth2' && isObject(method.flows) && isObject(method.flows.tokenExchange);
  }

  /**
   * Resolves the schemes that supply the input of a token exchange scheme.
   * The referenced schemes are alternatives, so each of them results in a
   * separate scheme with exactly one entry in `auth:refs` and the referenced
   * scheme embedded in `auth:schemes`. This keeps the scheme self-contained,
   * e.g. for persisting it across the OpenID Connect redirects.
   * 
   * The exchanged credentials are only sent to the URLs in `urlPrefixes`,
   * the folders of the assets and links in the document that reference the scheme.
   * 
   * @param {string} key The key of the scheme in `schemes`
   * @param {Object.<string, Object>} schemes
   * @param {STACReference} obj
   * @returns {Array.<Object>}
   */
  static resolveInput(key, schemes, obj) {
    const scheme = schemes[key];
    if (!AuthUtils.isTokenExchange(scheme)) {
      return [scheme];
    }
    const document = AuthUtils.getDocument(obj);
    const resource = document ? document.getAbsoluteUrl() : null;
    const urlPrefixes = AuthUtils.getUrlPrefixes(document, key);
    const refs = Array.isArray(scheme['auth:refs']) ? scheme['auth:refs'] : [];
    const resolved = refs
      .filter(ref => isObject(schemes[ref]))
      .map(ref => Object.assign({}, scheme, {
        'auth:refs': [ref],
        'auth:schemes': { [ref]: schemes[ref] },
        resource,
        urlPrefixes
      }));
    // Keep the unresolvable scheme so that it's still shown as unsupported
    return resolved.length > 0 ? resolved : [scheme];
  }

  /**
   * The tokenUrl is provided by the STAC document, but the token exchange
   * sends the user's token to it. Only send it to the token URLs configured
   * by the operator, otherwise any document could obtain the token.
   * 
   * @param {string} tokenUrl
   * @param {Object} config
   * @returns {boolean}
   */
  static isTrustedTokenUrl(tokenUrl, config = {}) {
    if (typeof tokenUrl !== 'string' || !Array.isArray(config.tokenExchangeUrls)) {
      return false;
    }
    try {
      const url = new URL(tokenUrl);
      return url.protocol === 'https:' && config.tokenExchangeUrls.some(allowed => new URL(allowed).href === url.href);
    } catch {
      return false;
    }
  }

  static getDocument(obj) {
    let context = obj;
    while (context instanceof STACReference) {
      context = context.getContext();
    }
    return context instanceof STAC ? context : null;
  }

  /**
   * Returns the folders of the assets (incl. alternates) and links
   * in the document that reference the given scheme.
   * 
   * @param {STAC|null} document
   * @param {string} key
   * @returns {Array.<string>}
   */
  static getUrlPrefixes(document, key) {
    if (!document) {
      return [];
    }
    const baseUrl = document.getAbsoluteUrl();
    const refs = [
      ...document.getAssets().flatMap(asset => [asset, ...asset.getAlternates()]),
      ...(Array.isArray(document.links) ? document.links : [])
    ];
    const prefixes = refs
      .filter(ref => Array.isArray(ref['auth:refs']) && ref['auth:refs'].includes(key) && typeof ref.href === 'string')
      .map(ref => {
        try {
          const url = new URL(ref.href, baseUrl || undefined);
          return ['http:', 'https:'].includes(url.protocol) ? new URL('./', url).href : null;
        } catch {
          return null;
        }
      })
      .filter(prefix => prefix !== null);
    return [...new Set(prefixes)];
  }

  /**
   * Checks whether the URL starts with one of the URL prefixes.
   * 
   * @param {string|Object} url
   * @param {Array.<string>} prefixes
   * @returns {boolean}
   */
  static matchesUrlPrefix(url, prefixes) {
    if (!Array.isArray(prefixes)) {
      return false;
    }
    try {
      const href = new URL(String(url)).href;
      return prefixes.some(prefix => href.startsWith(prefix));
    } catch {
      return false;
    }
  }

  static isSupported(method, config) {
    if (method instanceof Auth) {
      method = method.options;
    }
    switch(method.type) {
      case 'http':
        return (method.scheme === 'basic');
      case 'apiKey':
        return (method.in === 'header' || method.in === 'query');
      case 'openIdConnect':
        return (config.historyMode === 'history');
      case 'oauth2': {
        // Token exchange with the token of an OpenID Connect scheme, see resolveInput
        if (!AuthUtils.isTokenExchange(method) || size(method['auth:refs']) !== 1 || !isObject(method['auth:schemes'])) {
          return false;
        }
        const input = method['auth:schemes'][method['auth:refs'][0]];
        return isObject(input) && input.type === 'openIdConnect' && AuthUtils.isSupported(input, config)
          && AuthUtils.isTrustedTokenUrl(method.flows.tokenExchange.tokenUrl, config);
      }
      default:
        return false;
    }
  }

}
