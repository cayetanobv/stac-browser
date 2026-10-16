import { hasText, isObject, size } from 'stac-js/src/utils.js';
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

  /**
   * A scheme from a STAC document without the settings that only the operator may set.
   * The client settings in `oidcConfig` are passed to the OpenID Connect library as they are,
   * incl. its endpoints, so a document could send the login to another server.
   * Documents provide the client ID in `clientId` instead.
   * 
   * @param {Object} scheme
   * @returns {Object}
   */
  static fromDocument(scheme) {
    const copy = Object.assign({}, scheme);
    delete copy.oidcConfig;
    return copy;
  }

  /**
   * The client ID for an OpenID Connect scheme: the operator's `oidcConfigs`
   * or `oidcConfig` take priority over the `clientId` of the document.
   * 
   * @param {Object} scheme
   * @param {Object} config
   * @returns {string|null}
   */
  static getClientId(scheme, config = {}) {
    const operator = isObject(config.oidcConfigs) ? config.oidcConfigs[scheme.openIdConnectUrl] : null;
    const candidates = [
      isObject(scheme.oidcConfig) ? scheme.oidcConfig.client_id : null,
      isObject(operator) ? operator.client_id : null,
      scheme.clientId
    ];
    return candidates.find(id => hasText(id)) || null;
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
    const scheme = AuthUtils.fromDocument(schemes[key]);
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
        'auth:schemes': { [ref]: AuthUtils.fromDocument(schemes[ref]) },
        resource,
        urlPrefixes
      }));
    // Keep the unresolvable scheme so that it's still shown as unsupported
    return resolved.length > 0 ? resolved : [scheme];
  }

  /**
   * The operator settings for the token URL from the `tokenExchanges` option.
   * The tokenUrl is provided by the STAC document, but the token exchange
   * sends the user's token to it, and the folders that receive the exchanged
   * credentials are also provided by the document. Only exchanges and folders
   * allowed by the operator are used, otherwise any document could obtain
   * the token or the exchanged credentials.
   * 
   * @param {string} tokenUrl
   * @param {Object} config
   * @returns {Array.<string>|null} The URL prefixes that may receive the exchanged credentials, `null` if not allowed
   */
  static getTokenExchangeDataUrls(tokenUrl, config = {}) {
    if (typeof tokenUrl !== 'string' || !isObject(config.tokenExchanges)) {
      return null;
    }
    try {
      const url = new URL(tokenUrl);
      if (url.protocol !== 'https:') {
        return null;
      }
      for (const [allowed, dataUrls] of Object.entries(config.tokenExchanges)) {
        if (new URL(allowed).href === url.href) {
          const prefixes = Array.isArray(dataUrls) ? dataUrls.filter(prefix => typeof prefix === 'string') : [];
          return prefixes.length > 0 ? prefixes.map(prefix => new URL(prefix).href) : null;
        }
      }
    } catch {
      // Invalid URL
    }
    return null;
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
        // Token exchange with the token of an OpenID Connect scheme with a known client, see resolveInput
        if (!AuthUtils.isTokenExchange(method) || size(method['auth:refs']) !== 1 || !isObject(method['auth:schemes'])) {
          return false;
        }
        const input = method['auth:schemes'][method['auth:refs'][0]];
        return isObject(input) && input.type === 'openIdConnect' && AuthUtils.isSupported(input, config)
          && AuthUtils.getClientId(input, config) !== null
          && AuthUtils.getTokenExchangeDataUrls(method.flows.tokenExchange.tokenUrl, config) !== null;
      }
      default:
        return false;
    }
  }

}
