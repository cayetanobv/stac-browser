/**
 * Authentication tests.
 *
 * Baseline coverage for the global `authConfig` behavior: a request that fails
 * with 401 asks the user to log in and is retried with the credentials applied
 * as header or query parameter. Also covers the STAC Authentication extension
 * UI (unsupported schemes) and login cancellation.
 */
import { http, HttpResponse } from 'msw';
import { test, expect } from './fixtures.js';
import {
  configureBrowser,
  hasBasicAuth,
  hasHeader,
  hasQuery,
  mockImage,
  recordRequestHeaders,
  requireAuth,
  submitApiKey,
  submitBasicAuth,
  waitForBrowserReady,
} from './helpers.js';
import StaticCatalog from '../fixtures/instances/static.js';

const ROOT_URL = 'https://stac.example/catalog.json';

function createStaticCatalog() {
  return new StaticCatalog({ url: ROOT_URL });
}

// The login modal appears during the initial page load (before the app is
// "ready"), so it must absorb the full cold-load latency and needs a longer
// wait than the global assertion default under parallel load.
async function expectLoginModal(page) {
  await expect(page.locator('#stac-browser-auth-modal')).toBeVisible({ timeout: 15000 });
}

test.describe('Global authConfig (legacy single scheme)', () => {
  test('apiKey in header: 401 shows login, retry succeeds with header', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const catalog = createStaticCatalog();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));

    await page.goto(catalog.root.getBrowserPath());

    // The 401 must trigger the login form
    await expectLoginModal(page);

    // The retried request must carry the API key header
    const retried = page.waitForRequest(req => req.url().startsWith(ROOT_URL) && Boolean(req.headers()['x-api-key']));
    await submitApiKey(page, 'secret');
    expect((await retried).headers()['x-api-key']).toBe('secret');

    await waitForBrowserReady(page);
    await expect(page.getByRole('heading', { name: /Example Catalog/ })).toBeVisible();
    // Logged in: the header button offers logout
    await expect(page.getByRole('button', { name: /log out/i })).toBeVisible();
  });

  test('apiKey in query: retry succeeds with query parameter', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'query', name: 'API_KEY' },
    });
    const catalog = createStaticCatalog();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasQuery('API_KEY', 'secret'));

    await page.goto(catalog.root.getBrowserPath());
    await expectLoginModal(page);

    const retried = page.waitForRequest(req => req.url().startsWith(ROOT_URL) && req.url().includes('API_KEY='));
    await submitApiKey(page, 'secret');
    expect((await retried).url()).toContain('API_KEY=secret');

    await waitForBrowserReady(page);
    await expect(page.getByRole('heading', { name: /Example Catalog/ })).toBeVisible();
  });

  test('http basic: retry succeeds with Authorization header', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'http', scheme: 'basic' },
    });
    const catalog = createStaticCatalog();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasBasicAuth('jane', 'doe'));

    await page.goto(catalog.root.getBrowserPath());
    await expectLoginModal(page);

    const retried = page.waitForRequest(req => req.url().startsWith(ROOT_URL) && Boolean(req.headers().authorization));
    await submitBasicAuth(page, 'jane', 'doe');
    expect((await retried).headers().authorization).toBe(`Basic ${btoa('jane:doe')}`);

    await waitForBrowserReady(page);
    await expect(page.getByRole('heading', { name: /Example Catalog/ })).toBeVisible();
  });

  test('credentials are not sent to external domains', async ({ page, worker }) => {
    await configureBrowser(page, {
      catalogUrl: ROOT_URL,
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const catalog = createStaticCatalog();
    const external = catalog.addCatalog({ url: 'https://other.example/catalog.json' });
    external.setMetadata({ title: 'External Catalog' });
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));
    // The catalog card on the root page prefetches the external child in the
    // background, so its first request can fire at any time after login.
    // Record all requests on the handler side instead of racing a waiter.
    const externalRequests = await recordRequestHeaders(worker, 'https://other.example/catalog.json');

    await page.goto('/');
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);

    // Navigate to the external child
    await page.getByRole('link', { name: /External Catalog/ }).click();
    await waitForBrowserReady(page);
    await expect(page.getByRole('heading', { name: /External Catalog/ })).toBeVisible();

    // No request to the external domain may carry the credentials
    expect(externalRequests.length).toBeGreaterThan(0);
    for (const headers of externalRequests) {
      expect(headers['x-api-key']).toBeUndefined();
    }
  });

  test('logout clears the credentials', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const catalog = createStaticCatalog();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));

    await page.goto(catalog.root.getBrowserPath());
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);

    await page.getByRole('button', { name: /log out/i }).click();
    await expect(page.getByText(/logged out successfully/i)).toBeVisible();

    // Without the credentials the catalog asks for a login again
    await page.goto(catalog.root.getBrowserPath());
    await expectLoginModal(page);
  });

  test('cancelling the login dismisses the form', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const catalog = createStaticCatalog();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));

    await page.goto(catalog.root.getBrowserPath());
    await expectLoginModal(page);

    await page.getByRole('button', { name: /cancel/i }).click();
    await expect(page.locator('#stac-browser-auth-modal')).not.toBeVisible();
    // The catalog was not loaded
    await expect(page.getByRole('heading', { name: /Example Catalog/ })).not.toBeVisible();
  });
});

test.describe('Authenticated media', () => {
  const ITEM_URL = 'https://stac.example/item.json';
  const THUMB_URL = 'https://stac.example/thumb.png';

  function createCatalogWithItem() {
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    item.data.assets.thumbnail.href = THUMB_URL;
    return { catalog, item };
  }

  async function loginOnItemPage(page, worker, catalog, item) {
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));
    await page.goto(item.getBrowserPath());
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);
  }

  async function openThumbnailsTab(page) {
    const tab = page.getByRole('tab', { name: /thumbnails/i });
    await expect(tab).toBeVisible();
    await tab.click();
    return page.locator('.previews img.thumbnail').first();
  }

  test('thumbnails load with the auth header via object URLs', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    await mockImage(worker, THUMB_URL, hasHeader('x-api-key', 'secret'));
    await loginOnItemPage(page, worker, catalog, item);

    const img = await openThumbnailsTab(page);
    // The image can only decode if the fetch carried the header
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    await expect(img).toHaveAttribute('src', /^blob:/);
  });

  test('SVG thumbnails load with the auth header via data URLs', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>';
    await worker.use(
      http.get(THUMB_URL, ({ request }) => {
        if (!hasHeader('x-api-key', 'secret')(request)) {
          return new HttpResponse(null, { status: 401 });
        }
        return new HttpResponse(svg, { headers: { 'Content-Type': 'image/svg+xml' } });
      }),
    );
    await loginOnItemPage(page, worker, catalog, item);

    const img = await openThumbnailsTab(page);
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    // A data URL has an opaque origin, unlike an object URL
    await expect(img).toHaveAttribute('src', /^data:image\/svg\+xml/);
  });

  test('thumbnails carry the private query parameter without object URLs', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'query', name: 'API_KEY' },
    });
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    await mockImage(worker, THUMB_URL, hasQuery('API_KEY', 'secret'));
    await requireAuth(worker, ROOT_URL, hasQuery('API_KEY', 'secret'));

    await page.goto(item.getBrowserPath());
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);

    const img = await openThumbnailsTab(page);
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    await expect(img).toHaveAttribute('src', /API_KEY=secret/);
  });

  test('thumbnails on external domains are loaded without credentials', async ({ page, worker }) => {
    await configureBrowser(page, {
      catalogUrl: ROOT_URL,
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const externalThumb = 'https://other.example/thumb.png';
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    item.data.assets.thumbnail.href = externalThumb;
    await catalog.createServer(worker);
    const requests = await mockImage(worker, externalThumb);
    await loginOnItemPage(page, worker, catalog, item);

    const img = await openThumbnailsTab(page);
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    // Loaded natively (no object URL) and without the credentials
    await expect(img).not.toHaveAttribute('src', /^blob:/);
    expect(requests.length).toBeGreaterThan(0);
    expect(requests[0].headers['x-api-key']).toBeUndefined();
  });

  test('a 401 for a thumbnail does not open the login dialog', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    // The thumbnail always fails, even with credentials
    const requests = await mockImage(worker, THUMB_URL, () => false);
    await loginOnItemPage(page, worker, catalog, item);

    await openThumbnailsTab(page);
    await expect.poll(() => requests.length).toBeGreaterThan(0);
    await expect(page.locator('#stac-browser-auth-modal')).not.toBeVisible();
  });

  test('thumbnails load natively when no authentication is configured', async ({ page, worker }) => {
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    await mockImage(worker, THUMB_URL);

    await page.goto(item.getBrowserPath());
    await waitForBrowserReady(page);

    const img = await openThumbnailsTab(page);
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    await expect(img).toHaveAttribute('src', THUMB_URL);
  });

  test('failed thumbnails are hidden on cards, but kept in the thumbnails tab', async ({ page, worker }) => {
    const { catalog, item } = createCatalogWithItem();
    await catalog.createServer(worker);
    const requests = await mockImage(worker, THUMB_URL, () => false);

    await page.goto(catalog.root.getBrowserPath());
    await waitForBrowserReady(page);
    await expect.poll(() => requests.length).toBeGreaterThan(0);
    await expect(page.locator('.card img.thumbnail')).toHaveCount(0);

    await page.goto(item.getBrowserPath());
    await waitForBrowserReady(page);
    const img = await openThumbnailsTab(page);
    // Keeps the link to open or download the file
    await expect(img).toHaveAttribute('src', THUMB_URL);
  });

  test('card thumbnails on the catalog page load with the auth header', async ({ page, worker }) => {
    await configureBrowser(page, {
      catalogUrl: ROOT_URL,
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const { catalog } = createCatalogWithItem();
    await catalog.createServer(worker);
    await mockImage(worker, THUMB_URL, hasHeader('x-api-key', 'secret'));
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));

    await page.goto('/');
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);

    const img = page.locator('.card img.thumbnail').first();
    await img.scrollIntoViewIfNeeded();
    await expect.poll(() => img.evaluate(el => el.naturalWidth)).toBeGreaterThan(0);
    await expect(img).toHaveAttribute('src', /^blob:/);
  });
});

test.describe('Authenticated map layers', () => {
  const ITEM_URL = 'https://stac.example/item.json';
  const DATA_URL = 'https://stac.example/data.tif';
  const PMTILES_URL = 'https://stac.example/tiles.pmtiles';
  const ZARR_URL = 'https://stac.example/store.zarr';

  // Record the requests the map makes for a URL (the data is not valid,
  // rendering is expected to fail after the request was made)
  async function recordRequests(worker, url) {
    const requests = [];
    await worker.use(
      http.get(url, ({ request }) => {
        requests.push({
          url: request.url,
          apiKey: request.headers.get('x-api-key'),
        });
        return new HttpResponse(null, { status: 404 });
      }),
    );
    return requests;
  }

  async function loginOnItemPage(page, worker, item, check) {
    await requireAuth(worker, ROOT_URL, check);
    await page.goto(item.getBrowserPath());
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);
  }

  const HEADER_AUTH = { authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' } };
  const QUERY_AUTH = { authConfig: { type: 'apiKey', in: 'query', name: 'API_KEY' } };

  test('GeoTIFF requests on the map carry the auth header', async ({ page, worker }) => {
    await configureBrowser(page, { ...HEADER_AUTH, displayGeoTiffByDefault: true });
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, DATA_URL);
    await loginOnItemPage(page, worker, item, hasHeader('x-api-key', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].apiKey).toBe('secret');
  });

  test('GeoTIFF requests on the map carry the private query parameter', async ({ page, worker }) => {
    await configureBrowser(page, { ...QUERY_AUTH, displayGeoTiffByDefault: true });
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, DATA_URL);
    await loginOnItemPage(page, worker, item, hasQuery('API_KEY', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].url).toContain('API_KEY=secret');
  });

  function addPmtilesLink(item) {
    item.data.links.push({
      rel: 'pmtiles',
      href: PMTILES_URL,
      type: 'application/vnd.pmtiles',
    });
  }

  test('PMTiles requests on the map carry the auth header', async ({ page, worker }) => {
    await configureBrowser(page, HEADER_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addPmtilesLink(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, PMTILES_URL);
    await loginOnItemPage(page, worker, item, hasHeader('x-api-key', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].apiKey).toBe('secret');
  });

  test('PMTiles requests on the map carry the private query parameter', async ({ page, worker }) => {
    await configureBrowser(page, QUERY_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addPmtilesLink(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, PMTILES_URL);
    await loginOnItemPage(page, worker, item, hasQuery('API_KEY', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].url).toContain('API_KEY=secret');
  });

  const TILEJSON_URL = 'https://stac.example/manifest.json';

  function addTileJsonLink(item) {
    item.data.links.push({
      rel: 'tilejson',
      href: TILEJSON_URL,
      type: 'application/json',
    });
  }

  test('TileJSON manifest requests on the map carry the auth header', async ({ page, worker }) => {
    await configureBrowser(page, HEADER_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addTileJsonLink(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, TILEJSON_URL);
    await loginOnItemPage(page, worker, item, hasHeader('x-api-key', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].apiKey).toBe('secret');
  });

  test('TileJSON manifest requests on the map carry the private query parameter', async ({ page, worker }) => {
    await configureBrowser(page, QUERY_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addTileJsonLink(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, TILEJSON_URL);
    await loginOnItemPage(page, worker, item, hasQuery('API_KEY', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].url).toContain('API_KEY=secret');
  });

  function addGeoZarrAsset(item) {
    item.data.assets.zarr = {
      href: ZARR_URL,
      type: 'application/vnd.zarr; version=3; profile=multiscales',
      title: 'Data Cube',
      roles: ['data'],
    };
  }

  test('GeoZarr requests on the map carry the auth header', async ({ page, worker }) => {
    await configureBrowser(page, HEADER_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addGeoZarrAsset(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, `${ZARR_URL}/zarr.json`);
    await loginOnItemPage(page, worker, item, hasHeader('x-api-key', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].apiKey).toBe('secret');
  });

  test('GeoZarr requests on the map carry the private query parameter', async ({ page, worker }) => {
    await configureBrowser(page, QUERY_AUTH);
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    addGeoZarrAsset(item);
    await catalog.createServer(worker);
    const requests = await recordRequests(worker, `${ZARR_URL}/zarr.json`);
    await loginOnItemPage(page, worker, item, hasQuery('API_KEY', 'secret'));

    await expect.poll(() => requests.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(requests[0].url).toContain('API_KEY=secret');
  });
});

test.describe('External viewer actions', () => {
  const ITEM_URL = 'https://stac.example/item.json';

  // A GeoJSON asset, for which the geojson.io action (enabled by default) shows
  function createCatalogWithGeoJsonAsset() {
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: ITEM_URL });
    item.data.assets.vector = {
      href: 'https://stac.example/data.geojson',
      type: 'application/geo+json',
      title: 'Vector Data',
      roles: ['data'],
    };
    return { catalog, item };
  }

  test('are hidden when header credentials are required', async ({ page, worker }) => {
    await configureBrowser(page, {
      authConfig: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    });
    const { catalog, item } = createCatalogWithGeoJsonAsset();
    await catalog.createServer(worker);
    await requireAuth(worker, ROOT_URL, hasHeader('x-api-key', 'secret'));

    await page.goto(item.getBrowserPath());
    await expectLoginModal(page);
    await submitApiKey(page, 'secret');
    await waitForBrowserReady(page);

    await page.getByRole('button', { name: /vector data/i }).click();
    await expect(page.getByRole('button', { name: /download/i }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /geojson\.io/i })).not.toBeVisible();
  });

  test('are shown without authentication', async ({ page, worker }) => {
    const { catalog, item } = createCatalogWithGeoJsonAsset();
    await catalog.createServer(worker);

    await page.goto(item.getBrowserPath());
    await waitForBrowserReady(page);

    await page.getByRole('button', { name: /vector data/i }).click();
    await expect(page.getByRole('button', { name: /geojson\.io/i })).toBeVisible();
  });
});

test.describe('STAC Authentication extension', () => {
  test('unsupported scheme on an asset shows an error on login attempt', async ({ page, worker }) => {
    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: 'https://stac.example/item.json' });
    item.setMetadata({
      'auth:schemes': {
        oauth: {
          type: 'oauth2',
          flows: {
            authorizationCode: {
              authorizationUrl: 'https://auth.example/authorize',
              tokenUrl: 'https://auth.example/token',
              scopes: {},
            },
          },
        },
      },
    });
    item.data.assets.data['auth:refs'] = ['oauth'];
    await catalog.createServer(worker);

    await page.goto(item.getBrowserPath());
    await waitForBrowserReady(page);

    // Expand the accordion of the asset that requires authentication
    await page.getByRole('button', { name: /measurements/i }).click();

    const authButton = page.getByRole('button', { name: /authentication required/i }).first();
    await expect(authButton).toBeVisible();
    await authButton.click();
    await expect(page.getByText(/is not supported by STAC Browser/i)).toBeVisible();
  });
  const OIDC_URL = 'https://auth.example/.well-known/openid-configuration';
  const TOKEN_URL = 'https://broker.example/oauth/token';
  // The data is on another domain, only the folder of the assets
  // that reference the scheme receives the exchanged credentials
  const PRIVATE_THUMB_URL = 'https://data.example/private/thumb.png';
  const PUBLIC_THUMB_URL = 'https://data.example/public/thumb.png';

  // An item with an asset that requires a token exchange, a user who is
  // logged in at the OpenID Connect provider and a mocked token endpoint.
  async function setupTokenExchange(page, worker, config) {
    await configureBrowser(page, {
      oidcConfigs: { [OIDC_URL]: { client_id: 'browser-client' } },
      ...config,
    });
    // The session as stored by oidc-client-ts
    await page.addInitScript(() => {
      window.sessionStorage.setItem('oidc.user:https://auth.example:browser-client', JSON.stringify({
        id_token: 'identity-token',
        access_token: 'oidc-access-token',
        token_type: 'Bearer',
        profile: { sub: 'user' },
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }));
    });

    const catalog = createStaticCatalog();
    const item = catalog.addItem({ url: 'https://stac.example/item.json' });
    item.setMetadata({
      'auth:schemes': {
        oidc: { type: 'openIdConnect', openIdConnectUrl: OIDC_URL },
        exchange: {
          type: 'oauth2',
          'auth:refs': ['oidc'],
          flows: {
            tokenExchange: {
              tokenUrl: TOKEN_URL,
              subjectTokenType: 'urn:ietf:params:oauth:token-type:id_token',
              scopes: { 'read:data': 'Read the data' },
            },
          },
        },
      },
    });
    item.data.assets.data.href = 'https://data.example/private/data.tif';
    item.data.assets.data['auth:refs'] = ['exchange'];
    item.data.assets.thumbnail.href = PRIVATE_THUMB_URL;
    item.data.assets.thumbnail['auth:refs'] = ['exchange'];
    item.data.assets.overview = { href: PUBLIC_THUMB_URL, type: 'image/png', roles: ['thumbnail'] };
    await catalog.createServer(worker);
    const thumbnails = await mockImage(worker, PRIVATE_THUMB_URL, hasHeader('authorization', 'Bearer exchanged-token'));
    const publicThumbnails = await mockImage(worker, PUBLIC_THUMB_URL);

    const exchanges = [];
    await worker.use(
      http.post(TOKEN_URL, async ({ request }) => {
        exchanges.push(Object.fromEntries(new URLSearchParams(await request.text())));
        return HttpResponse.json({
          access_token: 'exchanged-token',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: 3600,
        });
      }),
    );

    await page.goto(item.getBrowserPath());
    await waitForBrowserReady(page);
    await page.getByRole('button', { name: /measurements/i }).click();
    await page.getByRole('button', { name: /authentication required/i }).first().click();
    return { item, exchanges, thumbnails, publicThumbnails };
  }

  test('token exchange: exchanges the OpenID Connect token for the credentials', async ({ page, worker }) => {
    const { item, exchanges, thumbnails, publicThumbnails } = await setupTokenExchange(page, worker, { tokenExchanges: { [TOKEN_URL]: ['https://data.example/'] } });

    await expect.poll(() => exchanges.length).toBe(1);
    expect(exchanges[0]).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: 'identity-token',
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      resource: item.getAbsoluteUrl(),
      scope: 'read:data',
    });
    await expect(page.getByRole('button', { name: /authentication required/i })).toHaveCount(0);

    await page.getByRole('tab', { name: /thumbnails/i }).click();
    await expect.poll(() => thumbnails.some(r => r.headers.authorization === 'Bearer exchanged-token')).toBe(true);
    await expect.poll(() => publicThumbnails.length).toBeGreaterThan(0);
    expect(publicThumbnails.every(r => !r.headers.authorization)).toBe(true);
  });

  test('token exchange: the token is not sent to token URLs that are not allowed', async ({ page, worker }) => {
    const { exchanges } = await setupTokenExchange(page, worker, { tokenExchanges: { 'https://other.example/token': ['https://data.example/'] } });

    await expect(page.getByText(/is not supported by STAC Browser/i)).toBeVisible();
    expect(exchanges).toHaveLength(0);
  });
  test('token exchange: the credentials are only sent to the URLs allowed by the operator', async ({ page, worker }) => {
    // The document's assets are in /private/, the operator only allows /public/
    const { exchanges, thumbnails } = await setupTokenExchange(page, worker, {
      tokenExchanges: { [TOKEN_URL]: ['https://data.example/public/'] },
    });

    await expect.poll(() => exchanges.length).toBe(1);
    await page.getByRole('tab', { name: /thumbnails/i }).click();
    await expect.poll(() => thumbnails.length).toBeGreaterThan(0);
    expect(thumbnails.every(r => !r.headers.authorization)).toBe(true);
  });

  test('token exchange: configured request headers are not sent to external data', async ({ page, worker }) => {
    const { exchanges, thumbnails } = await setupTokenExchange(page, worker, {
      catalogUrl: ROOT_URL,
      requestHeaders: { 'X-Static': 'secret' },
      tokenExchanges: { [TOKEN_URL]: ['https://data.example/'] },
    });

    await expect.poll(() => exchanges.length).toBe(1);
    await page.getByRole('tab', { name: /thumbnails/i }).click();
    await expect.poll(() => thumbnails.some(r => r.headers.authorization === 'Bearer exchanged-token')).toBe(true);
    expect(thumbnails.every(r => !r.headers['x-static'])).toBe(true);
  });
});
