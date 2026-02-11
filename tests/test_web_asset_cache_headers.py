import asyncio
import unittest

from starlette.requests import Request
from starlette.responses import Response

import east.web.app as web_app


class WebAssetCacheHeadersTests(unittest.TestCase):
    def test_index_injects_asset_version_and_no_store_headers(self):
        response = asyncio.run(web_app.index())
        self.assertIn(f"/static/js/app.js?v={web_app.ASSET_VERSION}", response.body.decode('utf-8'))
        self.assertIn(f"/static/css/app.css?v={web_app.ASSET_VERSION}", response.body.decode('utf-8'))
        self.assertEqual(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate')
        self.assertEqual(response.headers.get('pragma'), 'no-cache')
        self.assertEqual(response.headers.get('expires'), '0')

    def test_cache_middleware_sets_no_store_for_static_and_root(self):
        async def call_next(_request):
            return Response('ok')

        root_request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'headers': [], 'query_string': b''})
        root_response = asyncio.run(web_app._set_cache_headers(root_request, call_next))
        self.assertEqual(root_response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate')

        static_request = Request({'type': 'http', 'method': 'GET', 'path': '/static/js/app.js', 'headers': [], 'query_string': b''})
        static_response = asyncio.run(web_app._set_cache_headers(static_request, call_next))
        self.assertEqual(static_response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate')

        api_request = Request({'type': 'http', 'method': 'GET', 'path': '/api/jobs', 'headers': [], 'query_string': b''})
        api_response = asyncio.run(web_app._set_cache_headers(api_request, call_next))
        self.assertIsNone(api_response.headers.get('cache-control'))


if __name__ == '__main__':
    unittest.main()
