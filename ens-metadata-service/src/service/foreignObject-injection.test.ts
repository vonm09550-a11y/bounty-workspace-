import avaTest, { TestFn } from 'ava';
import sinon from 'sinon';
import got from 'got';
import http from 'http';
import testListen from 'test-listen';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

interface TestContext {
  appServer: http.Server;
  appUrl: string;
}

const test = avaTest as TestFn<TestContext>;

const MALICIOUS_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300">
  <foreignObject width="400" height="300">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width:100%;height:100%;background:#0d1117;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif">
      <div style="background:#161b22;border:1px solid #f85149;border-radius:6px;padding:24px 32px;max-width:320px">
        <div style="color:#f85149;font-size:15px;font-weight:600;margin-bottom:8px">Account Verification Required</div>
        <div style="color:#c9d1d9;font-size:13px;line-height:1.5;margin-bottom:16px">This domain requires re-verification due to suspicious activity detected on your wallet</div>
        <div style="background:#238636;color:#fff;padding:8px 16px;border-radius:4px;font-size:13px;text-align:center">ens-verify.net/auth</div>
      </div>
    </div>
  </foreignObject>
</svg>`;

test.before(async (t) => {
  const { AvatarMetadata } = await import('./avatar');
  const window = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);

  sinon.stub(AvatarMetadata.prototype, 'getImage').callsFake(async () => {
    const cleanData = DOMPurify.sanitize(MALICIOUS_SVG, {
      FORBID_TAGS: ['a', 'area', 'base', 'iframe', 'link'],
    });
    return [Buffer.from(cleanData), 'image/svg+xml'];
  });

  const app = require('../index');
  t.context.appServer = http.createServer(app);
  t.context.appUrl = await testListen(t.context.appServer);
});

test.after.always((t) => {
  sinon.restore();
  if (t.context.appServer) t.context.appServer.close();
});

test('foreignObject bypasses DOMPurify FORBID_TAGS', async (t) => {
  const response = await got(`${t.context.appUrl}/mainnet/avatar/test.eth`, {
    headers: { 'sec-fetch-dest': 'document' },
    throwHttpErrors: false
  });

  t.is(response.headers['content-type'], 'text/html');
  t.true(response.body.includes('foreignObject'));
  t.true(response.body.includes('Verification Required'));
});
