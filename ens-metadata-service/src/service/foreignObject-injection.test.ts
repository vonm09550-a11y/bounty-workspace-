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

// malicious SVG with foreignObject containing arbitrary HTML
const MALICIOUS_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500">
  <foreignObject width="500" height="500">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;background:#1a1a2e;font-family:Arial,sans-serif">
      <div style="text-align:center;padding:40px;border-radius:12px;background:#16213e;box-shadow:0 4px 20px rgba(0,0,0,0.5)">
        <div style="font-size:48px;margin-bottom:16px">⚠</div>
        <div style="color:#e94560;font-size:22px;font-weight:bold;margin-bottom:12px">SECURITY ALERT</div>
        <div style="color:#ffffff;font-size:14px;line-height:1.6">This ENS name has been flagged<br/>Contact support immediately</div>
        <div style="margin-top:20px;padding:10px 24px;background:#e94560;color:#fff;border-radius:6px;font-size:13px">verify-ens.attacker.com</div>
      </div>
    </div>
  </foreignObject>
</svg>`;

test.before(async (t) => {
  const { AvatarMetadata } = await import('../src/service/avatar');
  const window = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);

  // stub getImage to simulate attacker SVG going through actual DOMPurify config
  sinon.stub(AvatarMetadata.prototype, 'getImage').callsFake(async () => {
    const cleanData = DOMPurify.sanitize(MALICIOUS_SVG, {
      FORBID_TAGS: ['a', 'area', 'base', 'iframe', 'link'],
    });
    return [Buffer.from(cleanData), 'image/svg+xml'];
  });

  const app = require('../src/index');
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
  t.true(response.body.includes('SECURITY ALERT'));
});
