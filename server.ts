import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = parseInt(process.env.PORT || '3000', 10);
  const isProduction = process.env.NODE_ENV === 'production';

  app.use(express.json({ limit: '10mb' }));

  // API Route: Fetch PE header from URL
  app.post('/api/fetch-pe-header', async (req: Request, res: Response): Promise<void> => {
    try {
      const { url, maxBytes = 65536 } = req.body;

      if (!url || typeof url !== 'string') {
        res.status(400).json({ success: false, error: 'A valid URL string is required.' });
        return;
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch {
        res.status(400).json({ success: false, error: 'Invalid URL format. Must include protocol (e.g. https://).' });
        return;
      }

      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        res.status(400).json({ success: false, error: 'Only http and https protocols are supported.' });
        return;
      }

      // Basic SSRF protection against loopback/internal addresses
      const hostname = parsedUrl.hostname.toLowerCase();
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '::1' ||
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('172.16.') ||
        hostname === '169.254.169.254'
      ) {
        res.status(403).json({ success: false, error: 'Fetching from private or local addresses is not permitted.' });
        return;
      }

      const byteLimit = Math.min(Math.max(1024, Number(maxBytes) || 65536), 524288); // 1KB to 512KB

      // Abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000); // 12 seconds timeout

      // Request with Range header to efficiently fetch only the PE headers
      const fetchHeaders: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PEHeaderInspector/1.0',
        'Range': `bytes=0-${byteLimit - 1}`,
        'Accept': '*/*',
      };

      let response: globalThis.Response;
      try {
        response = await fetch(url, {
          headers: fetchHeaders,
          signal: controller.signal,
          redirect: 'follow',
        });
      } catch (err: unknown) {
        clearTimeout(timeoutId);
        const errMsg = err instanceof Error ? err.message : String(err);
        res.status(502).json({ success: false, error: `Network error while fetching URL: ${errMsg}` });
        return;
      }

      clearTimeout(timeoutId);

      if (!response.ok && response.status !== 206) {
        res.status(response.status).json({
          success: false,
          error: `Remote server responded with HTTP status ${response.status} (${response.statusText || 'Error'})`,
          status: response.status,
        });
        return;
      }

      const contentLengthHeader = response.headers.get('content-length');
      const contentRangeHeader = response.headers.get('content-range');
      const contentType = response.headers.get('content-type') || 'application/octet-stream';
      const lastModified = response.headers.get('last-modified');
      const etag = response.headers.get('etag');
      const serverHeader = response.headers.get('server');

      let totalSize: number | null = null;
      if (contentRangeHeader) {
        const match = contentRangeHeader.match(/\/(\d+|\*)$/);
        if (match && match[1] !== '*') {
          totalSize = parseInt(match[1], 10);
        }
      } else if (contentLengthHeader && response.status === 200) {
        totalSize = parseInt(contentLengthHeader, 10);
      }

      // Read stream up to byteLimit
      const arrayBuffer = await response.arrayBuffer();
      const slicedBuffer = arrayBuffer.byteLength > byteLimit ? arrayBuffer.slice(0, byteLimit) : arrayBuffer;
      const base64Data = Buffer.from(slicedBuffer).toString('base64');

      res.json({
        success: true,
        url,
        finalUrl: response.url,
        status: response.status,
        statusText: response.statusText,
        isPartial: response.status === 206 || slicedBuffer.byteLength < (totalSize ?? slicedBuffer.byteLength),
        fetchedBytes: slicedBuffer.byteLength,
        totalSize: totalSize ?? slicedBuffer.byteLength,
        contentType,
        headers: {
          lastModified,
          etag,
          server: serverHeader,
          contentRange: contentRangeHeader,
          contentLength: contentLengthHeader,
        },
        dataBase64: base64Data,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Unknown server error';
      res.status(500).json({ success: false, error: errMsg });
    }
  });

  // Setup Vite in development or serve dist in production
  if (!isProduction) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
        watch: process.env.DISABLE_HMR === 'true' ? null : {},
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PE Header Inspector] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[PE Header Inspector] Failed to start server:', err);
  process.exit(1);
});
