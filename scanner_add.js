// scanner.js
import path from 'path';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import pLimit from 'p-limit';
import {
  writeResultsToCsv,
  writeErrorLogToCsv,
  getCsvFilePath
} from './csv-utils.js';
import UserAgent from 'user-agents';
import { URL } from 'url';
import whois from "whois-json";
import os from 'os';



const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const stealth = StealthPlugin();
stealth.enabledEvasions.delete("chrome.app");
stealth.enabledEvasions.delete("chrome.csi");
stealth.enabledEvasions.delete("chrome.loadTimes");
stealth.enabledEvasions.delete("chrome.runtime");
stealth.enabledEvasions.delete("iframe.contentWindow");
stealth.enabledEvasions.delete("navigator.plugins");
stealth.enabledEvasions.delete("navigator.permissions");
stealth.enabledEvasions.delete("navigator.hardwareConcurrency");
stealth.enabledEvasions.delete("navigator.languages");
stealth.enabledEvasions.delete("media.codecs");
stealth.enabledEvasions.delete("webgl.vendor");
stealth.enabledEvasions.delete("window.outerdimensions");
stealth.enabledEvasions.delete("sourceurl"); 
puppeteer.use(stealth);

const SCRAPER_API_PROXY_PASS = '90317b95504115f9b4dba053893976e4';


let browser;
let relaunching = null;
async function launchBrowser(proxy = null) {
  if (browser) {
    try {
      await browser.close();
    } catch (_) {}
  }

  const args = [
    // safety over speed
    // `--user-data-dir=${path.join(os.tmpdir(), `pupp-${Date.now()}`)}`,
    // '--no-sandbox',
    // '--disable-setuid-sandbox',
    // '--disable-dev-shm-usage',
    // '--disable-accelerated-2d-canvas',
    // '--no-first-run',
    // '--no-zygote',
    // '--disable-gpu',
    // '--disable-infobars',
    // '--disable-web-security',
    // '--ignore-certificate-errors',
    // '--disable-features=IsolateOrigins,site-per-process'

    //speed over safety
    `--user-data-dir=${path.join(os.tmpdir(), `pupp-${Date.now()}`)}`,
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
  ];

  if (proxy) {
    args.push(`--proxy-server=${proxy}`);
  }

  browser = await puppeteer.launch({
    headless: 'new',
    args,
    protocolTimeout: 180000 //change
  });

  await delay(2500);
}

// 🚀 Safe global relaunch (only one at a time)
async function ensureBrowserRelaunched(proxy = null) {
  if (relaunching) {
    // someone else is already relaunching → wait for them
    await relaunching;
    return browser;
  }
  relaunching = (async () => {
    console.warn("🔁 Relaunching browser (global)...");
    await launchBrowser(proxy);
    relaunching = null; // reset lock
    return browser;
  })();
  return relaunching;
}

export const getDomFeatures = async (page, url, userAgent) => {

  const safeEval = async (fn, fallback) => {
    try {
      return await page.evaluate(fn);
    } catch {
      return fallback;
    }
  };

  try {
    if (page && !page.isClosed()) {
      await page.setUserAgent(userAgent);
    }
  } catch (err) {
    console.warn(`⚠️ Failed to set User-Agent: ${err.message}`);
  }

  await page.setViewport({ width: 1366, height: 768 });
  await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });
  await page.setJavaScriptEnabled(true);

  await delay(500);
  // await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });
    await delay(1000);
  } catch (_) {
    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 90000 });
      await delay(1000);
    } catch (e) {
      throw new Error(`Navigation failed (fallback too): ${e.message}`);
    }
}

  function shannonEntropy(str) {
  const map = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    map[ch] = (map[ch] || 0) + 1;
  }
  const len = str.length;
  return Object.values(map)
    .map(freq => freq / len)
    .reduce((sum, p) => sum - p * Math.log2(p), 0);
}

 // trial changes
  async function extractJsFeatures(page, pageUrl) {
    try {
      const origin = new URL(pageUrl).origin;

      // Attempt to get scripts via safeEval
      let scripts = await safeEval(() => {
        return Array.from(document.scripts).map(s => ({
          src: s.src,
          content: s.textContent
        }));
      }, []);

      if (!Array.isArray(scripts)) {
        throw new Error('scripts is not iterable');
      }

      let js_len = 0;
      let js_obf_len = 0;
      let js_external_count = 0;
      const jsThresholdEntropy = 4.3;

      for (const script of scripts) {
        let content = script.content || '';

        if (script.src) {
          try {
            const scriptUrl = new URL(script.src, pageUrl);
            if (scriptUrl.origin !== origin) {
              js_external_count++;
              continue;
            }

            content = await safeEval(async src => {
              try {
                const r = await fetch(src);
                if (!r.ok) return '';
                return await r.text();
              } catch {
                return '';
              }
            }, '', script.src);
          } catch {
            continue;
          }
        }

        const len = content.length;
        if (!len) continue;

        js_len += len;

        const entropy = shannonEntropy(content);
        if (entropy > jsThresholdEntropy) {
          js_obf_len += len;
        }
      }

      return {
        js_len,
        js_obf_len,
        js_external_count
      };

    } catch (err) {
      console.warn(`Error in extractJsFeatures: ${err.message}`);
      return {
        js_len: -1,
        js_obf_len: -1,
        js_external_count: -1
      };
    }
  }

  
  const jsFeatures = await extractJsFeatures(page, url);

  return {
    ...jsFeatures
  };
};

// async function checkWhoisComplete(url) {
//   const parsed = new URL(url);
//   const domain = parsed.hostname;

//   try {
//     // Try native WHOIS lookup
//     const result = await whois(domain, { follow: 3, timeout: 20000 });
//     const registrar = String(result.registrar || "").trim();

//     return registrar.length > 1 ? 1 : 0;

//   } catch (err) {
//     console.error(`🚫 WHOIS failed for ${url}:`, err.message || err);
//     return -1;
//   }

// }

async function checkWhoisComplete(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.replace(/^www\./, "");

    async function safeWhois(domain, retries = 2) {
      for (let i = 0; i < retries; i++) {
        try {
          return await whois(domain, { follow: 1, timeout: 20000 });
        } catch (err) {
          // Retry only if it's a network/DNS issue
          if (
            i < retries - 1 &&
            (err.code === "ECONNRESET" || err.code === "ENOTFOUND" || err.code === "EAI_AGAIN")
          ) {
            console.warn(`⚠️ WHOIS retry ${i + 1} for ${domain}: ${err.message}`);
            await delay(2000);
            continue;
          }
          throw err; // rethrow if not retryable or last attempt
        }
      }
    }

    const result = await safeWhois(domain);
    const registrar = String(result?.registrar || "").trim();

    return registrar.length > 1 ? 1 : 0;

  } catch (err) {
    if (err.code === "ENOTFOUND") {
      console.warn(`🌐 WHOIS server not found for ${url} — likely unsupported TLD or DNS issue.`);
      return 0; // treat as incomplete
    }
    console.error(`🚫 WHOIS failed for ${url}:`, err.message || err);
    return 0;
  }
}



async function checkHTTPsStatus(url) {
  let isHttps = 0;
  try {
    const parsed = new URL(url);
    isHttps = parsed.protocol === "https:" ? 1 : 0;
  } catch {
    isHttps = -1;
  }

  return isHttps;
}



export async function setupRequestInterception(page) {
  const blockedExtensions = [
    '.zip', '.rar', '.pdf', '.exe', '.doc', '.xls',
    '.msi', '.dmg', '.iso', '.7z', '.tar', '.gz', '.txt', '.apk',
    '.rss', 'AppImage', '.mp3'
  ];

  await page.setRequestInterception(true);

  page.on('request', req => {
    const url = req.url().toLowerCase();
    const type = req.resourceType();

    if (
      ['image', 'stylesheet', 'font'].includes(type) ||
      blockedExtensions.some(ext => url.endsWith(ext))
    ) {
      req.abort();
    } else {
      req.continue();
    }
  })};

async function tryScan(page, url, sslBypass, userAgent) {
  if (!page || page.isClosed()) {
    throw new Error("Page was closed before scan could start");
  }
  const client = await page.target().createCDPSession();
  if (sslBypass && url.startsWith('https://')) {
    await client.send('Security.setIgnoreCertificateErrors', { ignore: true });
  }
  return await getDomFeatures(page, url, userAgent);
}

export const scanUrls = async (urls, concurrencyLimit = 30) => {
  const pageLimit = pLimit(concurrencyLimit);
  const limit = pLimit(concurrencyLimit);
  const proxyLimit = pLimit(5);
  const results = {}; 
  const errorLog = [];

  await launchBrowser();

  async function scanWithRetry(originalUrl) {
    // const baseUrl = originalUrl.replace('://www.', '://');
    const versions = [
      { url: originalUrl, sslBypass: false },
      // { url: baseUrl, sslBypass: false },
      { url: originalUrl, sslBypass: true },
      // { url: baseUrl, sslBypass: true }
    ];

    const proxyRetryErrors = [
      // 'net::ERR_BLOCKED_BY_CLIENT',
      // 'net::ERR_CONNECTION_REFUSED',
      // // 'net::ERR_CONNECTION_TIMED_OUT',
      // 'ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
      // 'net::ERR_SSL_PROTOCOL_ERROR',
      // 'net::ERR_SSL_UNRECOGNIZED_NAME_ALERT',
      // 'net::ERR_HTTP2_PROTOCOL_ERROR',
      // 'net::ERR_CONNECTION_RESET',
      // 'ERR_NETWORK_CHANGED'
    ];

    let userAgent = new UserAgent().toString();
    let errorMsgs = [];
    let proxyNeeded = false;
    let result;
    // let networkChangedRetries = 0;

    // Non SSL Bypass Scanning
    let errNameNotResolvedCount = 0;
    let errConnectionTimedOut = 0;
    const nonBypassAttempts = versions.filter(v => !v.sslBypass);

    for (let { url, sslBypass } of nonBypassAttempts) {
      let page;
      try {
        page = await pageLimit(() => browser.newPage());
        await delay(2500);
        await setupRequestInterception(page);

        const features = await tryScan(page, url, sslBypass, userAgent);
        await delay(1000 + Math.random() * 500);

        return {
          features,
          finalUrl: url,
          sslBypassUsed: sslBypass ? 1 : 0,
          usedProxy: false,
          userAgent
        };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message}`);

        // Increment for the Skip SSL
        if (err.message.includes('ERR_NAME_NOT_RESOLVED')) {
          errNameNotResolvedCount++;
        }
        if (err.message.includes('ERR_CONNECTION_TIMED_OUT')) {
          errConnectionTimedOut++;
        }
        

        // Re run the puppeteer if it suddenly closed
        if (err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching browser due to closed connection at ${url}`);
          await ensureBrowserRelaunched();
          await delay(3000);

        }

        // Specifically if ERR_NETWORK_CHANGED encounter
        // if (err.message.includes('ERR_NETWORK_CHANGED')) {
        //   if (networkChangedRetries < 1) {
        //     console.warn(`⚠️ Network change detected for ${url}, retrying once...`);
        //     networkChangedRetries++;
        //     await delay(5000);
        //     continue;
        //   } else {
        //     console.warn(`🌐 Retrying with proxy after network change for ${url}`);
        //     proxyNeeded = true;
        //     break; // Exit normal scanning and go to proxy block
        //   }
        // }

        if (proxyRetryErrors.some(e => err.message.includes(e))) proxyNeeded = true;

      } finally {
        if (page) await page.close().catch(() => {});
      }
    }

    // Skip SSL 
    if (errNameNotResolvedCount === nonBypassAttempts.length) {
      console.warn(`🚫 Skipping SSL bypass for ${originalUrl}`);
      throw new Error(errorMsgs.map(msg => `- ${msg}`).join('\n'));
    }

    if (errConnectionTimedOut === nonBypassAttempts.length) {
      console.warn(`🚫 Skipping SSL bypass for ${originalUrl}`);
      throw new Error(errorMsgs.map(msg => `- ${msg}`).join('\n'));
    }

    // SSL Bypass Scanning
    const bypassAttempts = versions.filter(v => v.sslBypass);

    for (let { url, sslBypass } of bypassAttempts) {
      let page;
      try {
        page = await pageLimit(() => browser.newPage());
        await delay(2500);

        await page.setRequestInterception(true);
        await setupRequestInterception(page);

        const features = await tryScan(page, url, sslBypass, userAgent);
        await delay(1000 + Math.random() * 500);
        await page.close();

        return {
          features,
          finalUrl: url,
          sslBypassUsed: sslBypass ? 1 : 0,
          usedProxy: false,
          userAgent
        };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message}`);

        if (err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching browser due to closed connection at ${url}`);
          await ensureBrowserRelaunched();
          await delay(3000);

        }

        if (proxyRetryErrors.some(e => err.message.includes(e))) proxyNeeded = true;

      } finally {
        if (page) await page.close().catch(() => {});
      }
    }

    // With Proxy Scanning
    if (proxyNeeded) {
      console.warn(`🌐 Retrying ${originalUrl} using ScraperAPI URL proxy`);

      await proxyLimit(async () => {
        for (let { url } of versions) {
          let page;
          try {
            const scraperApiUrl = `http://api.scraperapi.com/?api_key=${SCRAPER_API_PROXY_PASS}&url=${encodeURIComponent(url)}`;

            page = await pageLimit(() => browser.newPage());
            await delay(2500);

            await page.setRequestInterception(true);
            page.on('request', req => {
              const type = req.resourceType();
              if (["image", "stylesheet", "font"].includes(type)) req.abort();
              else req.continue();
            });

            const features = await tryScan(page, scraperApiUrl, false, userAgent);
            await delay(1000 + Math.random() * 500);
            await page.close();

            result = {
              features,
              finalUrl: url,
              sslBypassUsed: 0,
              usedProxy: true,
              userAgent
            };
          } catch (err) {
            const msg = `ScraperAPI (fallback): ${err.message}`;
            errorMsgs.push(msg);
            console.error(`❌ Proxy error for ${url}: ${msg}`);
          } finally {
            if (page) await page.close().catch(() => {});
          }
        }
      });
    }

    if (result) return result;
    throw new Error(errorMsgs.map(msg => `- ${msg}`).join('\n'));
  }


  const tasks = urls.map(({ url, label }) =>
    limit(async () => {
      try {
        console.log(`Scanning: ${url}`);

        const { features, finalUrl, sslBypassUsed, usedProxy, userAgent } = await scanWithRetry(url);
        const isHttps = await checkHTTPsStatus(finalUrl); // check if the link is in https
        const whoisComplete = await checkWhoisComplete(finalUrl); //check if the whois is complete

        results[url] = {
          ...features,
          isHttps,  
          whoisComplete,
          label
        };
        console.log(`✅ Scanned: ${url}`);
      } catch (err) {
        console.error(`❌ Failed URL: ${url}`);
        console.error(`   ↳ Error: ${err.message}`);
        results[url] = {error: err.message, finalUrlTried: url,label};
        errorLog.push({url,error: err.message});
      }
    })
  );

  await Promise.all(tasks);

  try {
    if (browser) await browser.close();
  } catch (_) {}

  await writeResultsToCsv(getCsvFilePath(), results);
  return results;
};

