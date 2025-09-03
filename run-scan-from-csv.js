// run-scan-from-csv.js
import path from 'path';
import fsSync from 'fs';
import { fileURLToPath } from 'url';
import { scanUrls } from './scanner_add.js';
import {
  readUrlsFromCsv,
  writeResultsToCsv,
  writeErrorLogToCsv,
  getCsvFilePath
} from './csv-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const uploadsDir = path.join(__dirname, 'uploads');
const outputCsv = path.join(__dirname, 'outputs', 'dom-dataset.csv');

// ✅ delay helper
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ✅ function to get all CSV files sorted by modified time (oldest → newest)
function getAllCsvFiles(dir) {
  return fsSync.readdirSync(dir)
    .filter(file => file.endsWith('.csv'))
    .map(file => ({
      file,
      time: fsSync.statSync(path.join(dir, file)).mtime.getTime()
    }))
    .sort((a, b) => a.time - b.time) // oldest first
    .map(f => path.join(dir, f.file));
}

(async () => {
  const csvFiles = getAllCsvFiles(uploadsDir);

  if (csvFiles.length === 0) {
    console.error('❌ No CSV files found in uploads directory.');
    process.exit(1);
  }

  console.log(`📂 Found ${csvFiles.length} CSV file(s). Processing sequentially...\n`);

  for (let i = 0; i < csvFiles.length; i++) {
    const csvFile = csvFiles[i];
    const errorCsv = path.join(__dirname, 'outputs', `errors-${Date.now()}.csv`);

    console.log(`\n▶️ [${i + 1}/${csvFiles.length}] Processing: ${csvFile}`);

    const urls = await readUrlsFromCsv(csvFile);
    if (!urls.length) {
      console.warn(`⚠️ No URLs found in ${csvFile}, skipping.`);
      continue;
    }

    const results = await scanUrls(urls);

    const errors = Object.entries(results)
      .filter(([, val]) => val.error)
      .map(([url, val]) => ({ url, error: val.error }));

    if (errors.length) {
      await writeErrorLogToCsv(errorCsv, errors);
      console.warn(`⚠️ Logged ${errors.length} errors to ${errorCsv}`);
    }

    console.log(`✅ Finished processing ${csvFile}`);

    if (i < csvFiles.length - 1) {
      console.log(`⏳ Waiting 5 seconds before next CSV...\n`);
      await delay(5000); // change 5000 (ms) to any duration you prefer
    }
  }

  console.log('\n🎉 All CSV files processed!');
})();
