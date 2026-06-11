import { parentPort } from 'worker_threads';
import fs from 'fs/promises';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const pdf = require('pdf-parse');
const mammoth = require('mammoth');

parentPort.on('message', async ({ securePath, mimeType, pageStart, pageEnd, fileName }) => {
  try {
    const buffer = await fs.readFile(securePath);
    if (mimeType === 'application/pdf') {
      const pdfOptions = { max: 0 };
      const pdfData = await pdf(buffer, pdfOptions);
      let pages;
      if (pdfData.nativePageTexts && pdfData.nativePageTexts.length > 1) {
        pages = pdfData.nativePageTexts;
      } else {
        const ffPages = pdfData.text.split(/\f/);
        if (ffPages.length > 1) {
          pages = ffPages;
        } else {
          const CHUNK = 3000;
          const t = pdfData.text;
          pages = [];
          for (let i = 0; i < t.length; i += CHUNK) pages.push(t.slice(i, i + CHUNK));
        }
      }
      const totalPages = pages.length;
      const start = Math.max(1, parseInt(pageStart) || 1);
      const end   = Math.min(totalPages, parseInt(pageEnd) || totalPages);
      const slice = pages.slice(start - 1, end).join("\n");
      const header = `[PDF: ${fileName} | Pages ${start}–${end} of ${totalPages}]\n\n`;

      parentPort.postMessage({ success: true, text: header + slice });
    }
            
    else if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
      const docxData = await mammoth.extractRawText({ buffer: buffer });
      parentPort.postMessage({ success: true, text: docxData.value });
    }

    else {
      throw new Error(`Worker received unsupported MIME type: ${mimeType}`);
    }
      
  } catch (error) {
    parentPort.postMessage({ success: false, error: error.message });
  }
});
