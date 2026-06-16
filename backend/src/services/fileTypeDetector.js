// File-type detection. Uses `file-type` (magic-byte sniffing, the libmagic
// equivalent in Node) with an extension fallback, then normalizes to the four
// AETHER categories: PDF | Image | JS | Archive (else Unknown).
//
// MOCK NOTE: this is real magic-byte detection but the *category mapping* is
// AETHER-specific. Extend the maps below to support more formats.
import { fileTypeFromBuffer } from 'file-type';

const MIME_TO_CATEGORY = [
  [/^application\/pdf/, 'PDF'],
  [/^image\//, 'Image'],
  [/^application\/(zip|x-7z|x-rar|x-tar|gzip)/, 'Archive'],
  [/^(application|text)\/(javascript|ecmascript)/, 'JS'],
];

const EXT_TO_CATEGORY = {
  pdf: 'PDF',
  png: 'Image', jpg: 'Image', jpeg: 'Image', gif: 'Image', bmp: 'Image', webp: 'Image',
  zip: 'Archive', '7z': 'Archive', rar: 'Archive', tar: 'Archive', gz: 'Archive',
  js: 'JS', mjs: 'JS', cjs: 'JS', jse: 'JS',
};

export async function detectFileType(buffer, originalName = '') {
  let mime = null;
  let detectedExt = null;
  try {
    const ft = await fileTypeFromBuffer(buffer);
    if (ft) {
      mime = ft.mime;
      detectedExt = ft.ext;
    }
  } catch {
    // ignore — fall through to extension-based detection
  }

  let category = 'Unknown';
  if (mime) {
    for (const [re, cat] of MIME_TO_CATEGORY) {
      if (re.test(mime)) {
        category = cat;
        break;
      }
    }
  }

  // Extension fallback (covers text formats like .js that have no magic bytes).
  if (category === 'Unknown') {
    const ext = originalName.split('.').pop()?.toLowerCase();
    if (ext && EXT_TO_CATEGORY[ext]) category = EXT_TO_CATEGORY[ext];
  }

  return {
    category, // one of PDF | Image | JS | Archive | Unknown
    mime: mime || 'application/octet-stream',
    detected_ext: detectedExt,
    size_bytes: buffer.length,
  };
}
