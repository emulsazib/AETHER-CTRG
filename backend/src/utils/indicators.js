// Indicator helpers shared across the analysis service and graph stores.

// Refang a defanged indicator (45[.]137[.]21[.]9, hxxp://) into a usable value,
// so worker IoCs (defanged) align with OSINT reputation keys + seeded graph nodes.
export function refang(value = '') {
  return String(value)
    .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\[:\]/g, ':')
    .replace(/hxxps/g, 'https').replace(/hxxp/g, 'http')
    .replace(/^\[|\]$/g, '');
}

const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

// True when the (already-refanged) value looks like a bare IPv4 address.
export function isIpv4(value = '') {
  return IPV4.test(String(value));
}
