// Minimal inline stroke-icon set (no icon dependency). Each takes {size}.
const base = (size = 18) => ({
  width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
  stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round',
});

export const IconShield = ({ size }) => (
  <svg {...base(size)}><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /></svg>
);
export const IconGrid = ({ size }) => (
  <svg {...base(size)}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></svg>
);
export const IconUpload = ({ size }) => (
  <svg {...base(size)}><path d="M12 16V4" /><path d="M7 9l5-5 5 5" /><path d="M5 20h14" /></svg>
);
export const IconScan = ({ size }) => (
  <svg {...base(size)}><path d="M4 8V5a1 1 0 011-1h3" /><path d="M20 8V5a1 1 0 00-1-1h-3" /><path d="M4 16v3a1 1 0 001 1h3" /><path d="M20 16v3a1 1 0 01-1 1h-3" /><path d="M4 12h16" /></svg>
);
export const IconGraph = ({ size }) => (
  <svg {...base(size)}><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="7" r="2.5" /><circle cx="9" cy="18" r="2.5" /><path d="M8 7.5l8 0M7.5 8l1.5 8M11 17l6-8" /></svg>
);
export const IconServer = ({ size }) => (
  <svg {...base(size)}><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></svg>
);
export const IconRefresh = ({ size }) => (
  <svg {...base(size)}><path d="M21 12a9 9 0 11-2.6-6.4" /><path d="M21 4v5h-5" /></svg>
);
export const IconAlert = ({ size }) => (
  <svg {...base(size)}><path d="M12 3l9 16H3l9-16z" /><path d="M12 10v4M12 17h.01" /></svg>
);
export const IconBrain = ({ size }) => (
  <svg {...base(size)}><path d="M9 4a3 3 0 00-3 3 3 3 0 00-1 5 3 3 0 002 5 3 3 0 003 1V4z" /><path d="M15 4a3 3 0 013 3 3 3 0 011 5 3 3 0 01-2 5 3 3 0 01-3 1V4z" /></svg>
);
export const IconEye = ({ size }) => (
  <svg {...base(size)}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="2.6" /></svg>
);
export const IconCrosshair = ({ size }) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="8" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></svg>
);
export const IconChip = ({ size }) => (
  <svg {...base(size)}><rect x="7" y="7" width="10" height="10" rx="1.5" /><path d="M10 2v3M14 2v3M10 19v3M14 19v3M2 10h3M2 14h3M19 10h3M19 14h3" /></svg>
);
export const IconCheck = ({ size }) => (
  <svg {...base(size)}><path d="M20 6L9 17l-5-5" /></svg>
);
export const IconCopy = ({ size }) => (
  <svg {...base(size)}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 012-2h10" /></svg>
);
export const IconClock = ({ size }) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
);
