import { useMemo } from 'react';
import { qrMatrix, qrPath } from '@/lib/qr';
import { cn } from '@/lib/utils';

const QUIET_ZONE = 4;

/**
 * Locally rendered QR code. Dark modules are drawn black on a white square regardless of
 * theme so scanners always get a high-contrast code. `label` is the accessible name — pair
 * it with the text secret so the code is never the only way to enrol (WCAG 1.1.1).
 */
export function QrCode({
  value,
  label,
  className,
}: {
  value: string;
  label: string;
  className?: string;
}) {
  const { size, d } = useMemo(() => {
    const m = qrMatrix(value);
    return { size: m.size, d: qrPath(m) };
  }, [value]);
  const total = size + QUIET_ZONE * 2;
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${total} ${total}`}
      className={cn('size-44 rounded-md border bg-white', className)}
      shapeRendering="crispEdges"
    >
      <rect width={total} height={total} fill="#fff" />
      <path d={d} transform={`translate(${QUIET_ZONE} ${QUIET_ZONE})`} fill="#000" />
    </svg>
  );
}
