import type { ReactElement } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/errors';
import { ErrorBanner } from './ErrorBanner';
import { resolveActionHref } from './ErrorAction';

const renderBanner = (ui: ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('ErrorBanner', () => {
  it('renders the catalog title, userMessage, code, request id and navigate action', () => {
    renderBanner(<ErrorBanner error={ApiError.fromCode('LSE-KEY-003', { requestId: 'req_42' })} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('API key not working')).toBeInTheDocument();
    expect(screen.getByText("Your API key isn't working.")).toBeInTheDocument();
    expect(screen.getByText(/LSE-KEY-003 · Reference req_42/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open API key settings' })).toHaveAttribute(
      'href',
      '/settings#api-keys',
    );
  });

  it('adds returnTo to API auth links (Reconnect GitHub)', () => {
    window.history.replaceState(null, '', '/orgs/org_1');
    renderBanner(<ErrorBanner error={ApiError.fromCode('LSE-GH-001')} />);
    expect(screen.getByRole('link', { name: 'Reconnect GitHub' })).toHaveAttribute(
      'href',
      '/api/v1/auth/github?link=1&returnTo=%2Forgs%2Forg_1',
    );
  });

  it('opens external links in a new tab', () => {
    renderBanner(<ErrorBanner error={ApiError.fromCode('LSE-KEY-006')} />);
    const link = screen.getByRole('link', { name: /check service status/i });
    expect(link).toHaveAttribute('href', 'https://status.anthropic.com');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('wires retry actions to onRetry', async () => {
    const onRetry = vi.fn();
    renderBanner(<ErrorBanner error={ApiError.fromCode('LSE-SYS-001')} onRetry={onRetry} />);
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('renders nothing without an error', () => {
    const { container } = renderBanner(<ErrorBanner error={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('resolveActionHref', () => {
  it('adds returnTo to /signin', () => {
    expect(
      resolveActionHref({ type: 'navigate', label: 'Sign in', href: '/signin' }, '/orgs'),
    ).toBe('/signin?returnTo=%2Forgs');
  });
  it('leaves other links alone', () => {
    expect(resolveActionHref({ type: 'navigate', label: 'x', href: '/orgs' }, '/a')).toBe('/orgs');
  });
});
