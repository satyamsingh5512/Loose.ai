/**
 * Attachments & element inspection (spec §8.12; Phase 8).
 *
 * `POST /sessions/:id/attachments` stores an image or PDF as an Artifact of kind
 * `attachment` (raw body, ≤ 10 MB, allow-listed content types → LSE-AGT-009). Chat
 * messages reference those artifact ids; the orchestrator loads them and hands the bytes
 * to the runner (images inline, PDFs as document blocks).
 *
 * Click-to-select produces an `element` attachment: a Simple-safe label plus (Pro only)
 * the CSS selector and a cropped screenshot artifact.
 */
import {
  attachmentDtoSchema,
  ATTACHMENT_MIME_TYPES,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_PER_MESSAGE,
  type AttachmentDto,
  type AttachmentMimeType,
  type ChatAttachment,
  type RunnerAttachment,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import {
  assertCanAct,
  assertTokenScope,
  loadSessionForParticipant,
  saveArtifact,
  type Caller,
} from './sessionLifecycle.service';

function isAttachmentMime(v: string): v is AttachmentMimeType {
  return (ATTACHMENT_MIME_TYPES as readonly string[]).includes(v);
}

/** `image/png; charset=x` → `image/png`. */
export function normalizeMimeType(raw: string | undefined): string {
  return (raw ?? '').split(';')[0]!.trim().toLowerCase();
}

export interface UploadAttachmentInput {
  name: string;
  contentType: string | undefined;
  data: Buffer;
}

export async function uploadAttachment(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  input: UploadAttachmentInput,
): Promise<AttachmentDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  const { session } = access;
  assertCanAct(access, 'add attachments');
  const mimeType = normalizeMimeType(input.contentType);
  if (!isAttachmentMime(mimeType)) {
    throw new AppError('LSE-AGT-009', {
      devMessage: `Unsupported attachment type ${mimeType || 'unknown'}`,
      fields: { contentType: [`Use one of: ${ATTACHMENT_MIME_TYPES.join(', ')}`] },
    });
  }
  if (!input.data.length || input.data.length > MAX_ATTACHMENT_BYTES) {
    throw new AppError('LSE-AGT-009', {
      devMessage: `Attachment is ${input.data.length} bytes (max ${MAX_ATTACHMENT_BYTES})`,
      fields: { file: [`Attachments may be at most ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB`] },
    });
  }
  const name = input.name.slice(0, 255);
  const artifact = await saveArtifact(ctx, {
    sessionId: session.id,
    kind: 'attachment',
    data: input.data,
    contentType: mimeType,
    meta: { name, mimeType, uploadedBy: caller.user.id },
  });
  return attachmentDtoSchema.parse({
    id: artifact.id,
    kind: 'attachment',
    name,
    mimeType,
    size: input.data.length,
    url: artifact.url,
  });
}

async function readArtifact(ctx: AppContext, storageKey: string): Promise<Buffer | null> {
  const obj = await ctx.storage.get(storageKey).catch(() => null);
  if (!obj) return null;
  const chunks: Buffer[] = [];
  for await (const chunk of obj.stream) chunks.push(Buffer.from(chunk as Buffer));
  return Buffer.concat(chunks);
}

/**
 * Turn the attachments of a chat message into runner attachments: uploaded artifacts are
 * read back from object storage and inlined as base64; `element` selections are passed
 * through as context for the prompt.
 */
export async function loadRunnerAttachments(
  ctx: AppContext,
  sessionId: string,
  attachments: readonly ChatAttachment[],
): Promise<RunnerAttachment[]> {
  const out: RunnerAttachment[] = [];
  for (const a of attachments.slice(0, MAX_ATTACHMENTS_PER_MESSAGE)) {
    if (a.kind === 'element') {
      out.push({
        kind: 'element',
        name: a.name,
        ...(a.label ? { label: a.label } : {}),
        ...(a.selector ? { selector: a.selector } : {}),
      });
      continue;
    }
    if (!a.id) continue;
    const row = await ctx.prisma.artifact.findFirst({
      where: { id: a.id, sessionId },
      select: { storageKey: true, contentType: true },
    });
    if (!row?.storageKey) {
      ctx.logger.warn({ sessionId, artifactId: a.id }, 'attachment artifact is missing');
      continue;
    }
    const data = await readArtifact(ctx, row.storageKey);
    if (!data) continue;
    const mimeType = normalizeMimeType(a.mimeType ?? row.contentType);
    out.push({
      kind: mimeType === 'application/pdf' ? 'document' : 'image',
      name: a.name,
      mimeType,
      dataBase64: data.toString('base64'),
    });
  }
  return out;
}

/**
 * Extra prompt context for a selected preview element (spec §8.12): the agent needs to
 * know *what* the user clicked; Simple users never see the selector themselves.
 */
export function elementPromptContext(attachments: readonly ChatAttachment[]): string {
  const elements = attachments.filter((a) => a.kind === 'element');
  if (!elements.length) return '';
  const lines = elements.map((e) => {
    const parts = [`- ${e.label ?? e.name}`];
    if (e.selector) parts.push(`CSS selector: ${e.selector}`);
    if (e.rect)
      parts.push(
        `position: ${Math.round(e.rect.x)},${Math.round(e.rect.y)} ` +
          `size: ${Math.round(e.rect.width)}×${Math.round(e.rect.height)}`,
      );
    return parts.join(' — ');
  });
  return [
    '<selected_elements>',
    'The user pointed at these parts of the preview:',
    ...lines,
    '</selected_elements>',
  ].join('\n');
}
