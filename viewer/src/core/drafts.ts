const PREFIX = "lait.draft";

export type DraftKind = "new-title" | "new-body" | "title" | "description" | "comment";

export function loadDraft(spaceId: string, subject: string, kind: DraftKind): string {
  try {
    return localStorage.getItem(key(spaceId, subject, kind)) ?? "";
  } catch {
    return "";
  }
}

export function saveDraft(spaceId: string, subject: string, kind: DraftKind, value: string): void {
  try {
    const k = key(spaceId, subject, kind);
    if (value) localStorage.setItem(k, value);
    else localStorage.removeItem(k);
  } catch {
    // Draft persistence is private convenience; editing must still work when
    // storage is unavailable or disabled.
  }
}

export function clearDraft(spaceId: string, subject: string, kind: DraftKind): void {
  saveDraft(spaceId, subject, kind, "");
}

function key(spaceId: string, subject: string, kind: DraftKind): string {
  return `${PREFIX}:${encodeURIComponent(spaceId)}:${encodeURIComponent(subject)}:${kind}`;
}
