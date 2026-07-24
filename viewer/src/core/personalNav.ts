const FAVORITES = "lait.favorite-projects";
const RECENTS = "lait.issue-recents";
const SEARCHES = "lait.recent-searches";

export function loadFavoriteProjects(spaceId: string): string[] {
  return read(FAVORITES)[spaceId] ?? [];
}

export function toggleFavoriteProject(spaceId: string, project: string): string[] {
  const all = read(FAVORITES);
  const current = all[spaceId] ?? [];
  const next = current.includes(project)
    ? current.filter((key) => key !== project)
    : [...current, project];
  all[spaceId] = next;
  write(FAVORITES, all);
  return next;
}

export function rememberRecentIssue(spaceId: string, reff: string): void {
  const all = read(RECENTS);
  all[spaceId] = [reff, ...(all[spaceId] ?? []).filter((item) => item !== reff)].slice(0, 8);
  write(RECENTS, all);
}

export function loadRecentIssues(spaceId: string): string[] {
  return read(RECENTS)[spaceId] ?? [];
}

export function rememberRecentSearch(spaceId: string, query: string): void {
  const normalized = query.trim().replace(/\s+/g, " ");
  if (!normalized) return;
  const all = read(SEARCHES);
  all[spaceId] = [
    normalized,
    ...(all[spaceId] ?? []).filter((item) => item.toLowerCase() !== normalized.toLowerCase()),
  ].slice(0, 6);
  write(SEARCHES, all);
}

export function loadRecentSearches(spaceId: string): string[] {
  return read(SEARCHES)[spaceId] ?? [];
}

function read(key: string): Record<string, string[]> {
  try {
    return JSON.parse(localStorage.getItem(key) ?? "{}") as Record<string, string[]>;
  } catch {
    return {};
  }
}

function write(key: string, value: Record<string, string[]>): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Personal navigation is a local convenience, never a requirement.
  }
}
