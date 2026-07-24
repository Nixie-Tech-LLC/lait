const PREFIX = "lait.board-scroll.";

export function loadBoardScroll(projectId: string): number {
  try {
    const value = Number(localStorage.getItem(`${PREFIX}${projectId}`));
    return Number.isFinite(value) && value > 0 ? value : 0;
  } catch {
    return 0;
  }
}

export function saveBoardScroll(projectId: string, left: number): void {
  try {
    localStorage.setItem(`${PREFIX}${projectId}`, String(Math.max(0, Math.round(left))));
  } catch {
    // Durable window state is a convenience, never a board dependency.
  }
}
