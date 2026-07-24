import { useEffect, useRef } from "react";

/** Restore the invoking control when a transient overlay unmounts. */
export function useReturnFocus(): void {
  const target = useRef(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );
  useEffect(() => () => target.current?.focus(), []);
}
