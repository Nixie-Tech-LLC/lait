import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it } from "vitest";

import { useReturnFocus } from "./useReturnFocus";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("overlay focus restoration", () => {
  it("returns focus to the invoking control on unmount", () => {
    const opener = document.createElement("button");
    document.body.append(opener);
    opener.focus();
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);
    act(() => root.render(<Overlay />));
    (host.querySelector("button") as HTMLButtonElement).focus();

    act(() => root.unmount());

    expect(document.activeElement).toBe(opener);
    host.remove();
    opener.remove();
  });
});

function Overlay() {
  useReturnFocus();
  return <button>Inside overlay</button>;
}
