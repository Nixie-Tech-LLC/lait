import { useEffect, useState } from "react";
import * as AlertDialog from "@radix-ui/react-alert-dialog";
import * as Dialog from "@radix-ui/react-dialog";

import { Button } from "./primitives";

/**
 * Ask the user something, using our components.
 *
 * These replace `window.prompt` / `window.confirm`, which were never ours: they
 * ignore the theme, can't be styled, and are blocked outright wherever the page is
 * embedded or sandboxed — which is exactly where this app first got asked to run.
 * "It works in my tab" is not a design system.
 *
 * The API stays imperative and promise-based on purpose. `await ask.prompt(…)`
 * reads the same as the `window.prompt` it replaces, so the call sites stayed
 * simple and nothing had to be restructured into dialog state to gain a dialog.
 *
 * Radix does the parts that are tedious and invisible until they're wrong: focus
 * trap, restore-focus-on-close, Escape, `aria-modal`, and scroll locking.
 * `AlertDialog` for confirmations rather than `Dialog`, because it is the
 * semantically different one — it interrupts, it demands a choice, and it does not
 * close on an outside click, which is precisely what you want between someone and
 * a destructive verb.
 */

interface PromptReq {
  kind: "prompt";
  title: string;
  body?: string;
  label?: string;
  placeholder?: string;
  defaultValue?: string;
  confirmText?: string;
  /** An empty answer is a legitimate one (clearing a petname), so `""` !== null. */
  allowEmpty?: boolean;
  resolve: (v: string | null) => void;
}

interface ConfirmReq {
  kind: "confirm";
  title: string;
  body?: string;
  confirmText?: string;
  danger?: boolean;
  resolve: (v: boolean) => void;
}

type Req = PromptReq | ConfirmReq;

let emit: ((r: Req) => void) | null = null;

/** Text input. Resolves `null` on cancel — cancel and "" are different answers. */
export function prompt(o: Omit<PromptReq, "kind" | "resolve">): Promise<string | null> {
  return new Promise((resolve) => {
    // No host mounted means nobody can answer; resolving null is the honest
    // outcome, and it fails closed — a write simply doesn't happen.
    if (!emit) return resolve(null);
    emit({ kind: "prompt", ...o, resolve });
  });
}

/** Yes/no. Resolves `false` if there's nobody to ask. */
export function confirm(o: Omit<ConfirmReq, "kind" | "resolve">): Promise<boolean> {
  return new Promise((resolve) => {
    if (!emit) return resolve(false);
    emit({ kind: "confirm", ...o, resolve });
  });
}

/** Mount once, near the root. */
export function DialogHost() {
  const [req, setReq] = useState<Req | null>(null);
  const [value, setValue] = useState("");

  useEffect(() => {
    emit = (r) => {
      setReq(r);
      setValue(r.kind === "prompt" ? (r.defaultValue ?? "") : "");
    };
    return () => {
      emit = null;
    };
  }, []);

  if (!req) return null;

  /** Every path out answers the promise — a dialog that resolves nothing hangs
   *  whatever awaited it, forever. */
  const settle = (v: string | null | boolean) => {
    if (req.kind === "prompt") req.resolve(v as string | null);
    else req.resolve(v as boolean);
    setReq(null);
  };

  if (req.kind === "confirm") {
    return (
      <AlertDialog.Root open onOpenChange={(o) => !o && settle(false)}>
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
          <AlertDialog.Content className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-1/2 left-1/2 z-50 w-[min(440px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border p-4">
            <AlertDialog.Title className="text-lg font-semibold">{req.title}</AlertDialog.Title>
            {req.body && (
              <AlertDialog.Description className="text-dim mt-2">{req.body}</AlertDialog.Description>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <AlertDialog.Cancel asChild>
                <Button size="md" variant="outline">
                  Cancel
                </Button>
              </AlertDialog.Cancel>
              <AlertDialog.Action asChild>
                <Button
                  size="md"
                  variant={req.danger ? "destructive" : "primary"}
                  onClick={() => settle(true)}
                >
                  {req.confirmText ?? "Confirm"}
                </Button>
              </AlertDialog.Action>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    );
  }

  const empty = value.trim() === "" && !req.allowEmpty;

  return (
    <Dialog.Root open onOpenChange={(o) => !o && settle(null)}>
      <Dialog.Portal>
        <Dialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
        <Dialog.Content className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-[18vh] left-1/2 z-50 w-[min(480px,92vw)] -translate-x-1/2 rounded-lg border">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!empty) settle(req.allowEmpty ? value : value.trim());
            }}
          >
            <div className="border-line border-b p-4">
              <Dialog.Title className="font-semibold">{req.title}</Dialog.Title>
              {req.body && (
                <Dialog.Description className="text-dim mt-1 text-sm">{req.body}</Dialog.Description>
              )}
            </div>
            <div className="p-4">
              {req.label && <label className="text-mute mb-1 block text-2xs uppercase">{req.label}</label>}
              <input
                autoFocus
                value={value}
                placeholder={req.placeholder}
                onChange={(e) => setValue(e.target.value)}
                // Radix closes on Escape; stopping propagation keeps the app's
                // global keymap from also acting on the same keystroke.
                onKeyDown={(e) => e.stopPropagation()}
                className="border-line focus:border-line-strong placeholder:text-mute w-full rounded border bg-transparent px-2 py-1.5 text-base outline-none"
              />
            </div>
            <div className="border-line flex justify-end gap-2 border-t p-3">
              <Dialog.Close asChild>
                <Button size="md" variant="outline" type="button">
                  Cancel
                </Button>
              </Dialog.Close>
              <Button size="md" variant="primary" type="submit" disabled={empty}>
                {req.confirmText ?? "Save"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
