import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";

import { rpc } from "../api";
import { ColorPicker } from "./ColorPicker";
import { Button, FieldLabel, IconButton, Input, Kbd } from "./primitives";

/**
 * The project composer.
 *
 * Two fields, and the second one is the whole reason this is a dialog rather than a
 * one-line prompt: the **key** is not metadata, it is the name every issue in this
 * project will be called forever. `ENG-142` is what goes in a branch name, a commit
 * message, and a teammate's chat. Picking it deserves to be shown, not typed blind
 * into a box labelled "key".
 *
 * So the key derives from the name as you type — the overwhelmingly common case is
 * the first few letters — and stops the moment you touch it, because a derived value
 * that keeps overwriting your edit is worse than no derivation at all.
 *
 * The rules are mirrored from `replica.rs::project_new` for *feedback*, never for
 * enforcement: the daemon validates and its refusal is the answer. What this buys is
 * that you find out before you press the button rather than after.
 */

/** 1–8 ASCII letters. Anything else breaks `KEY-n` parsing and branch inference. */
const KEY_RE = /^[A-Za-z]{1,8}$/;

export function NewProject({
  spaceId,
  taken,
  onClose,
  onCreated,
}: {
  spaceId: string;
  /** Existing keys, uppercased — the daemon refuses a duplicate. */
  taken: string[];
  onClose: () => void;
  onCreated: (key: string) => void;
}) {
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [color, setColor] = useState("blue");
  /** Once you edit the key yourself, the name stops driving it. */
  const [manual, setManual] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const derived = manual ? key : deriveKey(name);
  const upper = derived.toUpperCase();

  const problem = projectKeyProblem(derived, taken);

  const ready = name.trim() !== "" && derived !== "" && !problem && !busy;

  const create = async () => {
    if (!ready) return;
    setBusy(true);
    setFailure("");
    try {
      const r = await rpc(spaceId, { cmd: "project_new", name: name.trim(), key: upper, color });
      // `project_new` replies with the key as the ref — switch the board to it, so
      // creating a project lands you in it rather than leaving you where you were.
      if (r.kind === "ref") onCreated(r.reff);
      onClose();
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
        <Dialog.Content
          className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-[18vh] left-1/2 z-50 w-[min(440px,92vw)] -translate-x-1/2 rounded-lg border"
          aria-describedby={undefined}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void create();
            }}
          >
            <header className="border-line flex items-center gap-2 border-b p-4">
              <Dialog.Title className="font-semibold">New project</Dialog.Title>
              <Dialog.Close asChild>
                <IconButton label="Close" chord="Esc" className="ml-auto">
                  <X className="size-4" />
                </IconButton>
              </Dialog.Close>
            </header>

            <div className="flex flex-col gap-3 p-4">
              <FieldLabel>
                <span>Name</span>
                <Input
                  autoFocus
                  value={name}
                  placeholder="Engineering"
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => e.stopPropagation()}
                />
              </FieldLabel>

              <FieldLabel>
                <span>Key</span>
                <Input
                  value={derived}
                  placeholder="ENG"
                  onChange={(e) => {
                    setManual(true);
                    setKey(e.target.value);
                  }}
                  onKeyDown={(e) => e.stopPropagation()}
                  className="font-mono uppercase"
                  aria-invalid={problem !== null}
                  aria-describedby="project-key-guidance"
                />
                <span id="project-key-guidance" className={`text-xs ${problem ? "text-danger" : "text-mute"}`}>
                  {problem ??
                    (upper
                      ? `Issues here will be ${upper}-1, ${upper}-2…`
                      : "Becomes the KEY in KEY-1 — 1–8 letters")}
                </span>
              </FieldLabel>

              <div className="flex flex-col gap-1.5">
                <span className="text-mute text-2xs uppercase">Color</span>
                <ColorPicker value={color} onChange={setColor} />
              </div>
              {failure && (
                <p className="border-danger/25 bg-danger/5 text-danger rounded border p-2 text-xs" role="alert">
                  Project not created. Your name and key are still here: {failure}
                </p>
              )}
            </div>

            <footer className="border-line flex items-center justify-end gap-2 border-t p-3">
              <Kbd>↵</Kbd>
              <Button size="md" variant="primary" type="submit" disabled={!ready} loading={busy}>
                {busy ? "Creating…" : "Create project"}
              </Button>
            </footer>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/**
 * A first guess at the key from the name.
 *
 * Initials for a multi-word name (`Design System` → `DS`), otherwise the first three
 * letters (`Engineering` → `ENG`). Non-letters are dropped rather than rejected,
 * because a name like "Web 2.0" should still suggest something rather than nothing.
 */
export function deriveKey(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "";
  if (words.length > 1) {
    return words
      .map((w) => w.replace(/[^A-Za-z]/g, "")[0] ?? "")
      .join("")
      .slice(0, 8)
      .toUpperCase();
  }
  return (words[0] ?? "").replace(/[^A-Za-z]/g, "").slice(0, 3).toUpperCase();
}

export function projectKeyProblem(key: string, taken: readonly string[]): string | null {
  if (!key) return null;
  const upper = key.toUpperCase();
  if (!KEY_RE.test(key)) return "1–8 letters, no digits or punctuation";
  if (taken.includes(upper)) return `${upper} is already a project here`;
  return null;
}
