import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";

import { ColorPicker } from "./ColorPicker";
import { Button } from "./primitives";

/**
 * The colour step for a label the picker is about to mint.
 *
 * A label typed into the picker used to be born gray with no say in the matter —
 * the engine has always taken a colour (`label_new {name, color}`), the viewer just
 * never asked. This is the ask: a small modal, because the picker that summoned it
 * has already closed, so there is nothing left to anchor a popover to. It only
 * chooses the colour; the caller owns the two requests that follow (register the
 * label, then attach it), because only the caller knows the issue it attaches to.
 */
export function NewLabelDialog({
  name,
  onCancel,
  onCreate,
}: {
  name: string;
  onCancel: () => void;
  onCreate: (name: string, color: string) => void;
}) {
  const [color, setColor] = useState("blue");
  return (
    <Dialog.Root open onOpenChange={(o) => !o && onCancel()}>
      <Dialog.Portal>
        <Dialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
        <Dialog.Content
          className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-1/2 left-1/2 z-50 w-[min(360px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border p-4"
          aria-describedby={undefined}
        >
          <Dialog.Title className="font-semibold">New label</Dialog.Title>
          <p className="text-dim mt-1 text-sm">
            Pick a colour for <span className="text-fg font-medium">{name}</span>.
          </p>
          <div className="mt-3">
            <ColorPicker value={color} onChange={setColor} />
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button size="md" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
            <Button size="md" variant="primary" onClick={() => onCreate(name, color)}>
              Create label
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
