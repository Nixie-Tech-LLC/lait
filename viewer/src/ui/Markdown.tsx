import { useMemo } from "react";

import {
  looksLikeMarkdown,
  parseMarkdown,
  type Block,
  type Inline,
} from "../core/markdown";

/**
 * Issue prose, rendered.
 *
 * The parse lives in `core/markdown.ts` (typed AST, unit-tested); this file only
 * turns that AST into elements. No string ever reaches `innerHTML`, so the
 * safety property is structural, not an escaping discipline.
 *
 * Plain text short-circuits: a description with no Markdown in it renders as the
 * same `pre-wrap` paragraph it always was, byte for byte. The formatting layer
 * must be invisible until asked for.
 */
export function Markdown({ text, className }: { text: string; className?: string }) {
  const blocks = useMemo(
    () => (looksLikeMarkdown(text) ? parseMarkdown(text) : null),
    [text],
  );

  if (!blocks) {
    return <p className={`whitespace-pre-wrap ${className ?? ""}`}>{text}</p>;
  }
  return (
    <div className={`flex flex-col gap-2 ${className ?? ""}`}>
      {blocks.map((b, i) => (
        <BlockView key={i} block={b} />
      ))}
    </div>
  );
}

/** Heading sizes stay close to body size: this is a side pane, not a document. */
const HEADING_CLS: Record<number, string> = {
  1: "text-lg font-semibold",
  2: "text-base font-semibold",
  3: "text-sm font-semibold",
  4: "text-sm font-semibold text-dim",
};

function BlockView({ block }: { block: Block }) {
  switch (block.kind) {
    case "heading": {
      const Tag = `h${block.level}` as "h1";
      return <Tag className={HEADING_CLS[block.level]}>{inlines(block.children)}</Tag>;
    }
    case "paragraph":
      return <p className="whitespace-pre-wrap">{inlines(block.children)}</p>;
    case "quote":
      return (
        <blockquote className="border-line-strong text-dim border-l-2 pl-3 whitespace-pre-wrap">
          {inlines(block.children)}
        </blockquote>
      );
    case "code":
      return (
        <pre className="bg-bg border-line overflow-x-auto rounded border p-2 font-mono text-xs">
          <code>{block.text}</code>
        </pre>
      );
    case "hr":
      return <hr className="border-line" />;
    case "list": {
      const Tag = block.ordered ? "ol" : "ul";
      return (
        <Tag className={block.ordered ? "list-decimal pl-5" : "list-disc pl-5"}>
          {block.items.map((item, i) => (
            <li key={i} className={item.checked !== null ? "list-none -ml-5" : ""}>
              {item.checked !== null && (
                <input
                  type="checkbox"
                  checked={item.checked}
                  // Read-only on purpose: the checkbox is prose, not state — there
                  // is no per-character write path back into the CRDT from here.
                  readOnly
                  tabIndex={-1}
                  className="mr-1.5 align-middle"
                  aria-label={item.checked ? "Done" : "Not done"}
                />
              )}
              <span className={item.checked === true ? "text-mute line-through" : ""}>
                {inlines(item.children)}
              </span>
            </li>
          ))}
        </Tag>
      );
    }
  }
}

function inlines(parts: Inline[]): React.ReactNode {
  return parts.map((p, i) => <InlineView key={i} inline={p} />);
}

function InlineView({ inline }: { inline: Inline }) {
  switch (inline.kind) {
    case "text":
      return inline.text;
    case "code":
      return (
        <code className="bg-bg border-line rounded border px-1 font-mono text-[0.85em]">
          {inline.text}
        </code>
      );
    case "strong":
      return <strong className="font-semibold">{inlines(inline.children)}</strong>;
    case "em":
      return <em>{inlines(inline.children)}</em>;
    case "strike":
      return <s className="text-mute">{inlines(inline.children)}</s>;
    case "link":
      // The parser admits only http(s) hrefs; `noreferrer` because an issue
      // tracker's prose links to the whole internet.
      return (
        <a
          href={inline.href}
          target="_blank"
          rel="noreferrer noopener"
          className="text-accent hover:underline"
        >
          {inlines(inline.children)}
        </a>
      );
  }
}
