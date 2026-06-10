/**
 * FileTool — renderer for the file tools `write_file`, `patch`, `read_file` and
 * `skill_manage` (Epic 2.3). Collapsed: the file path RELATIVE to the session
 * cwd, plus a themed `+N −M` change summary (rendered by the shell from
 * `stats`). Expanded: the FULL unified diff (gateway `diff_unified`, 512KB-
 * capped) through the NATIVE `<diff>` renderable — unified view (the transcript
 * is column-constrained), word-wrapped, line-numbered, themed. Multi-file diffs
 * are split per file (DiffRenderable parses only the FIRST file of a multi-file
 * diff) with a path label above each section. `read_file` (or any run without a
 * diff) falls back to the default labeled fields + output body.
 *
 * Arg keys verified against the Python tool schemas (tools/file_tools.py
 * READ_FILE_SCHEMA / WRITE_FILE_SCHEMA / PATCH_SCHEMA: `path`;
 * tools/skill_manager_tool.py skill_manage: `file_path`). patch-mode `patch`
 * calls have no path arg → gateway argsPreview fallback.
 *
 * Sizing: the `<diff>` gets NO height — like opencode's Edit() it sizes to its
 * content (the unified view is one auto-height code pane), so it never scrolls
 * internally against the transcript's outer <scrollbox>.
 */
import { pathToFiletype } from '@opentui/core'
import { createMemo, For, Show } from 'solid-js'

import { type DiffFileSection, relativizePath, splitUnifiedDiff } from '../../logic/diff.ts'
import type { ToolPartState } from '../../logic/store.ts'
import { syntaxStyleFor } from '../markdown.tsx'
import { useTheme } from '../theme.tsx'
import { DefaultToolBody, defaultRenderer, defaultSubtitle, structuredArgs, ToolOutputBlock } from './defaultTool.tsx'
import type { ToolBodyProps, ToolRenderer } from './registry.tsx'

/** The tool's target path: `path` (file tools) / `file_path` (skill_manage),
 *  via structuredArgs (prefers gateway-redacted argsText); else argsPreview. */
export function filePathOf(part: ToolPartState): string {
  const args = structuredArgs(part)
  const p = args?.['path'] ?? args?.['file_path']
  if (typeof p === 'string' && p.trim()) return p
  return part.argsPreview ?? ''
}

/** Non-diff result keys worth surfacing under a rendered diff (file_operations.py
 *  Write/PatchResult.to_dict + the file_tools.py `_warning` injection). */
const INTERESTING_KEYS = ['error', 'warning', '_warning', 'warnings', 'lsp_diagnostics'] as const

/** What to render below an ALREADY-RENDERED diff for the settled output. */
export type DiffOutputPlan =
  | { kind: 'suppress' } // JSON echo of the diff (or empty) — the diff tells the story
  | { kind: 'notes'; notes: Array<[string, string]> } // interesting non-diff keys only
  | { kind: 'output' } // plain text (lint tails, etc.) — full output block

/**
 * True when a NON-JSON-looking result is really an echo FRAGMENT of the
 * already-rendered diff. A gateway TAIL-cap (`_cap_tui_verbose_text`) on a
 * file-edit JSON result can cut off the `{"success"…` head entirely, and the
 * store's `normalizeOutput` then turns the surviving literal `\n` escapes into
 * real lines — so the fragment arrives looking like plain text whose lines ARE
 * lines of the diff. Suppress when most inner lines (first/last are typically
 * cut mid-line) appear verbatim in the rendered diff. Genuine plain-text
 * results (lint tails etc.) share no lines with the diff and still render.
 * (Current gateways strip the diff echo from result_text at the source —
 * server.py `_result_sans_diff_echo` — this guards older/other emitters.)
 */
function isDiffEchoFragment(r: string, diff: string): boolean {
  const lines = r
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
  if (lines.length < 3) return false
  const inner = lines.slice(1, -1)
  const hits = inner.filter(l => diff.includes(l)).length
  return hits >= Math.ceil(inner.length / 2)
}

/**
 * Decide the output section under a rendered diff. File-edit results are JSON
 * records whose payload IS the diff (`patch` returns `{success, diff, …}`) —
 * re-printing that below the native diff is noise. Worse, a verbose session's
 * `result_text` may arrive gateway-CAPPED mid-JSON (unparseable) — a
 * JSON-LOOKING blob under a rendered diff is never useful content, so anything
 * starting with `{` is suppressed regardless of parseability, and a non-JSON
 * fragment whose lines echo the diff (a tail-cap that lost the JSON head) is
 * suppressed too. The exception: parseable JSON carrying real non-diff signal
 * (error/warning strings, lsp_diagnostics) renders JUST those as labeled
 * lines. Plain-text results still render in full.
 */
export function diffOutputPlan(part: ToolPartState): DiffOutputPlan {
  const r = (part.resultText ?? '').trim()
  if (!r) return { kind: 'suppress' }
  if (!r.startsWith('{')) {
    if (part.diffUnified && isDiffEchoFragment(r, part.diffUnified)) return { kind: 'suppress' }
    return { kind: 'output' }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(r)
  } catch {
    return { kind: 'suppress' } // capped/garbled JSON — the diff already tells the story
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { kind: 'suppress' }
  const o = parsed as Record<string, unknown>
  const notes: Array<[string, string]> = []
  for (const key of INTERESTING_KEYS) {
    const v = o[key]
    if (typeof v === 'string' && v.trim()) notes.push([key, v.trim()])
    else if (Array.isArray(v)) {
      const items = v.filter((x): x is string => typeof x === 'string' && Boolean(x.trim()))
      if (items.length > 0) notes.push([key, items.join('\n')])
    }
  }
  return notes.length > 0 ? { kind: 'notes', notes } : { kind: 'suppress' }
}

/** The notes of a plan, as a `<Show when>`-friendly truthy value (else undefined). */
function notesOf(plan: DiffOutputPlan): Array<[string, string]> | undefined {
  return plan.kind === 'notes' ? plan.notes : undefined
}

/** One file's diff: an optional path label (chrome) + the native `<diff>`. */
function FileDiff(props: { file: DiffFileSection; label: boolean; cwd?: string | undefined }) {
  const theme = useTheme()
  return (
    <box style={{ flexDirection: 'column', flexShrink: 0, minWidth: 0 }}>
      <Show when={props.label && props.file.path}>
        {/* per-file section label (multi-file diffs) — chrome, not content */}
        <text selectable={false}>
          <span style={{ fg: theme().color.label }}>{relativizePath(props.file.path, props.cwd)}</span>
        </text>
      </Show>
      <diff
        diff={props.file.diff}
        view="unified"
        wrapMode="word"
        showLineNumbers
        width="100%"
        filetype={pathToFiletype(props.file.path)}
        syntaxStyle={syntaxStyleFor(theme())}
        fg={theme().color.text}
        addedBg={theme().color.diffAddedBg}
        removedBg={theme().color.diffRemovedBg}
        addedSignColor={theme().color.ok}
        removedSignColor={theme().color.error}
        lineNumberFg={theme().color.muted}
        selectionBg={theme().color.selectionBg}
      />
    </box>
  )
}

/** Labeled non-diff notes (warnings/errors) surfaced from a JSON result. */
function DiffNotes(props: { notes: Array<[string, string]> }) {
  const theme = useTheme()
  return (
    <For each={props.notes}>
      {([key, value]) => (
        <>
          {/* section label — chrome, not content */}
          <text selectable={false}>
            <span style={{ fg: key === 'error' ? theme().color.error : theme().color.label }}>{key}</span>
          </text>
          <For each={value.split('\n')}>
            {line => (
              <text selectionBg={theme().color.selectionBg}>
                <span style={{ fg: theme().color.muted }}>{line}</span>
              </text>
            )}
          </For>
        </>
      )}
    </For>
  )
}

/** Expanded body: per-file native diffs (+ non-redundant output), else default. */
export function FileToolBody(props: ToolBodyProps) {
  const files = createMemo(() => (props.part.diffUnified ? splitUnifiedDiff(props.part.diffUnified) : []))
  const plan = createMemo(() => diffOutputPlan(props.part))
  return (
    <Show when={files().length > 0} fallback={<DefaultToolBody part={props.part} width={props.width} />}>
      <box style={{ flexDirection: 'column', flexGrow: 1, minWidth: 0 }}>
        <For each={files()}>{file => <FileDiff file={file} label={files().length > 1} cwd={props.cwd} />}</For>
        <Show when={notesOf(plan())}>{notes => <DiffNotes notes={notes()} />}</Show>
        <Show when={plan().kind === 'output'}>
          <ToolOutputBlock part={props.part} width={props.width} label />
        </Show>
      </box>
    </Show>
  )
}

export const fileRenderer: ToolRenderer = {
  Body: FileToolBody,
  // A diff is always hidden content worth expanding; otherwise same as default.
  expandable: part => Boolean(part.diffUnified) || defaultRenderer.expandable(part),
  // `+N −M` (store-computed from diffUnified) — themed by the shell.
  stats: part => part.diffStats,
  // The target path, relative to the session cwd.
  subtitle: (part, cwd) => relativizePath(filePathOf(part), cwd) || defaultSubtitle(part)
}
