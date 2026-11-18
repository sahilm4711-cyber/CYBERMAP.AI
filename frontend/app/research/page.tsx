"use client";

import { useState } from "react";
import {
  addBookmark,
  addCollectionItem,
  ApiError,
  compareCves,
  createCollection,
  createNote,
  deleteAnalysis,
  deleteCollection,
  deleteNote,
  exportUrl,
  getCollectionStatus,
  listCollectionItems,
  removeBookmark,
  removeCollectionItem,
  updateNote,
  type CollectionItem,
  type CollectionStatus,
  type CompareRow,
  type ResearchCollection,
} from "@/lib/services/research";
import {
  useBookmarks,
  useCollections,
  useNotes,
  useSavedAnalyses,
} from "@/lib/hooks/useResearch";

const ITEM_TYPES = ["vulnerability", "cwe", "attack_technique"] as const;

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-red-900 bg-red-950/40 p-4 text-sm text-red-200">
      {message}
    </div>
  );
}

function LoadingBox({ label }: { label: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
      {label}…
    </div>
  );
}

export default function ResearchPage() {
  const collections = useCollections();
  const bookmarks = useBookmarks();
  const notes = useNotes();
  const analyses = useSavedAnalyses();

  const [openId, setOpenId] = useState<string | null>(null);
  const [items, setItems] = useState<CollectionItem[] | null>(null);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [status, setStatus] = useState<CollectionStatus | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [itemType, setItemType] = useState<string>("vulnerability");
  const [itemId, setItemId] = useState("");

  const [noteTitle, setNoteTitle] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const [noteTags, setNoteTags] = useState("");
  const [noteFilter, setNoteFilter] = useState("");
  const [editingNote, setEditingNote] = useState<string | null>(null);
  const [editingBody, setEditingBody] = useState("");

  const [compareInput, setCompareInput] = useState("");
  const [compareRows, setCompareRows] = useState<CompareRow[] | null>(null);
  const [compareError, setCompareError] = useState<string | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const [bookmarkType, setBookmarkType] = useState<string>("vulnerability");
  const [bookmarkId, setBookmarkId] = useState("");

  async function openCollection(c: ResearchCollection) {
    setOpenId(c.id);
    setItemsLoading(true);
    setItemsError(null);
    try {
      const [listed, st] = await Promise.all([
        listCollectionItems(c.id),
        getCollectionStatus(c.id),
      ]);
      setItems(listed.items);
      setStatus(st);
    } catch (err) {
      setItemsError(
        err instanceof ApiError ? err.message : "Could not load items.",
      );
      setItems(null);
    } finally {
      setItemsLoading(false);
    }
  }

  async function handleCreateCollection(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      await createCollection({ name: newName, description: newDesc || undefined });
      setNewName("");
      setNewDesc("");
      collections.refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Create failed.");
    }
  }

  async function handleAddItem(e: React.FormEvent) {
    e.preventDefault();
    if (!openId) return;
    setFormError(null);
    try {
      await addCollectionItem(openId, { item_type: itemType, item_id: itemId });
      setItemId("");
      const listed = await listCollectionItems(openId);
      setItems(listed.items);
      collections.refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Add item failed.");
    }
  }

  async function handleCreateNote(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      await createNote({
        title: noteTitle || undefined,
        body: noteBody,
        tags: noteTags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        collection_id: openId ?? undefined,
      });
      setNoteTitle("");
      setNoteBody("");
      setNoteTags("");
      notes.refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Create note failed.");
    }
  }

  async function handleCompare(e: React.FormEvent) {
    e.preventDefault();
    setCompareError(null);
    setCompareRows(null);
    const ids = compareInput
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (ids.length < 2 || ids.length > 5) {
      setCompareError("Enter 2 to 5 CVE IDs, separated by commas or spaces.");
      return;
    }
    setCompareLoading(true);
    try {
      const result = await compareCves(ids);
      setCompareRows(result.comparisons);
    } catch (err) {
      setCompareError(
        err instanceof ApiError ? err.message : "Comparison failed.",
      );
    } finally {
      setCompareLoading(false);
    }
  }

  const filteredNotes = (notes.notes ?? []).filter((n) =>
    noteFilter
      ? (n.tags ?? []).some((t) =>
          t.toLowerCase().includes(noteFilter.toLowerCase()),
        ) ||
        (n.title ?? "").toLowerCase().includes(noteFilter.toLowerCase())
      : true,
  );

  return (
    <div className="flex flex-col gap-8">
      <section>
        <h1 className="text-3xl font-bold tracking-tight">Research Workspace</h1>
        <p className="mt-2 max-w-2xl text-zinc-400">
          Your private collections, bookmarks, notes and saved analyses. Only
          you can see them — another user gets a 404, never your data.
        </p>
      </section>

      {collections.error && <ErrorBox message={collections.error} />}
      {formError && <ErrorBox message={formError} />}

      {/* Collections */}
      <section aria-label="Collections" className="flex flex-col gap-4">
        <h2 className="text-xl font-semibold">My collections</h2>
        <form onSubmit={handleCreateCollection} className="flex flex-wrap gap-2">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Collection name"
            required
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
          />
          <input
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Description (optional)"
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
          />
          <button
            type="submit"
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white"
          >
            Create collection
          </button>
        </form>
        {collections.loading ? (
          <LoadingBox label="Loading collections" />
        ) : (collections.collections ?? []).length === 0 ? (
          <p className="text-sm text-zinc-500">
            No collections yet. Create one above to start gathering CVEs, CWEs
            and techniques.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {(collections.collections ?? []).map((c) => (
              <li
                key={c.id}
                className="flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
              >
                <button
                  onClick={() => openCollection(c)}
                  className="text-left font-semibold text-cyan-300 underline-offset-2 hover:underline"
                >
                  {c.name}
                </button>
                <span className="text-sm text-zinc-400">
                  {c.item_count} item{c.item_count === 1 ? "" : "s"}
                </span>
                {c.description && (
                  <span className="text-sm text-zinc-500">{c.description}</span>
                )}
                <span className="ml-auto flex gap-2">
                  <a
                    href={exportUrl(c.id, "json")}
                    className="rounded-lg border border-zinc-700 px-3 py-1 text-xs"
                  >
                    Export JSON
                  </a>
                  <a
                    href={exportUrl(c.id, "csv")}
                    className="rounded-lg border border-zinc-700 px-3 py-1 text-xs"
                  >
                    Export CSV
                  </a>
                  <button
                    onClick={async () => {
                      await deleteCollection(c.id);
                      if (openId === c.id) {
                        setOpenId(null);
                        setItems(null);
                      }
                      collections.refresh();
                    }}
                    className="rounded-lg border border-red-900 px-3 py-1 text-xs text-red-300"
                  >
                    Delete
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}

        {openId && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="font-semibold">Collection items</h3>
            {status && (
              <p className="mt-1 text-sm text-zinc-400">
                Investigation status:{" "}
                <span className="text-zinc-100">{status.status}</span>
                <span className="text-zinc-500">
                  {" "}
                  (tracked by a note tagged “status” on this collection)
                </span>
              </p>
            )}
            {itemsLoading ? (
              <LoadingBox label="Loading items" />
            ) : itemsError ? (
              <ErrorBox message={itemsError} />
            ) : (items ?? []).length === 0 ? (
              <p className="mt-2 text-sm text-zinc-500">
                No items yet. Add one by its database UUID below.
              </p>
            ) : (
              <table className="mt-3 w-full text-sm">
                <thead>
                  <tr className="text-left text-zinc-400">
                    <th className="py-1">Label</th>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Added</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {items?.map((item) => (
                    <tr key={item.id} className="border-t border-zinc-800">
                      <td className="py-2 font-mono">{item.label}</td>
                      <td>{item.item_type}</td>
                      <td className="text-zinc-400">{item.name ?? "—"}</td>
                      <td className="text-zinc-500">
                        {item.added_at?.slice(0, 10) ?? "—"}
                      </td>
                      <td>
                        <button
                          onClick={async () => {
                            await removeCollectionItem(
                              openId,
                              item.item_id,
                              item.item_type,
                            );
                            const listed = await listCollectionItems(openId);
                            setItems(listed.items);
                            collections.refresh();
                          }}
                          className="text-xs text-red-300"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={handleAddItem} className="mt-4 flex flex-wrap gap-2">
              <select
                value={itemType}
                onChange={(e) => setItemType(e.target.value)}
                className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
              >
                {ITEM_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <input
                value={itemId}
                onChange={(e) => setItemId(e.target.value)}
                placeholder="Item UUID (from the explorer)"
                required
                className="min-w-72 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm"
              />
              <button
                type="submit"
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white"
              >
                Add item
              </button>
            </form>
          </div>
        )}
      </section>

      {/* Bookmarks */}
      <section aria-label="Bookmarks" className="flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Bookmarks</h2>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setFormError(null);
            try {
              await addBookmark({ item_type: bookmarkType, item_id: bookmarkId });
              setBookmarkId("");
              bookmarks.refresh();
            } catch (err) {
              setFormError(
                err instanceof ApiError ? err.message : "Bookmark failed.",
              );
            }
          }}
          className="flex flex-wrap gap-2"
        >
          <select
            value={bookmarkType}
            onChange={(e) => setBookmarkType(e.target.value)}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
          >
            {ITEM_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <input
            value={bookmarkId}
            onChange={(e) => setBookmarkId(e.target.value)}
            placeholder="Item UUID to bookmark"
            required
            className="min-w-72 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm"
          />
          <button
            type="submit"
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white"
          >
            Bookmark
          </button>
        </form>
        {bookmarks.loading ? (
          <LoadingBox label="Loading bookmarks" />
        ) : (bookmarks.bookmarks ?? []).length === 0 ? (
          <p className="text-sm text-zinc-500">No bookmarks yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {(bookmarks.bookmarks ?? []).map((b) => (
              <li
                key={b.id}
                className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 text-sm"
              >
                <span className="font-mono">{b.label}</span>
                <span className="text-zinc-400">{b.item_type}</span>
                <span className="text-zinc-500">{b.name ?? ""}</span>
                <button
                  onClick={async () => {
                    await removeBookmark(b.item_type, b.item_id);
                    bookmarks.refresh();
                  }}
                  className="ml-auto text-xs text-red-300"
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Notes */}
      <section aria-label="Notes" className="flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Notes</h2>
        <form onSubmit={handleCreateNote} className="flex flex-col gap-2">
          <input
            value={noteTitle}
            onChange={(e) => setNoteTitle(e.target.value)}
            placeholder="Title (optional)"
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
          />
          <textarea
            value={noteBody}
            onChange={(e) => setNoteBody(e.target.value)}
            placeholder="Write your findings…"
            required
            rows={3}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
          />
          <div className="flex flex-wrap gap-2">
            <input
              value={noteTags}
              onChange={(e) => setNoteTags(e.target.value)}
              placeholder="Tags, comma separated (use “status” + a status title to set investigation status)"
              className="min-w-72 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
            />
            <button
              type="submit"
              className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white"
            >
              Save note
            </button>
          </div>
        </form>
        <input
          value={noteFilter}
          onChange={(e) => setNoteFilter(e.target.value)}
          placeholder="Filter notes by tag or title"
          className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
        />
        {notes.loading ? (
          <LoadingBox label="Loading notes" />
        ) : notes.error ? (
          <ErrorBox message={notes.error} />
        ) : filteredNotes.length === 0 ? (
          <p className="text-sm text-zinc-500">No notes yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {filteredNotes.map((n) => (
              <li
                key={n.id}
                className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
              >
                <div className="flex items-center gap-3">
                  <span className="font-semibold">{n.title ?? "Untitled"}</span>
                  {(n.tags ?? []).map((t) => (
                    <span
                      key={t}
                      className="rounded-full border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400"
                    >
                      {t}
                    </span>
                  ))}
                  <span className="ml-auto flex gap-2 text-xs">
                    <button
                      onClick={() => {
                        setEditingNote(n.id);
                        setEditingBody(n.body);
                      }}
                      className="text-cyan-300"
                    >
                      Edit
                    </button>
                    <button
                      onClick={async () => {
                        await deleteNote(n.id);
                        notes.refresh();
                      }}
                      className="text-red-300"
                    >
                      Delete
                    </button>
                  </span>
                </div>
                {editingNote === n.id ? (
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      await updateNote(n.id, { body: editingBody });
                      setEditingNote(null);
                      notes.refresh();
                    }}
                    className="mt-2 flex flex-col gap-2"
                  >
                    <textarea
                      value={editingBody}
                      onChange={(e) => setEditingBody(e.target.value)}
                      rows={3}
                      className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm"
                    />
                    <button
                      type="submit"
                      className="self-start rounded-lg bg-cyan-600 px-3 py-1 text-sm text-white"
                    >
                      Save
                    </button>
                  </form>
                ) : (
                  <p className="mt-2 whitespace-pre-wrap text-sm text-zinc-300">
                    {n.body}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Saved analyses */}
      <section aria-label="Saved analyses" className="flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Saved analyses</h2>
        {analyses.loading ? (
          <LoadingBox label="Loading saved analyses" />
        ) : analyses.error ? (
          <ErrorBox message={analyses.error} />
        ) : (analyses.analyses ?? []).length === 0 ? (
          <p className="text-sm text-zinc-500">
            No saved analyses yet. Analyses you run from the AI assistant
            (Phase 6) appear here.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {(analyses.analyses ?? []).map((a) => (
              <li
                key={a.id}
                className="flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 text-sm"
              >
                <span className="font-mono">{a.cve_id ?? a.vulnerability_id}</span>
                <span className="text-zinc-400">{a.analysis_type}</span>
                <span className="text-zinc-500">
                  {a.ai_mode}
                  {a.model ? ` · ${a.model}` : ""}
                </span>
                <button
                  onClick={async () => {
                    await deleteAnalysis(a.id);
                    analyses.refresh();
                  }}
                  className="ml-auto text-xs text-red-300"
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Compare */}
      <section aria-label="Compare CVEs" className="flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Compare CVEs</h2>
        <form onSubmit={handleCompare} className="flex flex-wrap gap-2">
          <input
            value={compareInput}
            onChange={(e) => setCompareInput(e.target.value)}
            placeholder="CVE-2024-11111, CVE-2024-22222 (2–5 IDs)"
            className="min-w-72 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm"
          />
          <button
            type="submit"
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white"
          >
            Compare
          </button>
        </form>
        {compareError && <ErrorBox message={compareError} />}
        {compareLoading && <LoadingBox label="Comparing" />}
        {compareRows && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-zinc-400">
                  <th className="py-1 pr-3">Field</th>
                  {compareRows.map((r) => (
                    <th key={r.cve_id} className="py-1 pr-3 font-mono">
                      {r.cve_id}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(
                  [
                    ["CVSS score", (r: CompareRow) => String(r.cvss_score)],
                    ["Severity", (r: CompareRow) => r.severity],
                    ["CWEs", (r: CompareRow) => r.cwe_ids.join(", ") || "—"],
                    ["EPSS score", (r: CompareRow) => String(r.epss_score)],
                    ["EPSS percentile", (r: CompareRow) => String(r.epss_percentile)],
                    ["CISA KEV", (r: CompareRow) => (r.kev_listed ? "Yes" : "No")],
                    ["Published", (r: CompareRow) => r.published_at.slice(0, 10)],
                  ] as const
                ).map(([label, get]) => (
                  <tr key={label} className="border-t border-zinc-800">
                    <td className="py-2 pr-3 text-zinc-400">{label}</td>
                    {compareRows.map((r) => (
                      <td key={r.cve_id} className="py-2 pr-3">
                        {get(r)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-xs text-zinc-500">
              “unavailable” means the database has no value for that field —
              it is never invented.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
