export type ResourceKey = string;
export type ResourceState = "cold" | "partial" | "ready" | "refreshing" | "error";

export interface ResourceSnapshot<T> {
  readonly key: ResourceKey;
  readonly state: ResourceState;
  readonly data: T | undefined;
  readonly error: unknown | null;
  readonly stale: boolean;
}

type Listener = () => void;

interface Entry<T> {
  snapshot: ResourceSnapshot<T>;
  sequence: number;
  promise: Promise<T> | null;
  listeners: Set<Listener>;
  touched: number;
}

const coldSnapshots = new Map<ResourceKey, ResourceSnapshot<never>>();

function cold(key: ResourceKey): ResourceSnapshot<never> {
  let snapshot = coldSnapshots.get(key);
  if (!snapshot) {
    snapshot = Object.freeze({ key, state: "cold", data: undefined, error: null, stale: true });
    coldSnapshots.set(key, snapshot);
  }
  return snapshot;
}

/**
 * A small, framework-independent projection cache. It deliberately knows
 * nothing about issues or RPCs: callers supply keys, loaders and invalidation
 * scopes; React only observes its stable immutable snapshots.
 */
export class WorldViewStore {
  private entries = new Map<ResourceKey, Entry<unknown>>();
  private clock = 0;

  read<T>(key: ResourceKey): ResourceSnapshot<T> {
    const entry = this.entries.get(key);
    if (!entry) return cold(key) as ResourceSnapshot<T>;
    entry.touched = ++this.clock;
    return entry.snapshot as ResourceSnapshot<T>;
  }

  subscribe(key: ResourceKey, listener: Listener): () => void {
    const entry = this.entry(key);
    entry.listeners.add(listener);
    return () => entry.listeners.delete(listener);
  }

  set<T>(key: ResourceKey, data: T, complete = true): ResourceSnapshot<T> {
    const entry = this.entry<T>(key);
    entry.sequence++;
    entry.promise = null;
    this.publish(entry, {
      key,
      state: complete ? "ready" : "partial",
      data,
      error: null,
      stale: !complete,
    });
    return entry.snapshot;
  }

  notify(key: ResourceKey): void {
    const entry = this.entries.get(key);
    if (entry) this.publish(entry, { ...entry.snapshot });
  }

  ensure<T>(
    key: ResourceKey,
    loader: () => Promise<T>,
    options: { force?: boolean } = {},
  ): Promise<T> {
    const entry = this.entry<T>(key);
    if (entry.promise && !options.force) return entry.promise;
    if (!options.force && !entry.snapshot.stale && entry.snapshot.data !== undefined) {
      return Promise.resolve(entry.snapshot.data);
    }

    const sequence = ++entry.sequence;
    const previous = entry.snapshot.data;
    if (previous !== undefined) {
      this.publish(entry, { ...entry.snapshot, state: "refreshing", error: null });
    }

    let promise: Promise<T>;
    try {
      promise = loader();
    } catch (error) {
      promise = Promise.reject(error);
    }
    entry.promise = promise;
    void promise.then(
      (data) => {
        if (entry.sequence !== sequence) return;
        entry.promise = null;
        this.publish(entry, { key, state: "ready", data, error: null, stale: false });
      },
      (error) => {
        if (entry.sequence !== sequence) return;
        entry.promise = null;
        this.publish(entry, {
          key,
          state: "error",
          data: previous,
          error,
          stale: true,
        });
      },
    );
    return promise;
  }

  invalidate(scope: ResourceKey | ((key: ResourceKey) => boolean)): ResourceKey[] {
    const matches = typeof scope === "string" ? (key: string) => key === scope : scope;
    const invalidated: ResourceKey[] = [];
    for (const [key, raw] of this.entries) {
      if (!matches(key)) continue;
      const entry = raw as Entry<unknown>;
      entry.sequence++;
      entry.promise = null;
      invalidated.push(key);
      this.publish(entry, {
        ...entry.snapshot,
        state: entry.snapshot.data === undefined ? "cold" : "partial",
        stale: true,
      });
    }
    return invalidated;
  }

  reset(scope: ResourceKey | ((key: ResourceKey) => boolean)): ResourceKey[] {
    return this.invalidate(scope);
  }

  isActive(key: ResourceKey): boolean {
    return (this.entries.get(key)?.listeners.size ?? 0) > 0;
  }

  isInFlight(key: ResourceKey): boolean {
    return this.entries.get(key)?.promise != null;
  }

  /** Evict least-recently-read entries while retaining observed/in-flight keys. */
  evict(prefix: string, maximum: number, preserve: ReadonlySet<ResourceKey> = new Set()): void {
    const matching = [...this.entries.entries()].filter(([key]) => key.startsWith(prefix));
    if (matching.length <= maximum) return;
    matching.sort((a, b) => a[1].touched - b[1].touched);
    let remove = matching.length - maximum;
    for (const [key, entry] of matching) {
      if (remove === 0) break;
      if (preserve.has(key) || entry.listeners.size || entry.promise) continue;
      this.entries.delete(key);
      remove--;
    }
  }

  private entry<T>(key: ResourceKey): Entry<T> {
    let entry = this.entries.get(key) as Entry<T> | undefined;
    if (!entry) {
      entry = {
        snapshot: cold(key) as ResourceSnapshot<T>,
        sequence: 0,
        promise: null,
        listeners: new Set(),
        touched: ++this.clock,
      };
      this.entries.set(key, entry as Entry<unknown>);
    }
    return entry;
  }

  private publish<T>(entry: Entry<T>, snapshot: ResourceSnapshot<T>): void {
    entry.snapshot = Object.freeze(snapshot);
    entry.touched = ++this.clock;
    for (const listener of entry.listeners) listener();
  }
}
