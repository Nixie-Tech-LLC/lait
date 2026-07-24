import { createContext, useContext, useEffect, useSyncExternalStore, type ReactNode } from "react";
import { type ResourceKey, type ResourceSnapshot, WorldViewStore } from "./worldViewStore";

const WorldViewContext = createContext<WorldViewStore | null>(null);

export function WorldViewStoreProvider({
  store,
  children,
}: {
  store: WorldViewStore;
  children: ReactNode;
}) {
  return <WorldViewContext.Provider value={store}>{children}</WorldViewContext.Provider>;
}

export function useWorldViewStore(): WorldViewStore {
  const store = useContext(WorldViewContext);
  if (!store) throw new Error("WorldViewStoreProvider is missing");
  return store;
}

export function useWorldResource<T>(
  key: ResourceKey,
  loader?: () => Promise<T>,
): ResourceSnapshot<T> {
  const store = useWorldViewStore();
  const snapshot = useSyncExternalStore(
    (listener) => store.subscribe(key, listener),
    () => store.read<T>(key),
    () => store.read<T>(key),
  );
  useEffect(() => {
    if (loader) void store.ensure(key, loader).catch(() => undefined);
  }, [key, loader, store]);
  return snapshot;
}
