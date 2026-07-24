/** Build a stable lookup once at a projection boundary instead of repeating
 * `Array.find` in every rendered row/card. Later virtualization can consume the
 * same map without changing component contracts. */
export function indexBy<T, K>(values: readonly T[], keyOf: (value: T) => K): Map<K, T> {
  return new Map(values.map((value) => [keyOf(value), value]));
}

/** Keep the newest part of an ordered feed mounted while retaining an explicit
 * path to older local history. */
export function boundedTail<T>(values: readonly T[], count: number): readonly T[] {
  return values.slice(Math.max(0, values.length - Math.max(0, count)));
}
