/** Own methods run bound to `target`, the holder of their private fields. */
export function extended<T extends object, M extends object>(target: T, methods: M): T & M {
  return new Proxy(target, {
    get(object, key) {
      if (Object.hasOwn(methods, key)) return (methods as Record<PropertyKey, unknown>)[key];
      const value: unknown = Reflect.get(object, key, object);
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(object)
        : value;
    },
    has(object, key) {
      return Object.hasOwn(methods, key) || Reflect.has(object, key);
    },
  }) as T & M;
}
