print(JSON.stringify({
  globalThis: typeof globalThis,
  promise: typeof Promise,
  typedArray: typeof Uint8Array,
  finalizationRegistry: typeof FinalizationRegistry,
  weakRef: typeof WeakRef,
}));
