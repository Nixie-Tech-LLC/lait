import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The keymap is a DOM contract — `KeyboardEvent.key` semantics are the thing
    // under test, so a real DOM implementation is the point, not a convenience.
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
