import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { afterEach, mock, test } from "node:test";
import { openBrowser, parseAuthorizationEndpoint } from "../examples/client/cimd-client.mjs";

const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");

afterEach(() => {
  Object.defineProperty(process, "platform", platformDescriptor);
  mock.restoreAll();
  syncBuiltinESMExports();
});

function mockBrowserLaunch(platform) {
  Object.defineProperty(process, "platform", { value: platform });
  const child = new EventEmitter();
  child.unref = mock.fn();
  const spawn = mock.method(childProcess, "spawn", () => child);
  syncBuiltinESMExports();
  const log = mock.method(console, "log", () => {});
  return { child, spawn, log };
}

test("Windows prints server-controlled URLs without starting a shell", () => {
  const { spawn, log } = mockBrowserLaunch("win32");
  const url = "https://auth.example/&echo-test&/authorize?state=example&scope=mcp%3Atools";
  openBrowser(url);
  assert.equal(spawn.mock.callCount(), 0);
  assert.match(log.mock.calls[0].arguments[0], /Open this URL in your browser/);
  assert.ok(log.mock.calls[0].arguments[0].includes(url));
});

for (const [platform, command] of [["darwin", "open"], ["linux", "xdg-open"]]) {
  test(`${platform} passes the URL as one argument without a shell`, () => {
    const { child, spawn } = mockBrowserLaunch(platform);
    const url = "https://auth.example/authorize?state=example&scope=mcp%3Atools";
    openBrowser(url);
    assert.deepEqual(spawn.mock.calls[0].arguments, [command, [url], { stdio: "ignore", detached: true }]);
    assert.equal(child.unref.mock.callCount(), 1);
  });
}

test("browser launch failures print the error and a manual URL", () => {
  const { child } = mockBrowserLaunch("linux");
  const error = mock.method(console, "error", () => {});
  const url = "https://auth.example/authorize";
  openBrowser(url);
  child.emit("error", new Error("browser is unavailable"));
  assert.match(error.mock.calls[0].arguments[0], /browser is unavailable/);
  assert.ok(error.mock.calls[0].arguments[0].includes(url));
});

test("authorization endpoints accept HTTPS and local HTTP", () => {
  for (const endpoint of ["https://auth.example/authorize", "http://127.0.0.1:8787/authorize"]) {
    assert.equal(parseAuthorizationEndpoint(endpoint).href, endpoint);
  }
});

test("non-HTTP authorization endpoints are rejected before launching", () => {
  const { spawn } = mockBrowserLaunch("linux");
  for (const endpoint of ["javascript:alert(1)", "file:///tmp/authorize", "data:text/html,example"]) {
    assert.throws(() => parseAuthorizationEndpoint(endpoint), /authorization_endpoint must use http or https/);
    assert.throws(() => openBrowser(endpoint), /authorization_endpoint must use http or https/);
  }
  assert.equal(spawn.mock.callCount(), 0);
  assert.throws(() => parseAuthorizationEndpoint("not a URL"), TypeError);
});
