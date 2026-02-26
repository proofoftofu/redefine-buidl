import test from "node:test";
import assert from "node:assert/strict";
import {
  createInitialState,
  delegateAgent,
  generateBurnerAgent,
  markRunAgainFailure,
  revokeDelegation,
  runProtectedTx
} from "../src/state.js";

test("quick test happy path then revoke fail", () => {
  const state = createInitialState();
  const agent = generateBurnerAgent(state);

  const d = delegateAgent(state, agent.id, "demo.increment", 5);
  assert.equal(d.ok, true);

  const first = runProtectedTx(state, agent.id, "demo.increment");
  assert.equal(first.ok, true);

  const r = revokeDelegation(state, agent.id);
  assert.equal(r.ok, true);

  const second = runProtectedTx(state, agent.id, "demo.increment");
  assert.equal(second.ok, false);
  assert.equal(second.reason, "revoked");

  markRunAgainFailure(state, !second.ok);
  assert.equal(state.quickTest.runAgainFailed, true);
});

test("reject wrong scope", () => {
  const state = createInitialState();
  const agent = generateBurnerAgent(state);
  delegateAgent(state, agent.id, "vault.transfer", 5);

  const result = runProtectedTx(state, agent.id, "demo.increment");
  assert.equal(result.ok, false);
  assert.equal(result.reason, "scope mismatch");
});
