function nowTs() {
  return Date.now();
}

function shortId() {
  return Math.random().toString(16).slice(2, 10);
}

function toStatusText(delegation, now = nowTs()) {
  if (!delegation) return "none";
  if (delegation.revoked) return "revoked";
  if (now > delegation.expiresAt) return "expired";
  return "active";
}

export function createInitialState() {
  return {
    agents: [],
    activeAgentId: null,
    delegationByAgentId: {},
    quickTest: {
      generated: false,
      delegated: false,
      executed: false,
      revoked: false,
      runAgainFailed: false
    },
    logs: []
  };
}

export function generateBurnerAgent(state) {
  const agent = {
    id: `agent_${shortId()}`,
    label: `burner-${state.agents.length + 1}`,
    pubkey: `0x${shortId()}${shortId()}`
  };
  state.agents.unshift(agent);
  state.activeAgentId = agent.id;
  state.quickTest.generated = true;
  appendLog(state, "created", `burner agent generated: ${agent.label} (${agent.pubkey})`);
  return agent;
}

export function registerAgent(state, label, pubkey) {
  const cleanLabel = (label || "").trim();
  const cleanKey = (pubkey || "").trim();
  if (!cleanLabel || !cleanKey) {
    return { ok: false, reason: "missing label or pubkey" };
  }
  const agent = {
    id: `agent_${shortId()}`,
    label: cleanLabel,
    pubkey: cleanKey
  };
  state.agents.push(agent);
  if (!state.activeAgentId) state.activeAgentId = agent.id;
  appendLog(state, "created", `agent registered: ${agent.label} (${agent.pubkey})`);
  return { ok: true, agent };
}

export function delegateAgent(state, agentId, scope, expiryMinutes) {
  const agent = state.agents.find((a) => a.id === agentId);
  if (!agent) {
    appendLog(state, "rejected", "delegate failed: unknown agent");
    return { ok: false, reason: "unknown agent" };
  }
  const expiry = Math.max(1, Number(expiryMinutes) || 1);
  const delegation = {
    scope,
    createdAt: nowTs(),
    expiresAt: nowTs() + expiry * 60 * 1000,
    revoked: false,
    nullifier: shortId()
  };
  state.delegationByAgentId[agent.id] = delegation;
  state.activeAgentId = agent.id;
  state.quickTest.delegated = true;
  appendLog(
    state,
    "delegated",
    `delegation active for ${agent.label} scope=${scope} expiry=${expiry}m nullifier=0x${delegation.nullifier}`
  );
  return { ok: true, delegation };
}

export function runProtectedTx(state, agentId, expectedScope = "demo.increment") {
  const agent = state.agents.find((a) => a.id === agentId);
  if (!agent) {
    appendLog(state, "rejected", "execution failed: unknown agent");
    return { ok: false, reason: "unknown agent" };
  }

  const delegation = state.delegationByAgentId[agent.id];
  if (!delegation) {
    appendLog(state, "rejected", `execution failed: ${agent.label} not authorized`);
    return { ok: false, reason: "not authorized" };
  }

  const status = toStatusText(delegation);
  if (status === "revoked") {
    appendLog(state, "rejected", `execution failed: ${agent.label} revoked`);
    return { ok: false, reason: "revoked" };
  }
  if (status === "expired") {
    appendLog(state, "rejected", `execution failed: ${agent.label} expired`);
    return { ok: false, reason: "expired" };
  }
  if (delegation.scope !== expectedScope) {
    appendLog(state, "rejected", `execution failed: scope mismatch expected=${expectedScope}`);
    return { ok: false, reason: "scope mismatch" };
  }

  const txHash = `0x${shortId()}${shortId()}${shortId()}`;
  appendLog(state, "executed", `protected tx success by ${agent.label} tx=${txHash}`);
  state.quickTest.executed = true;
  return { ok: true, txHash };
}

export function revokeDelegation(state, agentId) {
  const delegation = state.delegationByAgentId[agentId];
  if (!delegation) {
    appendLog(state, "rejected", "revoke failed: no delegation");
    return { ok: false, reason: "no delegation" };
  }
  delegation.revoked = true;
  state.quickTest.revoked = true;
  appendLog(state, "revoked", `delegation revoked nullifier=0x${delegation.nullifier}`);
  return { ok: true };
}

export function appendLog(state, type, message) {
  state.logs.push({ type, message, at: new Date().toISOString() });
}

export function getAgentStatus(state, agent) {
  const delegation = state.delegationByAgentId[agent.id];
  return toStatusText(delegation);
}

export function getQuickSteps(state) {
  return [
    ["Generate Burner Agent", state.quickTest.generated],
    ["Delegate", state.quickTest.delegated],
    ["Run Protected Tx", state.quickTest.executed],
    ["Revoke", state.quickTest.revoked],
    ["Run Again (Should Fail)", state.quickTest.runAgainFailed]
  ];
}

export function markRunAgainFailure(state, failed) {
  state.quickTest.runAgainFailed = Boolean(failed);
}
