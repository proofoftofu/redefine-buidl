import {
  appendLog,
  createInitialState,
  delegateAgent,
  generateBurnerAgent,
  getAgentStatus,
  getQuickSteps,
  markRunAgainFailure,
  revokeDelegation,
  runProtectedTx
} from "./state.js";

const state = createInitialState();

const credentialVault = [
  {
    id: "cred_membership_plus",
    title: "Membership Credential",
    attrs: ["membership=true", "age>=18", "issuer=signed"],
    validity: "valid until 2027-01-01",
    tier: "TIER-ALPHA"
  },
  {
    id: "cred_trader_agent",
    title: "Trading Agent Pass",
    attrs: ["membership=true", "risk_profile=medium", "agent_scope=market"],
    validity: "valid until 2026-12-31",
    tier: "TIER-BETA"
  },
  {
    id: "cred_game_operator",
    title: "Game Operator Credential",
    attrs: ["membership=true", "age>=18", "agent_scope=gamefi"],
    validity: "valid until 2026-10-01",
    tier: "TIER-GAMMA"
  }
];

const el = {
  agents: document.querySelector("#agents"),
  credentialCards: document.querySelector("#credential-cards"),
  credentialSelect: document.querySelector("#credential-select"),
  proofPack: document.querySelector("#proof-pack"),
  delegateAgent: document.querySelector("#delegate-agent"),
  delegateScope: document.querySelector("#delegate-scope"),
  delegateExpiry: document.querySelector("#delegate-expiry"),
  steps: document.querySelector("#steps"),
  console: document.querySelector("#console"),
  generateBurner: document.querySelector("#generate-burner"),
  runProtected: document.querySelector("#run-protected"),
  runAgain: document.querySelector("#run-again"),
  revoke: document.querySelector("#revoke"),
  delegateForm: document.querySelector("#delegate-form")
};

function statusClass(status) {
  if (status === "active") return "status status-active";
  if (status === "none") return "status status-pending";
  return "status status-revoked";
}

function activeAgentId() {
  return state.activeAgentId || el.delegateAgent.value;
}

function activeAgentLabel() {
  const agent = state.agents.find((a) => a.id === activeAgentId());
  return agent ? agent.label : "none";
}

function selectedCredential() {
  return credentialVault.find((c) => c.id === el.credentialSelect.value) || credentialVault[0];
}

function renderCredentialCards() {
  el.credentialCards.innerHTML = "";
  el.credentialSelect.innerHTML = "";

  for (const cred of credentialVault) {
    const card = document.createElement("article");
    card.className = "credential-card";
    card.innerHTML = `
      <p class="credential-title">${cred.title}</p>
      <div class="credential-meta">
        <span>${cred.attrs.join(" • ")}</span>
        <span>${cred.validity}</span>
      </div>
      <span class="credential-tag">${cred.tier}</span>
    `;
    el.credentialCards.appendChild(card);

    const opt = document.createElement("option");
    opt.value = cred.id;
    opt.textContent = cred.title;
    el.credentialSelect.appendChild(opt);
  }
}

function renderAgents() {
  el.agents.innerHTML = "";
  el.delegateAgent.innerHTML = "";

  for (const agent of state.agents) {
    const status = getAgentStatus(state, agent);
    const wrap = document.createElement("article");
    wrap.className = `agent-item${agent.id === state.activeAgentId ? " active" : ""}`;
    wrap.innerHTML = `
      <div class="agent-main">
        <p class="agent-title">${agent.label}</p>
        <p class="agent-key">${agent.pubkey}</p>
      </div>
      <span class="${statusClass(status)}">${status}</span>
    `;
    wrap.addEventListener("click", () => {
      state.activeAgentId = agent.id;
      render();
    });
    el.agents.appendChild(wrap);

    const opt = document.createElement("option");
    opt.value = agent.id;
    opt.textContent = `${agent.label} (${agent.pubkey.slice(0, 10)}...)`;
    if (agent.id === state.activeAgentId) opt.selected = true;
    el.delegateAgent.appendChild(opt);
  }
}

function renderProofPack() {
  const agentId = activeAgentId();
  const delegation = agentId ? state.delegationByAgentId[agentId] : null;
  const cred = selectedCredential();

  if (!delegation) {
    el.proofPack.innerHTML = `
      <div class="proof-line"><span>Credential</span><strong>${cred.title}</strong></div>
      <div class="proof-line"><span>Agent</span><strong>${activeAgentLabel()}</strong></div>
      <div class="proof-line"><span>Proof</span><strong>not generated</strong></div>
      <div class="proof-line"><span>Nullifier</span><strong>pending</strong></div>
      <div class="proof-line"><span>Delegation</span><strong>pending</strong></div>
    `;
    return;
  }

  const proofHash = `0xproof${delegation.nullifier}${delegation.scope.length}`;
  const status = delegation.revoked ? "revoked" : "active";
  el.proofPack.innerHTML = `
    <div class="proof-line"><span>Credential</span><strong>${cred.title}</strong></div>
    <div class="proof-line"><span>Agent</span><strong>${activeAgentLabel()}</strong></div>
    <div class="proof-line"><span>Scope</span><strong>${delegation.scope}</strong></div>
    <div class="proof-line"><span>Proof</span><strong>${proofHash}</strong></div>
    <div class="proof-line"><span>Nullifier</span><strong>0x${delegation.nullifier}</strong></div>
    <div class="proof-line"><span>Delegation</span><strong>${status}</strong></div>
  `;
}

function renderSteps() {
  el.steps.innerHTML = "";
  for (const [label, done] of getQuickSteps(state)) {
    const row = document.createElement("div");
    row.className = "step";
    row.innerHTML = `<span>${label}</span><span class="${done ? "status status-active" : "status status-pending"}">${done ? "done" : "pending"}</span>`;
    el.steps.appendChild(row);
  }
}

function renderLogs() {
  el.console.innerHTML = "";
  for (const item of state.logs.slice(-100)) {
    const line = document.createElement("p");
    line.className = "log-line";
    line.innerHTML = `<strong>[${item.type}]</strong> ${item.at} ${item.message}`;
    el.console.appendChild(line);
  }
  el.console.scrollTop = el.console.scrollHeight;
}

function render() {
  renderCredentialCards();
  renderAgents();
  renderProofPack();
  renderSteps();
  renderLogs();
}

el.generateBurner.addEventListener("click", () => {
  generateBurnerAgent(state);
  appendLog(state, "issued", "issuer prepared anonymous credential pack for burner agent");
  render();
});

el.delegateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const agentId = activeAgentId();
  if (!agentId) {
    appendLog(state, "rejected", "delegate failed: generate burner agent first");
    render();
    return;
  }
  const cred = selectedCredential();
  const result = delegateAgent(state, agentId, el.delegateScope.value, Number(el.delegateExpiry.value));
  if (result.ok) {
    appendLog(state, "proof", `zk proof package generated using ${cred.title}`);
  }
  render();
});

el.runProtected.addEventListener("click", () => {
  runProtectedTx(state, activeAgentId(), "demo.increment");
  render();
});

el.revoke.addEventListener("click", () => {
  revokeDelegation(state, activeAgentId());
  render();
});

el.runAgain.addEventListener("click", () => {
  const result = runProtectedTx(state, activeAgentId(), "demo.increment");
  markRunAgainFailure(state, !result.ok);
  render();
});

el.credentialSelect.addEventListener("change", renderProofPack);
el.delegateAgent.addEventListener("change", () => {
  state.activeAgentId = el.delegateAgent.value;
  render();
});

appendLog(state, "info", "dashboard initialized. generate burner agent, choose credential card, then create zk delegation proof.");
render();
