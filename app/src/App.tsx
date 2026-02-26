import { useEffect, useMemo, useState } from 'react';
import './App.css';
import { Noir } from '@noir-lang/noir_js';
import { Abi, DebugFileMap } from '@noir-lang/types';
import { UltraHonkBackend } from '@aztec/bb.js';
import { getZKHonkCallData, init } from 'garaga';
import { Account, Contract, RpcProvider } from 'starknet';
import initNoirC from '@noir-lang/noirc_abi';
import initACVM from '@noir-lang/acvm_js';
import acvm from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import noirc from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import { bytecode, abi } from './assets/circuit.json';
import { abi as verifierAbi } from './assets/verifier.json';
import vkUrl from './assets/vk.bin?url';

type Agent = {
  id: string;
  label: string;
  pubkey: string;
  walletAddress: string;
};

type Credential = {
  id: string;
  title: string;
  attrs: string[];
  validity: string;
  tier: string;
  holderSecret: bigint;
  dobDays: number;
  expiryDay: number;
};

type LogItem = {
  type: string;
  message: string;
  at: string;
};

type DelegationRecord = {
  scope: string;
  scopeHash: bigint;
  currentDay: number;
  minAgeDays: number;
  issuerPubkey: bigint;
  nullifier: bigint;
  proofHash: string;
  revoked: boolean;
  calldata: string[];
};

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const G = 7n;
const DEFAULT_RPC_URL = import.meta.env.VITE_STARKNET_RPC_URL ?? 'http://127.0.0.1:5050/rpc';
const DEFAULT_VERIFIER_ADDRESS = import.meta.env.VITE_VERIFIER_CONTRACT_ADDRESS ?? '';
const DEFAULT_ZK_AUTH_ADDRESS = import.meta.env.VITE_ZK_AGENT_AUTH_CONTRACT_ADDRESS ?? '';
const DEFAULT_INVOKER_ADDRESS = import.meta.env.VITE_INVOKER_ACCOUNT_ADDRESS ?? '';
const DEFAULT_INVOKER_PRIVATE_KEY = import.meta.env.VITE_INVOKER_PRIVATE_KEY ?? '';
const DEFAULT_FEE_TOKEN_ADDRESS =
  import.meta.env.VITE_FEE_TOKEN_ADDRESS ??
  '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
const DEFAULT_BURNER_FUND_WEI = import.meta.env.VITE_BURNER_FUND_WEI ?? '1000000000000000';
const DEFAULT_PROVER_THREADS = Number(import.meta.env.VITE_PROVER_THREADS ?? '1');

const CREDENTIALS: Credential[] = [
  {
    id: 'cred_membership_plus',
    title: 'Membership Credential',
    attrs: ['membership=true', 'age>=18', 'issuer=signed'],
    validity: 'valid until 2027-01-01',
    tier: 'TIER-ALPHA',
    holderSecret: 987654321n,
    dobDays: 10000,
    expiryDay: 22000,
  },
  {
    id: 'cred_trader_agent',
    title: 'Trading Agent Pass',
    attrs: ['membership=true', 'risk_profile=medium', 'agent_scope=market'],
    validity: 'valid until 2026-12-31',
    tier: 'TIER-BETA',
    holderSecret: 1234512345n,
    dobDays: 10240,
    expiryDay: 21900,
  },
  {
    id: 'cred_game_operator',
    title: 'Game Operator Credential',
    attrs: ['membership=true', 'age>=18', 'agent_scope=gamefi'],
    validity: 'valid until 2026-10-01',
    tier: 'TIER-GAMMA',
    holderSecret: 7788991122n,
    dobDays: 9800,
    expiryDay: 21400,
  },
];

const SCOPES = ['demo.increment', 'vault.transfer', 'market.place_order'];

function nowIso(): string {
  return new Date().toISOString();
}

function appendLog(setter: React.Dispatch<React.SetStateAction<LogItem[]>>, type: string, message: string): void {
  setter((prev) => [...prev, { type, message, at: nowIso() }]);
}

function randomHex(bytes = 8): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values)
    .map((v) => v.toString(16).padStart(2, '0'))
    .join('');
}

function modField(value: bigint): bigint {
  const reduced = value % FIELD_MODULUS;
  return reduced >= 0n ? reduced : reduced + FIELD_MODULUS;
}

function pow7(x: bigint): bigint {
  const x2 = modField(x * x);
  const x4 = modField(x2 * x2);
  return modField(x4 * x2 * x);
}

function mimcPermute(message: bigint, key: bigint): bigint {
  let x = modField(message + key);
  for (let i = 0n; i < 64n; i += 1n) {
    x = modField(pow7(x + i + 1n) + key);
  }
  return modField(x + key);
}

function hash2(a: bigint, b: bigint): bigint {
  const s1 = mimcPermute(a, b);
  return mimcPermute(b, s1);
}

function hash4(a: bigint, b: bigint, c: bigint, d: bigint): bigint {
  return hash2(hash2(a, b), hash2(c, d));
}

function hash5(a: bigint, b: bigint, c: bigint, d: bigint, e: bigint): bigint {
  return hash2(hash4(a, b, c, d), e);
}

function scopeToField(scope: string): bigint {
  let acc = 0n;
  for (const ch of scope) {
    acc = modField(acc * 257n + BigInt(ch.charCodeAt(0)));
  }
  return acc;
}

function flattenFieldsAsArray(fields: string[]): Uint8Array {
  const flattenedPublicInputs = fields.map(hexToUint8Array);
  return flattenUint8Arrays(flattenedPublicInputs);
}

function flattenUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, val) => acc + val.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

function hexToUint8Array(hex: string): Uint8Array {
  const sanitisedHex = BigInt(hex).toString(16).padStart(64, '0');
  const len = sanitisedHex.length / 2;
  const u8 = new Uint8Array(len);

  let i = 0;
  let j = 0;
  while (i < len) {
    u8[i] = parseInt(sanitisedHex.slice(j, j + 2), 16);
    i += 1;
    j += 2;
  }

  return u8;
}

function toUint256(value: bigint): [string, string] {
  const lowMask = (1n << 128n) - 1n;
  const low = value & lowMask;
  const high = value >> 128n;
  return [low.toString(), high.toString()];
}

function truncateMiddle(value: string, left = 12, right = 8): string {
  if (value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

function App() {
  const [vk, setVk] = useState<Uint8Array | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null);
  const [credentialId, setCredentialId] = useState<string>(CREDENTIALS[0].id);
  const [scope, setScope] = useState<string>(SCOPES[0]);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [burnerFunding, setBurnerFunding] = useState<boolean>(false);
  const [lastDelegation, setLastDelegation] = useState<DelegationRecord | null>(null);

  const rpcUrl = DEFAULT_RPC_URL;
  const verifierAddress = DEFAULT_VERIFIER_ADDRESS;
  const zkAuthAddress = DEFAULT_ZK_AUTH_ADDRESS;
  const invokerAddress = DEFAULT_INVOKER_ADDRESS;
  const invokerPrivateKey = DEFAULT_INVOKER_PRIVATE_KEY;
  const feeTokenAddress = DEFAULT_FEE_TOKEN_ADDRESS;
  const burnerFundWei = DEFAULT_BURNER_FUND_WEI;

  const logEvent = (type: string, message: string) => {
    console.log(`[${type}] ${message}`);
    appendLog(setLogs, type, message);
  };

  const selectedCredential = useMemo(
    () => CREDENTIALS.find((c) => c.id === credentialId) ?? CREDENTIALS[0],
    [credentialId],
  );

  const activeAgent = useMemo(
    () => agents.find((agent) => agent.id === activeAgentId) ?? null,
    [agents, activeAgentId],
  );

  useEffect(() => {
    const initWasm = async () => {
      await Promise.all([initACVM(fetch(acvm)), initNoirC(fetch(noirc))]);
      logEvent('ready', 'ACVM/Noir WASM initialized');
    };

    const loadVk = async () => {
      const response = await fetch(vkUrl);
      const arrayBuffer = await response.arrayBuffer();
      setVk(new Uint8Array(arrayBuffer));
      logEvent('ready', 'verifying key loaded');
    };

    Promise.all([initWasm(), loadVk()]).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('error', `startup init failed: ${message}`);
    });
  }, []);

  const generateBurnerAgent = async () => {
    logEvent('debug', 'generateBurnerAgent requested');
    if (agents.length > 0) {
      logEvent('rejected', 'burner agent already exists; only one is allowed');
      return;
    }

    const pubkey = modField(BigInt(`0x${randomHex(16)}`)).toString();
    const walletAddress = `0x${randomHex(32)}`;
    const agent: Agent = {
      id: `agent_${randomHex(4)}`,
      label: 'burner-1',
      pubkey,
      walletAddress,
    };
    setAgents([agent]);
    setActiveAgentId(agent.id);
    logEvent(
      'created',
      `burner agent generated: ${agent.label} pubkey=${agent.pubkey} wallet=${agent.walletAddress}`,
    );

    if (!invokerAddress || !invokerPrivateKey) {
      logEvent('warn', 'invoker credentials missing; skipping burner funding');
      return;
    }

    try {
      setBurnerFunding(true);
      logEvent('debug', `funding burner started from ${invokerAddress}`);
      const provider = new RpcProvider({ nodeUrl: rpcUrl });
      const account = new Account({
        provider,
        address: invokerAddress,
        signer: invokerPrivateKey,
      });
      const amountWei = BigInt(burnerFundWei || '0');
      const [low, high] = toUint256(amountWei);
      const transferTx = await account.execute({
        contractAddress: feeTokenAddress,
        entrypoint: 'transfer',
        calldata: [agent.walletAddress, low, high],
      });
      logEvent('debug', `burner funding tx submitted: ${transferTx.transaction_hash}`);
      await account.waitForTransaction(transferTx.transaction_hash);
      logEvent('executed', `burner funded: ${amountWei.toString()} wei tx=${transferTx.transaction_hash}`);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('error', `burner funding failed: ${message}`);
    } finally {
      setBurnerFunding(false);
    }
  };

  const buildPublicInputs = (agentPubkey: bigint, scopeHash: bigint, currentDay: number) => {
    const minAgeDays = 6570;
    const holderCommitment = hash2(selectedCredential.holderSecret, agentPubkey);
    const credentialHash = hash4(
      BigInt(selectedCredential.dobDays),
      1n,
      BigInt(selectedCredential.expiryDay),
      holderCommitment,
    );

    const issuerSecret = 123456789n;
    const issuerPubkey = modField(G * issuerSecret);
    const nonce = modField(BigInt(`0x${randomHex(16)}`));
    const issuerSigR = modField(G * nonce);
    const e = hash5(issuerSigR, issuerPubkey, credentialHash, agentPubkey, scopeHash);
    const issuerSigS = modField(nonce + e * issuerSecret);

    const nullifier = hash2(hash2(selectedCredential.holderSecret, scopeHash), agentPubkey);

    return {
      currentDay,
      minAgeDays,
      issuerPubkey,
      issuerSigR,
      issuerSigS,
      nullifier,
    };
  };

  const runProofPipeline = async () => {
    logEvent('debug', 'runProofPipeline started');
    if (!activeAgent) {
      logEvent('rejected', 'delegate failed: generate burner agent first');
      return;
    }
    if (!vk) {
      logEvent('rejected', 'delegate failed: verifying key not loaded');
      return;
    }

    setLoading(true);
    logEvent('proof', 'starting witness generation');

    try {
      const agentPubkey = modField(BigInt(activeAgent.pubkey));
      const scopeHash = scopeToField(scope);
      const currentDay = Math.floor(Date.now() / 86_400_000);
      logEvent(
        'debug',
        `public inputs context agent=${agentPubkey.toString()} scopeHash=${scopeHash.toString()} day=${currentDay}`,
      );

      const inputs = buildPublicInputs(agentPubkey, scopeHash, currentDay);
      const noirInput = {
        dob_days: selectedCredential.dobDays,
        membership: 1,
        credential_expiry_day: selectedCredential.expiryDay,
        holder_secret: selectedCredential.holderSecret.toString(),
        issuer_sig_r: inputs.issuerSigR.toString(),
        issuer_sig_s: inputs.issuerSigS.toString(),
        issuer_pubkey: inputs.issuerPubkey.toString(),
        current_day: currentDay,
        min_age_days: inputs.minAgeDays,
        agent_key: agentPubkey.toString(),
        scope_hash: scopeHash.toString(),
        nullifier: inputs.nullifier.toString(),
      };

      logEvent('debug', 'executing noir witness');
      let noir = new Noir({ bytecode, abi: abi as Abi, debug_symbols: '', file_map: {} as DebugFileMap });
      let execResult = await noir.execute(noirInput);
      logEvent('proof', 'witness generated');

      logEvent('debug', 'generating UltraHonk proof');
      const proverThreads = Number.isFinite(DEFAULT_PROVER_THREADS) && DEFAULT_PROVER_THREADS > 0
        ? Math.floor(DEFAULT_PROVER_THREADS)
        : 1;
      logEvent('debug', `creating UltraHonk backend threads=${proverThreads}`);
      let honk = new UltraHonkBackend(bytecode, { threads: proverThreads });
      let proof = await honk.generateProof(execResult.witness, { keccakZK: true });
      honk.destroy();
      logEvent('proof', 'proof generated');

      logEvent('debug', 'initializing garaga and preparing calldata');
      await init();
      let callData = getZKHonkCallData(
        proof.proof,
        flattenFieldsAsArray(proof.publicInputs),
        vk,
      );

      const record: DelegationRecord = {
        scope,
        scopeHash,
        currentDay,
        minAgeDays: inputs.minAgeDays,
        issuerPubkey: inputs.issuerPubkey,
        nullifier: inputs.nullifier,
        revoked: false,
        proofHash: `0x${randomHex(20)}`,
        calldata: callData.slice(1).map((value) => value.toString()),
      };

      setLastDelegation(record);
      logEvent('delegated', `delegation prepared scope=${scope} nullifier=0x${inputs.nullifier.toString(16)}`);

      const provider = new RpcProvider({ nodeUrl: rpcUrl });
      logEvent('debug', `rpc provider ready at ${rpcUrl}`);

      if (zkAuthAddress) {
        logEvent('debug', `using zkAuth contract ${zkAuthAddress}`);
        const consumeCalldata = [
          record.calldata.length.toString(),
          ...record.calldata,
          record.issuerPubkey.toString(),
          record.currentDay.toString(),
          record.minAgeDays.toString(),
          agentPubkey.toString(),
          record.scopeHash.toString(),
          record.nullifier.toString(),
        ];

        if (invokerAddress && invokerPrivateKey) {
          const account = new Account({
            provider,
            address: invokerAddress,
            signer: invokerPrivateKey,
          });
          const invocation = await account.execute({
            contractAddress: zkAuthAddress,
            entrypoint: 'verify_and_consume',
            calldata: consumeCalldata,
          });
          await account.waitForTransaction(invocation.transaction_hash);
          logEvent('executed', `verify_and_consume invoked tx=${invocation.transaction_hash}`);
        } else {
          const providerLike = provider as unknown as {
            callContract: (args: {
              contractAddress: string;
              entrypoint: string;
              calldata: string[];
            }) => Promise<{ result: string[] }>;
          };
          const response = await providerLike.callContract({
            contractAddress: zkAuthAddress,
            entrypoint: 'verify_and_consume',
            calldata: consumeCalldata,
          });

          const ok = response.result[0] === '0x1' || response.result[0] === '1';
          if (!ok) {
            throw new Error('verify_and_consume returned false');
          }
          logEvent('executed', 'zk-agent-auth verify_and_consume passed (read-only call)');
        }
      } else {
        if (!verifierAddress) {
          throw new Error('Missing verifier address. Set VITE_VERIFIER_CONTRACT_ADDRESS or fill UI field.');
        }
        logEvent('debug', `using fallback verifier contract ${verifierAddress}`);
        const verifierContract = new Contract({
          abi: verifierAbi,
          address: verifierAddress,
          providerOrAccount: provider,
        });
        const result = await verifierContract.verify_ultra_keccak_zk_honk_proof(record.calldata);
        if (!result.is_ok()) {
          throw new Error('Verifier rejected proof');
        }
        logEvent('executed', 'base verifier accepted proof (stateless check)');
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('error', message);
    } finally {
      setLoading(false);
      logEvent('debug', 'runProofPipeline completed');
    }
  };

  const runProtected = () => {
    logEvent('debug', 'runProtected requested');
    if (!activeAgent || !lastDelegation || lastDelegation.revoked) {
      logEvent('rejected', 'execution failed: no active delegation');
      return;
    }
    logEvent('executed', `protected tx success by ${activeAgent.label} scope=${lastDelegation.scope}`);
  };

  const revoke = () => {
    logEvent('debug', 'revoke requested');
    if (!lastDelegation) {
      logEvent('rejected', 'revoke failed: no delegation');
      return;
    }
    setLastDelegation({ ...lastDelegation, revoked: true });
    logEvent('revoked', `delegation revoked nullifier=0x${lastDelegation.nullifier.toString(16)}`);
  };

  const runAgain = () => {
    logEvent('debug', 'runAgain requested');
    if (!lastDelegation || lastDelegation.revoked) {
      logEvent('rejected', 'execution failed as expected: delegation revoked or missing');
      return;
    }
    logEvent('warn', 'execution unexpectedly succeeded; revoke first to test nullifier replay failure');
  };

  const quickSteps: Array<[string, boolean]> = [
    ['Generate Burner Agent', agents.length > 0],
    ['Delegate', Boolean(lastDelegation)],
    ['Run Protected Tx', logs.some((log) => log.message.includes('protected tx success'))],
    ['Revoke', Boolean(lastDelegation?.revoked)],
    ['Run Again (Should Fail)', logs.some((log) => log.message.includes('as expected'))],
  ];

  return (
    <>
      <div className="scanline" aria-hidden="true" />

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark" />
          <div>
            <p className="eyebrow">Starknet Privacy Infra</p>
            <h1>Agent Credential Terminal</h1>
          </div>
        </div>
        <div className="chip">Root app (Garaga + Noir + zk-agent-auth)</div>
      </header>

      <main className="layout">
        <section className="card card-issuer">
          <div className="card-head">
            <h2>Issuer Credential Vault</h2>
            <span className="chip chip-soft">Anonymous Attributes</span>
          </div>
          <div className="credential-cards">
            {CREDENTIALS.map((cred) => (
              <article key={cred.id} className="credential-card">
                <p className="credential-title">{cred.title}</p>
                <div className="credential-meta">
                  <span>{cred.attrs.join(' • ')}</span>
                  <span>{cred.validity}</span>
                </div>
                <span className="credential-tag">{cred.tier}</span>
              </article>
            ))}
          </div>
        </section>

        <section className="card card-agents">
          <div className="card-head">
            <h2>Agent Registry</h2>
            <button
              disabled={loading || burnerFunding || agents.length > 0}
              onClick={generateBurnerAgent}
              className="btn btn-primary"
              type="button"
            >
              Generate Burner Agent
            </button>
          </div>
          <p className="mono-note">
            Burner agent key is used as `agent_key` public input. Only one burner agent is allowed.
          </p>
          <div className="agents-list">
            {agents.map((agent) => {
              const isActive = agent.id === activeAgentId;
              return (
                <article
                  key={agent.id}
                  className={`agent-item${isActive ? ' active' : ''}`}
                  onClick={() => setActiveAgentId(agent.id)}
                >
                  <div className="agent-main">
                    <p className="agent-title">{agent.label}</p>
                    <p className="agent-key">pubkey: {truncateMiddle(agent.pubkey)}</p>
                    <p className="agent-key">wallet: {truncateMiddle(agent.walletAddress)}</p>
                  </div>
                  <span className={`status ${lastDelegation?.revoked ? 'status-revoked' : 'status-active'}`}>
                    {isActive ? 'selected' : 'idle'}
                  </span>
                </article>
              );
            })}
          </div>
        </section>

        <section className="card card-delegate">
          <div className="card-head">
            <h2>ZK Delegation Composer</h2>
            <span className="chip chip-soft">Issuer -&gt; Agent</span>
          </div>
          <div className="stack-form">
            <label>
              Agent
              <select
                value={activeAgentId ?? ''}
                onChange={(event) => setActiveAgentId(event.target.value || null)}
                disabled={loading || agents.length === 0}
              >
                <option value="">Select agent</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Credential Card
              <select value={credentialId} onChange={(event) => setCredentialId(event.target.value)} disabled={loading}>
                {CREDENTIALS.map((cred) => (
                  <option key={cred.id} value={cred.id}>
                    {cred.title}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Scope
              <select value={scope} onChange={(event) => setScope(event.target.value)} disabled={loading}>
                {SCOPES.map((scopeValue) => (
                  <option key={scopeValue} value={scopeValue}>
                    {scopeValue}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn btn-primary" type="button" disabled={loading} onClick={runProofPipeline}>
              {loading ? 'Generating proof...' : 'Issue Delegation + Proof Package'}
            </button>
          </div>

          <div className="proof-pack">
            <h3>Proof Package</h3>
            <div className="proof-pack-body">
              <div className="proof-line">
                <span>Credential</span>
                <strong>{selectedCredential.title}</strong>
              </div>
              <div className="proof-line">
                <span>Agent</span>
                <strong>{activeAgent?.label ?? 'none'}</strong>
              </div>
              <div className="proof-line">
                <span>Scope</span>
                <strong>{lastDelegation?.scope ?? 'pending'}</strong>
              </div>
              <div className="proof-line">
                <span>Proof</span>
                <strong>{lastDelegation?.proofHash ?? 'not generated'}</strong>
              </div>
              <div className="proof-line">
                <span>Nullifier</span>
                <strong>{lastDelegation ? `0x${lastDelegation.nullifier.toString(16)}` : 'pending'}</strong>
              </div>
              <div className="proof-line">
                <span>Delegation</span>
                <strong>{lastDelegation ? (lastDelegation.revoked ? 'revoked' : 'active') : 'pending'}</strong>
              </div>
            </div>
          </div>
        </section>

        <section className="card card-flow">
          <div className="card-head">
            <h2>Delegation Flow</h2>
            <span className="chip chip-soft">Quick Test</span>
          </div>
          <div className="steps">
            {quickSteps.map(([label, done]) => (
              <div key={label} className="step">
                <span>{label}</span>
                <span className={`status ${done ? 'status-active' : 'status-pending'}`}>{done ? 'done' : 'pending'}</span>
              </div>
            ))}
          </div>
          <div className="step-actions">
            <button id="run-protected" className="btn" type="button" onClick={runProtected}>
              Run Protected Tx
            </button>
            <button id="revoke" className="btn btn-danger" type="button" onClick={revoke}>
              Revoke
            </button>
            <button id="run-again" className="btn" type="button" onClick={runAgain}>
              Run Again (Should Fail)
            </button>
          </div>
        </section>

        <section className="card card-console">
          <div className="card-head">
            <h2>Runtime Logs</h2>
            <span className="chip chip-soft">Privacy-safe logs</span>
          </div>
          <div className="console">
            {logs.slice(-100).map((item, index) => (
              <p key={`${item.at}-${index}`} className="log-line">
                <strong>[{item.type}]</strong> {item.at} {item.message}
              </p>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}

export default App;
