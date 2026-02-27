import { useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import { Noir } from '@noir-lang/noir_js';
import { Abi, DebugFileMap } from '@noir-lang/types';
import { UltraHonkBackend } from '@aztec/bb.js';
import { getZKHonkCallData, init } from 'garaga';
import { disconnect, type StarknetWindowObject } from '@starknet-io/get-starknet';
import { getStarknet } from '@starknet-io/get-starknet-core';
import { Contract, RpcProvider, WalletAccount } from 'starknet';
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
  vcId: string;
  vcType: string[];
  issuer: string;
  subject: string;
  issuanceDate: string;
  expirationDate: string;
  proofType: string;
  status: string;
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
  agentId: string;
  credentialLabel: string;
  scope: string;
  scopeHash: bigint;
  currentDay: number;
  minAgeDays: number;
  issuerPubkey: bigint;
  nullifier: bigint;
  proofHash: string;
  issued: boolean;
  issuedAt: string | null;
  issuedTxHash: string | null;
  onchainNullifierUsed: boolean | null;
  revoked: boolean;
  calldata: string[];
};

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const STARK_FIELD_MODULUS =
  3618502788666131213697322783095070105623107215331596699973092056135872020481n;
const G = 7n;
const DEFAULT_RPC_URL = import.meta.env.VITE_STARKNET_RPC_URL ?? 'http://127.0.0.1:5050/rpc';
const DEFAULT_VERIFIER_ADDRESS = import.meta.env.VITE_VERIFIER_CONTRACT_ADDRESS ?? '';
const DEFAULT_ZK_AUTH_ADDRESS = import.meta.env.VITE_ZK_AGENT_AUTH_CONTRACT_ADDRESS ?? '';
const DEFAULT_FEE_TOKEN_ADDRESS =
  import.meta.env.VITE_FEE_TOKEN_ADDRESS ??
  '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
const DEFAULT_BURNER_FUND_WEI = import.meta.env.VITE_BURNER_FUND_WEI ?? '1000000000000000';
const DEFAULT_PROVER_THREADS = Number(import.meta.env.VITE_PROVER_THREADS ?? '1');
const DEFAULT_TX_EXPLORER_BASE = import.meta.env.VITE_TX_EXPLORER_BASE ?? 'https://sepolia.voyager.online/tx';

const CREDENTIALS: Credential[] = [
  {
    id: 'cred_membership_plus',
    vcId: 'urn:uuid:7f5d8ac6-5de5-4d53-94bb-45293c4d1001',
    vcType: ['VerifiableCredential', 'MembershipCredential', 'AgeOver18Credential'],
    issuer: 'did:web:issuer.zk-agent.example',
    subject: 'did:key:z6Mkh5k...burner',
    issuanceDate: '2026-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    proofType: 'Bls12381G2Signature2020',
    status: 'StatusList2021Entry',
    holderSecret: 987654321n,
    dobDays: 10000,
    expiryDay: 22000,
  },
  {
    id: 'cred_trader_agent',
    vcId: 'urn:uuid:7f5d8ac6-5de5-4d53-94bb-45293c4d1002',
    vcType: ['VerifiableCredential', 'TradingAgentCredential'],
    issuer: 'did:web:issuer.zk-agent.example',
    subject: 'did:key:z6MkiA1...burner',
    issuanceDate: '2026-02-01T00:00:00Z',
    expirationDate: '2026-12-31T00:00:00Z',
    proofType: 'Bls12381G2Signature2020',
    status: 'StatusList2021Entry',
    holderSecret: 1234512345n,
    dobDays: 10240,
    expiryDay: 21900,
  },
  {
    id: 'cred_game_operator',
    vcId: 'urn:uuid:7f5d8ac6-5de5-4d53-94bb-45293c4d1003',
    vcType: ['VerifiableCredential', 'GameOperatorCredential', 'AgeOver18Credential'],
    issuer: 'did:web:issuer.zk-agent.example',
    subject: 'did:key:z6MkfW7...burner',
    issuanceDate: '2026-01-15T00:00:00Z',
    expirationDate: '2026-10-01T00:00:00Z',
    proofType: 'Bls12381G2Signature2020',
    status: 'StatusList2021Entry',
    holderSecret: 7788991122n,
    dobDays: 9800,
    expiryDay: 21400,
  },
];

const SCOPES = ['demo.increment', 'vault.transfer', 'market.place_order'];
const BURNER_STORAGE_KEY = 'zk_agent_auth_burner_agent_v1';

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

function modStarkField(value: bigint): bigint {
  const reduced = value % STARK_FIELD_MODULUS;
  return reduced >= 0n ? reduced : reduced + STARK_FIELD_MODULUS;
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

function txExplorerUrl(txHash: string): string {
  const base = DEFAULT_TX_EXPLORER_BASE.endsWith('/')
    ? DEFAULT_TX_EXPLORER_BASE.slice(0, -1)
    : DEFAULT_TX_EXPLORER_BASE;
  return `${base}/${txHash}`;
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
  const [wallet, setWallet] = useState<StarknetWindowObject | null>(null);
  const [walletAccount, setWalletAccount] = useState<WalletAccount | null>(null);
  const [connectedWalletAddress, setConnectedWalletAddress] = useState<string>('');
  const [walletConnecting, setWalletConnecting] = useState<boolean>(false);
  const [walletError, setWalletError] = useState<string>('');
  const [delegationSyncing, setDelegationSyncing] = useState<boolean>(false);
  const consoleRef = useRef<HTMLDivElement | null>(null);

  const rpcUrl = DEFAULT_RPC_URL;
  const verifierAddress = DEFAULT_VERIFIER_ADDRESS;
  const zkAuthAddress = DEFAULT_ZK_AUTH_ADDRESS;
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
  const selectedCredentialLabel = selectedCredential.vcType[1] ?? selectedCredential.vcType[0];

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

  useEffect(() => {
    try {
      const raw = localStorage.getItem(BURNER_STORAGE_KEY);
      if (!raw) return;

      const parsed = JSON.parse(raw) as { agent?: Agent; activeAgentId?: string | null };
      if (!parsed.agent) return;

      setAgents([parsed.agent]);
      setActiveAgentId(parsed.activeAgentId ?? parsed.agent.id);
      logEvent('ready', 'restored burner agent from local storage');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('warn', `failed to restore burner agent: ${message}`);
    }
  }, []);

  useEffect(() => {
    if (!consoleRef.current) return;
    consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [logs]);

  const connectWallet = async () => {
    if (walletConnecting) return;

    try {
      setWalletConnecting(true);
      setWalletError('');
      const starknet = getStarknet();
      const wallets = await starknet.getAvailableWallets({ include: ['argentX'], sort: ['argentX'] });
      const readyWallet = wallets.find((walletObject) => walletObject.id === 'argentX');
      if (!readyWallet) {
        const message = 'Ready Wallet (Argent X) not found. Install/enable Argent X extension.';
        setWalletError(message);
        logEvent('error', message);
        return;
      }

      const connectedWallet = await starknet.enable(readyWallet);
      if (!connectedWallet) {
        logEvent('warn', 'wallet connection cancelled');
        return;
      }

      const provider = new RpcProvider({ nodeUrl: rpcUrl });
      const account = await WalletAccount.connect(provider, connectedWallet);
      setWallet(connectedWallet);
      setWalletAccount(account);
      setConnectedWalletAddress(account.address);
      logEvent('executed', `wallet connected: ${account.address}`);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('error', `wallet connection failed: ${message}`);
    } finally {
      setWalletConnecting(false);
    }
  };

  const disconnectWallet = async () => {
    try {
      await disconnect({ clearLastWallet: true });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('warn', `wallet disconnect warning: ${message}`);
    }

    setWallet(null);
    setWalletAccount(null);
    setConnectedWalletAddress('');
    setWalletError('');
    logEvent('debug', 'wallet disconnected');
  };

  const generateBurnerAgent = async () => {
    logEvent('debug', 'generateBurnerAgent requested');
    if (agents.length > 0) {
      logEvent('rejected', 'burner agent already exists; only one is allowed');
      return;
    }

    const pubkey = modField(BigInt(`0x${randomHex(16)}`)).toString();
    // Starknet ContractAddress is a felt; keep generated demo address within felt range.
    const walletAddress = `0x${randomHex(31)}`;
    const agent: Agent = {
      id: `agent_${randomHex(4)}`,
      label: 'burner-1',
      pubkey,
      walletAddress,
    };
    setAgents([agent]);
    setActiveAgentId(agent.id);
    localStorage.setItem(BURNER_STORAGE_KEY, JSON.stringify({ agent, activeAgentId: agent.id }));
    logEvent(
      'created',
      `burner agent generated: ${agent.label} pubkey=${agent.pubkey} wallet=${agent.walletAddress}`,
    );
  };

  const fundActiveBurnerAgent = async () => {
    if (!activeAgent) {
      logEvent('rejected', 'funding failed: no active burner agent');
      return;
    }
    if (!walletAccount) {
      logEvent('rejected', 'funding failed: connect wallet first');
      return;
    }

    try {
      setBurnerFunding(true);
      logEvent('debug', `funding burner started from ${walletAccount.address}`);
      const amountWei = BigInt(burnerFundWei || '0');
      const [low, high] = toUint256(amountWei);
      const transferTx = await walletAccount.execute({
        contractAddress: feeTokenAddress,
        entrypoint: 'transfer',
        calldata: [activeAgent.walletAddress, low, high],
      });
      logEvent(
        'debug',
        `burner funding tx submitted: ${transferTx.transaction_hash} ${txExplorerUrl(transferTx.transaction_hash)}`,
      );
      await walletAccount.waitForTransaction(transferTx.transaction_hash);
      logEvent(
        'executed',
        `burner funded: ${amountWei.toString()} wei tx=${transferTx.transaction_hash} ${txExplorerUrl(transferTx.transaction_hash)}`,
      );
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('error', `burner funding failed: ${message}`);
    } finally {
      setBurnerFunding(false);
    }
  };

  const checkNullifierUsedOnchain = async (
    provider: RpcProvider,
    contractAddress: string,
    nullifier: bigint,
  ): Promise<boolean> => {
    const providerLike = provider as unknown as {
      callContract: (args: {
        contractAddress: string;
        entrypoint: string;
        calldata: string[];
      }) => Promise<{ result?: string[] } | string[]>;
    };

    const response = await providerLike.callContract({
      contractAddress,
      entrypoint: 'is_nullifier_used',
      calldata: [modStarkField(nullifier).toString()],
    });
    const values = Array.isArray(response) ? response : response.result ?? [];
    if (values.length === 0) {
      throw new Error('is_nullifier_used returned empty result');
    }
    return values[0] === '0x1' || values[0] === '1';
  };

  const syncDelegationFromOnchain = async () => {
    if (!activeAgent || !zkAuthAddress) return;
    try {
      setDelegationSyncing(true);
      const provider = new RpcProvider({ nodeUrl: rpcUrl });
      const agentPubkey = modField(BigInt(activeAgent.pubkey));
      const scopeHash = scopeToField(scope);
      const nullifier = hash2(hash2(selectedCredential.holderSecret, scopeHash), agentPubkey);
      const nullifierUsed = await checkNullifierUsedOnchain(provider, zkAuthAddress, nullifier);

      if (nullifierUsed) {
        setLastDelegation((prev) => ({
          agentId: activeAgent.id,
          credentialLabel: selectedCredentialLabel,
          scope,
          scopeHash,
          currentDay: prev?.currentDay ?? Math.floor(Date.now() / 86_400_000),
          minAgeDays: prev?.minAgeDays ?? 6570,
          issuerPubkey: prev?.issuerPubkey ?? modField(G * 123456789n),
          nullifier,
          proofHash: prev?.proofHash ?? 'onchain',
          issued: true,
          issuedAt: prev?.issuedAt ?? null,
          issuedTxHash: prev?.issuedTxHash ?? null,
          onchainNullifierUsed: true,
          revoked: prev?.revoked ?? false,
          calldata: prev?.calldata ?? [],
        }));
      } else {
        setLastDelegation((prev) => (prev?.agentId === activeAgent.id ? null : prev));
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent('warn', `on-chain delegation sync failed: ${message}`);
    } finally {
      setDelegationSyncing(false);
    }
  };

  useEffect(() => {
    syncDelegationFromOnchain().catch(() => {
      // errors already logged
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeAgentId, zkAuthAddress, credentialId, scope, rpcUrl]);

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
    if (!walletAccount) {
      logEvent('rejected', 'delegate failed: connect wallet first');
      return;
    }
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
        agentId: activeAgent.id,
        credentialLabel: selectedCredentialLabel,
        scope,
        scopeHash,
        currentDay,
        minAgeDays: inputs.minAgeDays,
        issuerPubkey: inputs.issuerPubkey,
        nullifier: inputs.nullifier,
        revoked: false,
        issued: false,
        issuedAt: null,
        issuedTxHash: null,
        onchainNullifierUsed: null,
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
          modStarkField(record.issuerPubkey).toString(),
          record.currentDay.toString(),
          record.minAgeDays.toString(),
          modStarkField(agentPubkey).toString(),
          modStarkField(record.scopeHash).toString(),
          modStarkField(record.nullifier).toString(),
        ];

        const invocation = await walletAccount.execute({
          contractAddress: zkAuthAddress,
          entrypoint: 'verify_and_consume',
          calldata: consumeCalldata,
        });
        await walletAccount.waitForTransaction(invocation.transaction_hash);
        logEvent(
          'executed',
          `verify_and_consume invoked tx=${invocation.transaction_hash} ${txExplorerUrl(invocation.transaction_hash)}`,
        );

        const nullifierUsed = await checkNullifierUsedOnchain(provider, zkAuthAddress, record.nullifier);
        setLastDelegation({
          ...record,
          issued: true,
          issuedAt: nowIso(),
          issuedTxHash: invocation.transaction_hash,
          onchainNullifierUsed: nullifierUsed,
        });
        logEvent(
          'executed',
          `on-chain verification state nullifier_used=${nullifierUsed ? 'true' : 'false'}`,
        );
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
    if (!activeAgent || !lastDelegation || !lastDelegation.issued || lastDelegation.revoked) {
      logEvent('rejected', 'execution failed: no active delegation');
      return;
    }
    logEvent('executed', `protected action simulated by ${activeAgent.label} scope=${lastDelegation.scope}`);
  };

  const revoke = () => {
    logEvent('debug', 'revoke requested');
    if (!lastDelegation || !lastDelegation.issued || lastDelegation.revoked) {
      logEvent('rejected', 'revoke failed: proof is not actively issued');
      return;
    }
    setLastDelegation({ ...lastDelegation, revoked: true });
    logEvent('revoked', `delegation revoked nullifier=0x${lastDelegation.nullifier.toString(16)}`);
  };

  const isIssuedAndActive = Boolean(lastDelegation?.issued && !lastDelegation?.revoked);

  const quickSteps: Array<[string, boolean]> = [
    ['Generate Burner Agent', agents.length > 0],
    ['Delegate', Boolean(lastDelegation?.issued)],
    ['Run Protected Tx', logs.some((log) => log.message.includes('protected tx success'))],
    ['Revoke', Boolean(lastDelegation?.revoked)],
  ];

  return (
    <>
      <div className="scanline" aria-hidden="true" />

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark" />
          <div>
            <p className="eyebrow">Starknet AI Agent Privacy Infra</p>
            <h1>Anonymous AI Agent Credentials</h1>
          </div>
        </div>
        <div className="topbar-actions">
          <div className="wallet-controls">
            <span className="chip chip-soft">
              {wallet
                ? `wallet ${truncateMiddle(connectedWalletAddress, 10, 6)}`
                : 'wallet disconnected'}
            </span>
            {wallet ? (
              <button className="btn" type="button" onClick={disconnectWallet} disabled={loading || burnerFunding}>
                Disconnect
              </button>
            ) : (
              <button
                className="btn btn-primary"
                type="button"
                onClick={connectWallet}
                disabled={walletConnecting || loading || burnerFunding}
              >
                {walletConnecting ? 'Connecting...' : 'Connect Ready Wallet'}
              </button>
            )}
          </div>
        </div>
        {walletError ? <p className="wallet-error">{walletError}</p> : null}
      </header>

      <main className="layout">
        <section className="card card-issuer">
          <div className="card-head">
            <h2>Issuer Credential Vault</h2>
          </div>
          <div className="credential-cards">
            {CREDENTIALS.map((cred) => (
              <article key={cred.id} className="credential-card">
                <p className="credential-title">VERIFIABLE CREDENTIAL</p>
                <p className="credential-id">{truncateMiddle(cred.vcId, 22, 12)}</p>
                <div className="credential-meta">
                  <span>type: {cred.vcType.join(', ')}</span>
                  <span>issuer: {cred.issuer}</span>
                  <span>subject: {cred.subject}</span>
                  <span>issuanceDate: {cred.issuanceDate}</span>
                  <span>expirationDate: {cred.expirationDate}</span>
                </div>
                <div className="credential-foot">
                  <span className="credential-tag">{cred.proofType}</span>
                  <span className="credential-tag">{cred.status}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="card card-agents">
          <div className="card-head">
            <h2>Agent Registry</h2>
            <div className="agent-actions">
              <button
                disabled={loading || burnerFunding || agents.length > 0}
                onClick={generateBurnerAgent}
                className="btn btn-primary"
                type="button"
              >
                Generate
              </button>
              <button
                disabled={loading || burnerFunding || agents.length === 0 || !walletAccount}
                onClick={fundActiveBurnerAgent}
                className="btn"
                type="button"
              >
                {burnerFunding ? 'Funding...' : 'Fund'}
              </button>
            </div>
          </div>
          <p className="mono-note">
            Burner agent key is used as `agent_key` public input. Only one burner agent is allowed.
            {' '}
            Funding is manual via `Fund Burner`.
            {delegationSyncing ? ' Syncing on-chain delegation...' : ''}
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
          {activeAgent && lastDelegation && lastDelegation.agentId === activeAgent.id ? (
            <div className="agent-attrs">
              <p className="agent-key">credential: {lastDelegation.credentialLabel}</p>
              <p className="agent-key">scope: {lastDelegation.scope}</p>
              <p className="agent-key">
                issued: {lastDelegation.issued ? 'yes' : 'no'}{lastDelegation.issuedAt ? ` @ ${lastDelegation.issuedAt}` : ''}
              </p>
              <p className="agent-key">
                onchain_valid:{' '}
                {lastDelegation.onchainNullifierUsed === null
                  ? 'n/a'
                  : lastDelegation.onchainNullifierUsed
                    ? 'yes'
                    : 'no'}
              </p>
              {lastDelegation.issuedTxHash ? (
                <p className="agent-key">tx: {truncateMiddle(lastDelegation.issuedTxHash)}</p>
              ) : null}
            </div>
          ) : null}
        </section>

        <section className="card card-delegate">
          <div className="card-head">
            <h2>ZK Delegation Composer</h2>
          </div>
          <div className="stack-form">
            <label>
              Agent
              <select
                value={activeAgentId ?? ''}
                onChange={(event) => setActiveAgentId(event.target.value || null)}
                disabled
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
              Credential
              <select value={credentialId} onChange={(event) => setCredentialId(event.target.value)} disabled>
                {CREDENTIALS.map((cred) => (
                  <option key={cred.id} value={cred.id}>
                    {cred.vcType[1] ?? cred.vcType[0]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Scope
              <select value={scope} onChange={(event) => setScope(event.target.value)} disabled>
                {SCOPES.map((scopeValue) => (
                  <option key={scopeValue} value={scopeValue}>
                    {scopeValue}
                  </option>
                ))}
              </select>
            </label>
            <div className="composer-actions">
              <button
                className="btn btn-primary"
                type="button"
                disabled={loading || !walletAccount || isIssuedAndActive}
                onClick={runProofPipeline}
              >
                {loading ? 'Generating...' : 'Issue'}
              </button>
              <button
                id="revoke"
                className="btn btn-danger"
                type="button"
                onClick={revoke}
                disabled={!isIssuedAndActive}
              >
                Revoke
              </button>
            </div>
          </div>
        </section>

        <section className="card card-flow">
          <div className="card-head">
            <h2>Delegation Flow</h2>
          </div>
          <div className="steps">
            {quickSteps.map(([label, done]) => (
              <div key={label} className="step">
                <span>{label}</span>
                <span className={`status ${done ? 'status-active' : 'status-pending'}`}>{done ? 'done' : 'pending'}</span>
              </div>
            ))}
          </div>
          <div className="step-actions step-actions-stacked">
            <button id="run-protected" className="btn" type="button" onClick={runProtected}>
              Run Protected Tx
            </button>
          </div>
        </section>

        <section className="card card-console">
          <div className="card-head">
            <h2>Runtime Logs</h2>
          </div>
          <div className="console" ref={consoleRef}>
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
