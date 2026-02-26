# zk-agent-auth root app

This root workspace now combines:
- `circuit/` from `prototypes/noir/delegation_proof`
- `contracts/` from `prototypes/scaffold-garaga` plus app contracts:
  - `noir_verifier_adapter`
  - `zk_agent_auth_verifier`
- `app/` from `prototypes/scaffold-garaga/app` with `zk-agent-auth-dashboard` frontend design and integrated proof flow

## Project layout

- `app/`: Vite + React dashboard UI that generates Noir proofs in-browser and verifies them on Starknet
- `circuit/`: delegation proof Noir circuit
- `contracts/verifier/`: Garaga-generated UltraHonk verifier
- `contracts/noir_verifier_adapter/`: adapter exposing `verify(proof, public_inputs) -> bool`
- `contracts/zk_agent_auth_verifier/`: app contract with nullifier replay protection and `verify_and_consume`

## Run end-to-end

1. Install dependencies/tools (one-time):
```sh
make install-bun
make install-noir
make install-barretenberg
make install-starknet
make install-devnet
make install-garaga
```

2. Build circuit, witness, vk, and contracts:
```sh
make build-circuit
make exec-circuit
make gen-vk
make gen-verifier
make build-contracts
```

3. Start devnet in another terminal:
```sh
make devnet
```

4. Prepare accounts and deploy contracts (new terminal):
```sh
make accounts-file

make declare-verifier
# export VERIFIER_CLASS_HASH=0x... from command output
make deploy-verifier
# export VERIFIER_CONTRACT_ADDRESS=0x... from command output

make declare-noir-adapter
# export NOIR_ADAPTER_CLASS_HASH=0x...
make deploy-noir-adapter
# export NOIR_ADAPTER_CONTRACT_ADDRESS=0x...

make declare-zk-auth
# export ZK_AUTH_CLASS_HASH=0x...
make deploy-zk-auth
```

5. Copy generated artifacts to frontend:
```sh
make artifacts
```

6. Configure app env:
```sh
cp app/.env.example app/.env
```
Set:
- `VITE_STARKNET_RPC_URL`
- `VITE_VERIFIER_CONTRACT_ADDRESS` (fallback stateless verifier)
- `VITE_ZK_AGENT_AUTH_CONTRACT_ADDRESS` (recommended app contract)
- `VITE_INVOKER_ACCOUNT_ADDRESS` (optional; required for real nullifier consumption)
- `VITE_INVOKER_PRIVATE_KEY` (optional; devnet key for invoker account)

7. Run frontend:
```sh
make install-app-deps
make run-app
```

Open `http://localhost:5173`.

## Notes

- `verify_and_consume` enforces `current_day == block_day`, so run proof generation and verification on the same day.
- The frontend computes valid demo signatures and nullifiers matching the circuit hash logic.
- If `VITE_ZK_AGENT_AUTH_CONTRACT_ADDRESS` is empty, the app falls back to stateless verification with `UltraKeccakZKHonkVerifier`.
- If invoker credentials are set, `verify_and_consume` is sent as an onchain transaction (stateful nullifier write). Without invoker credentials, the app uses read-only `call` for verification only.
