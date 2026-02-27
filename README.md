# zk-agent-auth root app

## Live App

https://redefine-buidl.vercel.app/

## Demo

https://youtu.be/DhcxXuy9BWw

## Description

Anonymous AI Agent Credentials is a privacy-first identity layer for Starknet AI agents.

It addresses a core problem: most AI agents can execute actions, but they do not carry a portable, verifiable identity. Without identity, contracts cannot reliably gate access for specific agent capabilities.

This project combines W3C Verifiable Credential concepts with zero-knowledge proofs so agents can prove policy compliance without exposing sensitive attributes. The result is private, composable, on-chain authorization for autonomous agents.

## How it works

1. Connect wallet and prepare agent
A user connects a Starknet wallet (Ready / Argent) and generates a local burner agent identity. The burner account is funded and deployed for autonomous execution.

2. Build an off-chain delegation package
The app prepares VC-derived inputs and generates a zero-knowledge proof package off-chain. Private attributes stay private; only required public inputs are exposed.

3. Prove policy compliance in ZK
The circuit (built in Noir) proves that policy conditions are satisfied (for example membership/age/expiry constraints), issuer signature relation is valid for the credential commitment, and nullifier is correctly derived and bound to agent + scope.

4. Verify and consume on-chain
The burner agent submits `verify_and_consume` to the auth verifier contract on Starknet. The contract enforces replay protection via nullifier checks, matches the day against on-chain block time, and requires the underlying proof verification to pass. On success, nullifier is consumed and the protected action is authorized.

5. Developer stack
Noir is used for policy logic and private-proof constraints, Garaga is used for Starknet-compatible verifier generation, and Starknet contracts handle verification orchestration and nullifier state.

## Why this matters

This pattern can bridge VC-based identity wallets to AI agents, enabling trusted machine identities that are privacy-preserving, verifiable, and reusable across on-chain applications.
