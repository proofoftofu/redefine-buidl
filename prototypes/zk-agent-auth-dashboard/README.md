# zk-agent-auth-dashboard prototype

Rich frontend prototype for anonymous credential delegation UX.

## Run

```bash
cd prototypes/zk-agent-auth-dashboard
npm test
npm run start
```

Then open `http://localhost:4173`.

## Quick Test Flow

1. Generate Burner Agent
2. Delegate
3. Run Protected Tx
4. Revoke
5. Run Again (should fail)

## Notes

- This is a UI/logic prototype with mock verifier outcomes wired through a deterministic state machine.
- No live Starknet RPC calls are included in this prototype.
