install-bun:
	curl -fsSL https://bun.sh/install | bash

install-noir:
	curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
	noirup --version 1.0.0-beta.16

install-barretenberg:
	curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
	bbup --version 3.0.0-nightly.20251104

install-starknet:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.starkup.dev | sh

install-devnet:
	asdf plugin add starknet-devnet
	asdf install starknet-devnet 0.6.1

install-garaga:
	pip install garaga==1.0.1

install-app-deps:
	cd app && bun install

devnet:
	starknet-devnet --accounts=2 --seed=0 --initial-balance=100000000000000000000000

accounts-file:
	curl -s -X POST -H "Content-Type: application/json" \
		--data '{"jsonrpc":"2.0","id":"1","method":"devnet_getPredeployedAccounts"}' http://127.0.0.1:5050/ \
		| jq '{"alpha-sepolia": {"devnet0": {\
			address: .result[0].address, \
			private_key: .result[0].private_key, \
			public_key: .result[0].public_key, \
			class_hash: "0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", \
			deployed: true, \
			legacy: false, \
			salt: "0x14", \
			type: "open_zeppelin"\
		}}}' > ./contracts/accounts.json

build-circuit:
	cd circuit && nargo build

exec-circuit:
	cd circuit && nargo execute witness

gen-vk:
	bb write_vk --scheme ultra_honk --oracle_hash keccak -b ./circuit/target/delegation_proof.json -o ./circuit/target

gen-verifier:
	cd contracts && garaga gen --system ultra_keccak_zk_honk --vk ../circuit/target/vk --project-name verifier

build-contracts:
	cd contracts && scarb build

declare-verifier:
	cd contracts && sncast declare --contract-name UltraKeccakZKHonkVerifier

deploy-verifier:
	# Set VERIFIER_CLASS_HASH from make declare-verifier output
	cd contracts && sncast deploy --salt 0x00 --class-hash $$VERIFIER_CLASS_HASH

declare-noir-adapter:
	cd contracts && sncast declare --contract-name NoirVerifierAdapter

deploy-noir-adapter:
	# Set NOIR_ADAPTER_CLASS_HASH and VERIFIER_CONTRACT_ADDRESS
	cd contracts && sncast deploy --class-hash $$NOIR_ADAPTER_CLASS_HASH --constructor-calldata $$VERIFIER_CONTRACT_ADDRESS

declare-zk-auth:
	cd contracts && sncast declare --contract-name ZkAgentAuthVerifier

deploy-zk-auth:
	# Set ZK_AUTH_CLASS_HASH and NOIR_ADAPTER_CONTRACT_ADDRESS
	cd contracts && sncast deploy --class-hash $$ZK_AUTH_CLASS_HASH --constructor-calldata $$NOIR_ADAPTER_CONTRACT_ADDRESS

artifacts:
	cp ./circuit/target/delegation_proof.json ./app/src/assets/circuit.json
	cp ./circuit/target/vk ./app/src/assets/vk.bin
	cp ./contracts/target/release/verifier_UltraKeccakZKHonkVerifier.contract_class.json ./app/src/assets/verifier.json

run-app:
	cd app && bun run dev
