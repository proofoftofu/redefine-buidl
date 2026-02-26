use starknet::ContractAddress;

#[derive(Copy, Drop, Serde)]
pub struct PublicInputs {
    issuer_pubkey: felt252,
    current_day: u64,
    min_age_days: u64,
    agent_key: felt252,
    scope_hash: felt252,
    nullifier: felt252,
}

#[starknet::interface]
pub trait INoirVerifier<TContractState> {
    fn verify(self: @TContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool;
}

#[starknet::interface]
pub trait IZkAgentAuthVerifier<TContractState> {
    fn verify_and_consume(
        ref self: TContractState,
        proof: Span<felt252>,
        public_inputs: PublicInputs,
    ) -> bool;

    fn is_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;
}

#[starknet::contract]
mod ZkAgentAuthVerifier {
    use starknet::get_block_timestamp;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::{
        ContractAddress, INoirVerifierDispatcher, INoirVerifierDispatcherTrait, PublicInputs,
    };

    #[storage]
    struct Storage {
        verifier: ContractAddress,
        nullifier_used: Map<felt252, bool>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, verifier: ContractAddress) {
        self.verifier.write(verifier);
    }

    fn as_public_inputs_array(public_inputs: PublicInputs) -> Array<felt252> {
        let mut arr = array![];
        arr.append(public_inputs.issuer_pubkey);
        arr.append(public_inputs.current_day.into());
        arr.append(public_inputs.min_age_days.into());
        arr.append(public_inputs.agent_key);
        arr.append(public_inputs.scope_hash);
        arr.append(public_inputs.nullifier);
        arr
    }

    #[abi(embed_v0)]
    impl ZkAgentAuthVerifierImpl of super::IZkAgentAuthVerifier<ContractState> {
        fn verify_and_consume(
            ref self: ContractState,
            proof: Span<felt252>,
            public_inputs: PublicInputs,
        ) -> bool {
            if self.nullifier_used.read(public_inputs.nullifier) {
                return false;
            }

            let block_day: u64 = get_block_timestamp() / 86400;
            if public_inputs.current_day != block_day {
                return false;
            }

            let verifier_addr = self.verifier.read();
            let verifier = INoirVerifierDispatcher { contract_address: verifier_addr };
            let ok = verifier.verify(proof, as_public_inputs_array(public_inputs).span());
            if !ok {
                return false;
            }

            self.nullifier_used.write(public_inputs.nullifier, true);
            true
        }

        fn is_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifier_used.read(nullifier)
        }
    }
}
