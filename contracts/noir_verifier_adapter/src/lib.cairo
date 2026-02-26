use starknet::ContractAddress;

#[starknet::interface]
pub trait INoirVerifier<TContractState> {
    fn verify(self: @TContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool;
}

#[starknet::contract]
mod NoirVerifierAdapter {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::call_contract_syscall;
    use super::{ContractAddress, INoirVerifier};

    const VERIFY_SELECTOR: felt252 = selector!("verify_ultra_keccak_zk_honk_proof");

    #[storage]
    struct Storage {
        verifier: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, verifier: ContractAddress) {
        self.verifier.write(verifier);
    }

    #[abi(embed_v0)]
    impl NoirVerifierAdapterImpl of INoirVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            let _ = public_inputs;

            let mut calldata = array![];
            calldata.append(proof.len().into());
            for felt in proof {
                calldata.append(*felt);
            }

            let response = call_contract_syscall(
                self.verifier.read(), VERIFY_SELECTOR, calldata.span(),
            );
            match response {
                Result::Ok(result_data) => {
                    if result_data.len() == 0 {
                        return false;
                    }
                    let result_tag = *result_data.at(0);
                    result_tag == 0
                },
                Result::Err(_) => false,
            }
        }
    }
}
