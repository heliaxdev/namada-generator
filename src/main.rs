use chrono::DateTime;
use chrono::Utc;
use ibc::applications::transfer::msgs::transfer::MsgTransfer;
use ibc::applications::transfer::packet::PacketData;
use ibc::applications::transfer::Amount;
use ibc::applications::transfer::BaseDenom;
use ibc::applications::transfer::Memo;
use ibc::applications::transfer::PrefixedCoin;
use ibc::applications::transfer::PrefixedDenom;
use ibc::applications::transfer::TracePath;
use ibc::applications::transfer::TracePrefix;
use ibc::core::ics04_channel::timeout::TimeoutHeight;
use ibc::core::ics24_host::identifier::{ChannelId, PortId};
use ibc::core::timestamp::Timestamp;
use ibc::core::Msg;
use ibc::proto::Any;
use ibc::Height;
use ibc::Signer;
use namada_sdk::core::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, PGFTarget, ProposalType,
};
use namada_sdk::core::ledger::governance::storage::vote::{StorageProposalVote, VoteType};
use namada_sdk::core::proto::{Code, Commitment, Header, Section, Tx};
use namada_sdk::core::types::address::testing::arb_address;
use namada_sdk::core::types::address::Address;
use namada_sdk::core::types::chain::ChainId;
use namada_sdk::core::types::dec::Dec;
use namada_sdk::core::types::eth_bridge_pool::{
    GasFee, PendingTransfer, TransferToEthereum, TransferToEthereumKind,
};
use namada_sdk::core::types::ethereum_events::EthAddress;
use namada_sdk::core::types::hash;
use namada_sdk::core::types::key::testing::arb_keypair;
use namada_sdk::core::types::key::{common, ed25519, secp256k1, RefTo, SecretKey, SigScheme};
use namada_sdk::core::types::storage::Epoch;
use namada_sdk::core::types::time::DateTimeUtc;
use namada_sdk::core::types::token::testing::arb_amount;
use namada_sdk::core::types::token::Transfer;
use namada_sdk::core::types::token::{DenominatedAmount, Denomination};
use namada_sdk::core::types::transaction::account::{InitAccount, UpdateAccount};
use namada_sdk::core::types::transaction::governance::{InitProposalData, VoteProposalData};
use namada_sdk::core::types::transaction::pgf::UpdateStewardCommission;
use namada_sdk::core::types::transaction::pos::{
    Bond, CommissionChange, ConsensusKeyChange, InitValidator, MetaDataChange, Redelegation,
    Unbond, Withdraw,
};
use namada_sdk::core::types::transaction::{DecryptedTx, Fee, GasLimit, TxType, WrapperTx};
use namada_sdk::core::types::uint::{Uint, I256};
use namada_sdk::signing::to_ledger_vector;
use namada_sdk::tx::TX_BOND_WASM;
use namada_sdk::tx::TX_TRANSFER_WASM;
use namada_sdk::tx::{
    TX_BRIDGE_POOL_WASM, TX_CHANGE_COMMISSION_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
    TX_CHANGE_METADATA_WASM, TX_CLAIM_REWARDS_WASM, TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_INIT_VALIDATOR_WASM, TX_REACTIVATE_VALIDATOR_WASM,
    TX_REDELEGATE_WASM, TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM,
    TX_UPDATE_ACCOUNT_WASM, TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
};
use namada_sdk::wallet::fs::FsWalletUtils;
use proptest::collection;
use proptest::option;
use proptest::prelude::{Just, Strategy};
use proptest::prop_compose;
use proptest::strategy::ValueTree;
use proptest::test_runner::Reason;
use proptest::test_runner::TestRunner;
use prost::Message;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
// To facilitate propagating debugging information
pub enum TxData {
    CommissionChange(CommissionChange),
    ConsensusKeyChange(ConsensusKeyChange),
    MetaDataChange(MetaDataChange),
    ClaimRewards(Withdraw),
    DeactivateValidator(Address),
    InitAccount(InitAccount),
    InitProposal(InitProposalData),
    InitValidator(InitValidator),
    ReactivateValidator(Address),
    RevealPk(common::PublicKey),
    Unbond(Unbond),
    UnjailValidator(Address),
    UpdateAccount(UpdateAccount),
    VoteProposal(VoteProposalData),
    Withdraw(Withdraw),
    Transfer(Transfer),
    Bond(Bond),
    Redelegation(Redelegation),
    UpdateStewardCommission(UpdateStewardCommission),
    ResignSteward(Address),
    PendingTransfer(PendingTransfer),
    IbcAny(Any),
    Custom(Box<dyn std::fmt::Debug>),
}

prop_compose! {
    // Generate an arbitrary denomination
    pub fn arb_denomination()(denom in 0u8..) -> Denomination {
        Denomination(denom)
    }
}

prop_compose! {
    // Generate a denominated amount
    pub fn arb_denominated_amount()(
        amount in arb_amount(),
        denom in arb_denomination(),
    ) -> DenominatedAmount {
        DenominatedAmount::new(amount, denom)
    }
}

prop_compose! {
    // Generate a transfer
    pub fn arb_transfer()(
        source in arb_address(),
        target in arb_address(),
        token in arb_address(),
        amount in arb_denominated_amount(),
        key in option::of("[a-zA-Z0-9_]*"),
    ) -> Transfer {
        Transfer {
            source,
            target,
            token,
            amount,
            key,
            shielded: None,
        }
    }
}

prop_compose! {
    // Generate a bond
    pub fn arb_bond()(
        validator in arb_address(),
        amount in arb_amount(),
        source in option::of(arb_address()),
    ) -> Bond {
        Bond {
            validator,
            amount,
            source,
        }
    }
}

prop_compose! {
    // Generate an account initialization
    pub fn arb_init_account()(
        public_keys in collection::vec(arb_common_pk(), 0..10),
    )(
        threshold in 0..=public_keys.len() as u8,
        public_keys in Just(public_keys),
        vp_code_hash in arb_hash(),
    ) -> InitAccount {
        InitAccount {
            public_keys,
            vp_code_hash,
            threshold,
        }
    }
}

// Generate an arbitrary add or removal of what's generated by the supplied
// strategy
pub fn arb_add_remove<X: Strategy>(
    strategy: X,
) -> impl Strategy<Value = AddRemove<<X as Strategy>::Value>> {
    (0..2, strategy).prop_map(|(discriminant, val)| match discriminant {
        0 => AddRemove::Add(val),
        1 => AddRemove::Remove(val),
        _ => unreachable!(),
    })
}

prop_compose! {
    // Generate an arbitrary PGF target
    pub fn arb_pgf_target()(
        target in arb_address(),
        amount in arb_amount(),
    ) -> PGFTarget {
        PGFTarget {
            target,
            amount,
        }
    }
}

// Generate an arbitrary PGF action
pub fn arb_pgf_action() -> impl Strategy<Value = PGFAction> {
    arb_add_remove(arb_pgf_target())
        .prop_map(PGFAction::Continuous)
        .boxed()
        .prop_union(arb_pgf_target().prop_map(PGFAction::Retro).boxed())
}

// Generate an arbitrary proposal type
pub fn arb_proposal_type() -> impl Strategy<Value = ProposalType> {
    option::of(arb_hash())
        .prop_map(ProposalType::Default)
        .boxed()
        .prop_union(
            collection::hash_set(arb_add_remove(arb_address()), 0..10)
                .prop_map(ProposalType::PGFSteward)
                .boxed(),
        )
        .or(collection::vec(arb_pgf_action(), 0..10)
            .prop_map(ProposalType::PGFPayment)
            .boxed())
}

prop_compose! {
    // Generate a proposal initialization
    pub fn arb_init_proposal()(
        id: Option<u64>,
        content in arb_hash(),
        author in arb_address(),
        r#type in arb_proposal_type(),
        voting_start_epoch in arb_epoch(),
        voting_end_epoch in arb_epoch(),
        grace_epoch in arb_epoch(),
    ) -> InitProposalData {
        InitProposalData {
            id,
            content,
            author,
            r#type,
            voting_start_epoch,
            voting_end_epoch,
            grace_epoch,
        }
    }
}

prop_compose! {
    // Geerate an arbitrary vote type
    pub fn arb_vote_type()(discriminant in 0..3) -> VoteType {
        match discriminant {
            0 => VoteType::Default,
            1 => VoteType::PGFSteward,
            2 => VoteType::PGFPayment,
            _ => unreachable!(),
        }
    }
}

// Generate an arbitrary proposal vote
pub fn arb_proposal_vote() -> impl Strategy<Value = StorageProposalVote> {
    arb_vote_type()
        .prop_map(StorageProposalVote::Yay)
        .boxed()
        .prop_union(Just(StorageProposalVote::Nay).boxed())
        .or(Just(StorageProposalVote::Abstain).boxed())
}

prop_compose! {
    // Generate an arbitrary vote proposal
    pub fn arb_vote_proposal()(
        id: u64,
        vote in arb_proposal_vote(),
        voter in arb_address(),
        delegations in collection::vec(arb_address(), 0..10),
    ) -> VoteProposalData {
        VoteProposalData {
            id,
            vote,
            voter,
            delegations,
        }
    }
}

prop_compose! {
    // Generate an arbitrary account update
    pub fn arb_update_account()(
        public_keys in collection::vec(arb_common_pk(), 0..10),
    )(
        addr in arb_address(),
        vp_code_hash in option::of(arb_hash()),
        threshold in option::of(0..=public_keys.len() as u8),
        public_keys in Just(public_keys),
    ) -> UpdateAccount {
        UpdateAccount {
            addr,
            vp_code_hash,
            public_keys,
            threshold,
        }
    }
}

prop_compose! {
    // Generate an arbitrary withdraw
    pub fn arb_withdraw()(
        validator in arb_address(),
        source in option::of(arb_address()),
    ) -> Withdraw {
        Withdraw {
            validator,
            source,
        }
    }
}

prop_compose! {
    // Generate an arbitrary commission change
    pub fn arb_commission_change()(
        validator in arb_address(),
        new_rate in arb_dec(),
    ) -> CommissionChange {
        CommissionChange {
            validator,
            new_rate,
        }
    }
}

prop_compose! {
    // Generate an arbitrary metadata change
    pub fn arb_metadata_change()(
        validator in arb_address(),
        email in option::of("[a-zA-Z0-9_]*"),
        description in option::of("[a-zA-Z0-9_]*"),
        website in option::of("[a-zA-Z0-9_]*"),
        discord_handle in option::of("[a-zA-Z0-9_]*"),
        commission_rate in option::of(arb_dec()),
    ) -> MetaDataChange {
        MetaDataChange {
            validator,
            email,
            description,
            website,
            discord_handle,
            commission_rate,
        }
    }
}

prop_compose! {
    // Generate an arbitrary consensus key change
    pub fn arb_consensus_key_change()(
        validator in arb_address(),
        consensus_key in arb_common_pk(),
    ) -> ConsensusKeyChange {
        ConsensusKeyChange {
            validator,
            consensus_key,
        }
    }
}

prop_compose! {
    // Generate an arbitrary uint
    pub fn arb_uint()(value: [u64; 4]) -> Uint {
        Uint(value)
    }
}

prop_compose! {
    // Generate an arbitrary signed 256-bit integer
    pub fn arb_i256()(value in arb_uint()) -> I256 {
        I256(value)
    }
}

prop_compose! {
    // Generate an arbitrary decimal wih the native denomination
    pub fn arb_dec()(value in arb_i256()) -> Dec {
        Dec(value)
    }
}

prop_compose! {
    // Generate a validator initialization
    pub fn arb_init_validator()(
        account_keys in collection::vec(arb_common_pk(), 0..10),
    )(
        threshold in 0..=account_keys.len() as u8,
        account_keys in Just(account_keys),
        consensus_key in arb_common_pk(),
        eth_cold_key in arb_pk::<secp256k1::SigScheme>(),
        eth_hot_key in arb_pk::<secp256k1::SigScheme>(),
        protocol_key in arb_common_pk(),
        commission_rate in arb_dec(),
        max_commission_rate_change in arb_dec(),
        email in "[a-zA-Z0-9_]*",
        description in option::of("[a-zA-Z0-9_]*"),
        website in option::of("[a-zA-Z0-9_]*"),
        discord_handle in option::of("[a-zA-Z0-9_]*"),
        validator_vp_code_hash in arb_hash(),
    ) -> InitValidator {
        InitValidator {
            account_keys,
            threshold,
            consensus_key,
            eth_cold_key,
            eth_hot_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            email,
            description,
            website,
            discord_handle,
            validator_vp_code_hash,
        }
    }
}

prop_compose! {
    // Generate an arbitrary redelegation
    pub fn arb_redelegation()(
        src_validator in arb_address(),
        dest_validator in arb_address(),
        owner in arb_address(),
        amount in arb_amount(),
    ) -> Redelegation {
        Redelegation {
            src_validator,
            dest_validator,
            owner,
            amount,
        }
    }
}

prop_compose! {
    // Generate an arbitraary steward commission update
    pub fn arb_update_steward_commission()(
        steward in arb_address(),
        commission in collection::hash_map(arb_address(), arb_dec(), 0..10),
    ) -> UpdateStewardCommission {
        UpdateStewardCommission {
            steward,
            commission,
        }
    }
}

prop_compose! {
    // Generate the kind of a transfer to ethereum
    pub fn arb_transfer_to_ethereum_kind()(
        discriminant in 0..2,
    ) -> TransferToEthereumKind {
        match discriminant {
            0 => TransferToEthereumKind::Erc20,
            1 => TransferToEthereumKind::Nut,
            _ => unreachable!(),
        }
    }
}

prop_compose! {
    // Generate an arbitrary Ethereum address
    pub fn arb_eth_address()(bytes: [u8; 20]) -> EthAddress {
        EthAddress(bytes)
    }
}

prop_compose! {
    // Generate an arbitrary transfer to Ethereum
    pub fn arb_transfer_to_ethereum()(
        kind in arb_transfer_to_ethereum_kind(),
        asset in arb_eth_address(),
        recipient in arb_eth_address(),
        sender in arb_address(),
        amount in arb_amount(),
    ) -> TransferToEthereum {
        TransferToEthereum {
            kind,
            asset,
            recipient,
            sender,
            amount,
        }
    }
}

prop_compose! {
    // Generate an arbitrary Ethereum gas fee
    pub fn arb_gas_fee()(
        amount in arb_amount(),
        payer in arb_address(),
        token in arb_address(),
    ) -> GasFee {
        GasFee {
            amount,
            payer,
            token,
        }
    }
}

prop_compose! {
    // Generate an arbitrary pending transfer
    pub fn arb_pending_transfer()(
        transfer in arb_transfer_to_ethereum(),
        gas_fee in arb_gas_fee(),
    ) -> PendingTransfer {
        PendingTransfer {
            transfer,
            gas_fee,
        }
    }
}

prop_compose! {
    // Generate an arbitrary port ID
    pub fn arb_ibc_port_id()(id in "[a-zA-Z0-9_+.\\-\\[\\]#<>]{2,128}") -> PortId {
        PortId::new(id).expect("generated invalid port ID")
    }
}

prop_compose! {
    // Generate an arbitrary channel ID
    pub fn arb_ibc_channel_id()(id: u64) -> ChannelId {
        ChannelId::new(id)
    }
}

prop_compose! {
    // Generate an arbitrary IBC height
    pub fn arb_ibc_height()(
        revision_number: u64,
        revision_height in 1u64..,
    ) -> Height {
        Height::new(revision_number, revision_height)
            .expect("generated invalid IBC height")
    }
}

// Generate arbitrary timeout data
pub fn arb_ibc_timeout_data() -> impl Strategy<Value = TimeoutHeight> {
    arb_ibc_height()
        .prop_map(TimeoutHeight::At)
        .boxed()
        .prop_union(Just(TimeoutHeight::Never).boxed())
}

prop_compose! {
    // Generate an arbitrary IBC timestamp
    pub fn arb_ibc_timestamp()(nanoseconds: u64) -> Timestamp {
        Timestamp::from_nanoseconds(nanoseconds).expect("generated invalid IBC timestamp")
    }
}

prop_compose! {
    // Generate an arbitrary IBC memo
    pub fn arb_ibc_memo()(memo in "[a-zA-Z0-9_]*") -> Memo {
        memo.into()
    }
}

prop_compose! {
    // Generate an arbitrary IBC memo
    pub fn arb_ibc_signer()(signer in "[a-zA-Z0-9_]*") -> Signer {
        signer.into()
    }
}

prop_compose! {
    // Generate an arbitrary IBC trace prefix
    pub fn arb_ibc_trace_prefix()(
        port_id in arb_ibc_port_id(),
        channel_id in arb_ibc_channel_id(),
    ) -> TracePrefix {
        TracePrefix::new(port_id, channel_id)
    }
}

prop_compose! {
    // Generate an arbitrary IBC trace path
    pub fn arb_ibc_trace_path()(path in collection::vec(arb_ibc_trace_prefix(), 0..10)) -> TracePath {
        TracePath::from(path)
    }
}

prop_compose! {
    // Generate an arbitrary IBC base denomination
    pub fn arb_ibc_base_denom()(base_denom in "[a-zA-Z0-9_]+") -> BaseDenom {
        BaseDenom::from_str(&base_denom).expect("generated invalid IBC base denomination")
    }
}

prop_compose! {
    // Generate an arbitrary IBC prefixed denomination
    pub fn arb_ibc_prefixed_denom()(
        trace_path in arb_ibc_trace_path(),
        base_denom in arb_ibc_base_denom(),
    ) -> PrefixedDenom {
        PrefixedDenom {
            trace_path,
            base_denom,
        }
    }
}

prop_compose! {
    // Generate an arbitrary IBC amount
    pub fn arb_ibc_amount()(value: [u64; 4]) -> Amount {
        value.into()
    }
}

prop_compose! {
    // Generate an arbitrary prefixed coin
    pub fn arb_ibc_prefixed_coin()(
        denom in arb_ibc_prefixed_denom(),
        amount in arb_ibc_amount(),
    ) -> PrefixedCoin {
        PrefixedCoin {
            denom,
            amount,
        }
    }
}

prop_compose! {
    // Generate arbitrary packet data
    pub fn arb_ibc_packet_data()(
        token in arb_ibc_prefixed_coin(),
        sender in arb_ibc_signer(),
        receiver in arb_ibc_signer(),
        memo in arb_ibc_memo(),
    ) -> PacketData {
        PacketData {
            token,
            sender,
            receiver,
            memo,
        }
    }
}

prop_compose! {
    // Generate an arbitrary IBC transfer message
    pub fn arb_ibc_msg_transfer()(
        port_id_on_a in arb_ibc_port_id(),
        chan_id_on_a in arb_ibc_channel_id(),
        packet_data in arb_ibc_packet_data(),
        timeout_height_on_b in arb_ibc_timeout_data(),
        timeout_timestamp_on_b in arb_ibc_timestamp(),
    ) -> MsgTransfer {
        MsgTransfer {
            port_id_on_a,
            chan_id_on_a,
            packet_data,
            timeout_height_on_b,
            timeout_timestamp_on_b,
        }
    }
}

prop_compose! {
    // Generate an arbitrary IBC any object
    pub fn arb_ibc_any()(msg_transfer in arb_ibc_msg_transfer()) -> Any {
        msg_transfer.to_any()
    }
}

prop_compose! {
    // Generate an arbitrary commitment
    pub fn arb_commitment()(
        hash in arb_hash(),
    ) -> Commitment {
        Commitment::Hash(hash)
    }
}

prop_compose! {
    // Generate an arbitrary code section
    pub fn arb_code()(
        salt: [u8; 8],
        code in arb_commitment(),
        tag in option::of("[a-zA-Z0-9_]*"),
    ) -> Code {
        Code {
            salt,
            code,
            tag,
        }
    }
}

prop_compose! {
    // Generate a chain ID
    pub fn arb_chain_id()(id in "[a-zA-Z0-9_]*") -> ChainId {
        ChainId(id)
    }
}

prop_compose! {
    // Generate a date and time
    pub fn arb_date_time_utc()(
        secs in DateTime::<Utc>::MIN_UTC.timestamp()..=DateTime::<Utc>::MAX_UTC.timestamp(),
        nsecs in ..1000000000u32,
    ) -> DateTimeUtc {
        DateTimeUtc(DateTime::<Utc>::from_timestamp(secs, nsecs).unwrap())
    }
}

prop_compose! {
    // Generate an arbitrary fee
    pub fn arb_fee()(
        amount_per_gas_unit in arb_denominated_amount(),
        token in arb_address(),
    ) -> Fee {
        Fee {
            amount_per_gas_unit,
            token,
        }
    }
}

prop_compose! {
    // Generate an arbitrary epoch
    pub fn arb_epoch()(epoch: u64) -> Epoch {
        Epoch(epoch)
    }
}

// Generate an arbitrary public key
pub fn arb_pk<S: SigScheme>() -> impl Strategy<Value = <S::SecretKey as SecretKey>::PublicKey> {
    arb_keypair::<S>().prop_map(|x| x.ref_to())
}

// Generate an arbitrary common key
pub fn arb_common_pk() -> impl Strategy<Value = common::PublicKey> {
    let ed25519 = arb_pk::<ed25519::SigScheme>()
        .prop_map(common::PublicKey::Ed25519)
        .sboxed();
    let secp256k1 = arb_pk::<secp256k1::SigScheme>()
        .prop_map(common::PublicKey::Secp256k1)
        .sboxed();
    ed25519.prop_union(secp256k1)
}

prop_compose! {
    // Generate an arbitrary gas limit
    pub fn arb_gas_limit()(multiplier: u64) -> GasLimit {
        multiplier.into()
    }
}

prop_compose! {
    // Generate an arbitrary hash
    pub fn arb_hash()(bytes: [u8; 32]) -> hash::Hash {
        hash::Hash(bytes)
    }
}

prop_compose! {
    // Generate an arbitrary wrapper transaction
    pub fn arb_wrapper_tx()(
        fee in arb_fee(),
        epoch in arb_epoch(),
        pk in arb_common_pk(),
        gas_limit in arb_gas_limit(),
        unshield_section_hash in option::of(arb_hash()),
    ) -> WrapperTx {
        WrapperTx {
            fee,
            epoch,
            pk,
            gas_limit,
            unshield_section_hash,
        }
    }
}

prop_compose! {
    // Generate an arbitrary decrypted transaction
    pub fn arb_decrypted_tx()(discriminant in 0..2) -> DecryptedTx {
        match discriminant {
            0 => DecryptedTx::Decrypted,
            1 => DecryptedTx::Undecryptable,
            _ => unreachable!(),
        }
    }
}

// Generate an arbitrary transaction type
pub fn arb_tx_type() -> impl Strategy<Value = TxType> {
    let raw_tx = Just(TxType::Raw).boxed();
    let decrypted_tx = arb_decrypted_tx().prop_map(TxType::Decrypted).boxed();
    let wrapper_tx = arb_wrapper_tx()
        .prop_map(|x| TxType::Wrapper(Box::new(x)))
        .boxed();
    raw_tx.prop_union(decrypted_tx).or(wrapper_tx)
}

prop_compose! {
    // Generate an arbitrary header
    pub fn arb_header()(
        chain_id in arb_chain_id(),
        expiration in option::of(arb_date_time_utc()),
        timestamp in arb_date_time_utc(),
        code_hash in arb_hash(),
        data_hash in arb_hash(),
        tx_type in arb_tx_type(),
    ) -> Header {
        Header {
            chain_id,
            expiration,
            timestamp,
            data_hash,
            code_hash,
            tx_type,
        }
    }
}

prop_compose! {
    // Generate an arbitrary transfer transaction
    pub fn arb_transfer_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        transfer in arb_transfer(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(transfer.clone());
        tx.add_code_from_hash(code_hash, Some(TX_TRANSFER_WASM.to_owned()));
        (tx, TxData::Transfer(transfer))
    }
}

prop_compose! {
    // Generate an arbitrary bond transaction
    pub fn arb_bond_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        bond in arb_bond(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(bond.clone());
        tx.add_code_from_hash(code_hash, Some(TX_BOND_WASM.to_owned()));
        (tx, TxData::Bond(bond))
    }
}

prop_compose! {
    // Generate an arbitrary bond transaction
    pub fn arb_unbond_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        unbond in arb_bond(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(unbond.clone());
        tx.add_code_from_hash(code_hash, Some(TX_UNBOND_WASM.to_owned()));
        (tx, TxData::Unbond(unbond))
    }
}

prop_compose! {
    // Generate an arbitrary account initialization transaction
    pub fn arb_init_account_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        mut init_account in arb_init_account(),
        extra_data in arb_code(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        let vp_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
        init_account.vp_code_hash = vp_code_hash;
        tx.add_data(init_account.clone());
        tx.add_code_from_hash(code_hash, Some(TX_INIT_ACCOUNT_WASM.to_owned()));
        (tx, TxData::InitAccount(init_account))
    }
}

prop_compose! {
    // Generate an arbitrary account initialization transaction
    pub fn arb_init_validator_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        mut init_validator in arb_init_validator(),
        extra_data in arb_code(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        let vp_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
        init_validator.validator_vp_code_hash = vp_code_hash;
        tx.add_data(init_validator.clone());
        tx.add_code_from_hash(code_hash, Some(TX_INIT_VALIDATOR_WASM.to_owned()));
        (tx, TxData::InitValidator(init_validator))
    }
}

prop_compose! {
    // Generate an arbitrary proposal initialization transaction
    pub fn arb_init_proposal_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        mut init_proposal in arb_init_proposal(),
        content_extra_data in arb_code(),
        type_extra_data in arb_code(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        let content_hash = tx.add_section(Section::ExtraData(content_extra_data)).get_hash();
        init_proposal.content = content_hash;
        if let ProposalType::Default(Some(hash)) = &mut init_proposal.r#type {
            let type_hash = tx.add_section(Section::ExtraData(type_extra_data)).get_hash();
            *hash = type_hash;
        }
        tx.add_data(init_proposal.clone());
        tx.add_code_from_hash(code_hash, Some(TX_INIT_PROPOSAL.to_owned()));
        (tx, TxData::InitProposal(init_proposal))
    }
}

prop_compose! {
    // Generate an arbitrary vote proposal transaction
    pub fn arb_vote_proposal_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        vote_proposal in arb_vote_proposal(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(vote_proposal.clone());
        tx.add_code_from_hash(code_hash, Some(TX_VOTE_PROPOSAL.to_owned()));
        (tx, TxData::VoteProposal(vote_proposal))
    }
}

prop_compose! {
    // Generate an arbitrary reveal public key transaction
    pub fn arb_reveal_pk_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        pk in arb_common_pk(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(pk.clone());
        tx.add_code_from_hash(code_hash, Some(TX_REVEAL_PK.to_owned()));
        (tx, TxData::RevealPk(pk))
    }
}

prop_compose! {
    // Generate an arbitrary account initialization transaction
    pub fn arb_update_account_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        mut update_account in arb_update_account(),
        extra_data in arb_code(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        if let Some(vp_code_hash) = &mut update_account.vp_code_hash {
            let new_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
            *vp_code_hash = new_code_hash;
        }
        tx.add_data(update_account.clone());
        tx.add_code_from_hash(code_hash, Some(TX_UPDATE_ACCOUNT_WASM.to_owned()));
        (tx, TxData::UpdateAccount(update_account))
    }
}

prop_compose! {
    // Generate an arbitrary reveal public key transaction
    pub fn arb_withdraw_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        withdraw in arb_withdraw(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(withdraw.clone());
        tx.add_code_from_hash(code_hash, Some(TX_WITHDRAW_WASM.to_owned()));
        (tx, TxData::Withdraw(withdraw))
    }
}

prop_compose! {
    // Generate an arbitrary claim rewards transaction
    pub fn arb_claim_rewards_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        claim_rewards in arb_withdraw(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(claim_rewards.clone());
        tx.add_code_from_hash(code_hash, Some(TX_CLAIM_REWARDS_WASM.to_owned()));
        (tx, TxData::ClaimRewards(claim_rewards))
    }
}

prop_compose! {
    // Generate an arbitrary commission change transaction
    pub fn arb_commission_change_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        commission_change in arb_commission_change(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(commission_change.clone());
        tx.add_code_from_hash(code_hash, Some(TX_CHANGE_COMMISSION_WASM.to_owned()));
        (tx, TxData::CommissionChange(commission_change))
    }
}

prop_compose! {
    // Generate an arbitrary commission change transaction
    pub fn arb_metadata_change_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        metadata_change in arb_metadata_change(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(metadata_change.clone());
        tx.add_code_from_hash(code_hash, Some(TX_CHANGE_METADATA_WASM.to_owned()));
        (tx, TxData::MetaDataChange(metadata_change))
    }
}

prop_compose! {
    // Generate an arbitrary unjail validator transaction
    pub fn arb_unjail_validator_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        address in arb_address(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(address.clone());
        tx.add_code_from_hash(code_hash, Some(TX_UNJAIL_VALIDATOR_WASM.to_owned()));
        (tx, TxData::UnjailValidator(address))
    }
}

prop_compose! {
    // Generate an arbitrary deactivate validator transaction
    pub fn arb_deactivate_validator_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        address in arb_address(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(address.clone());
        tx.add_code_from_hash(code_hash, Some(TX_DEACTIVATE_VALIDATOR_WASM.to_owned()));
        (tx, TxData::DeactivateValidator(address))
    }
}

prop_compose! {
    // Generate an arbitrary reactivate validator transaction
    pub fn arb_reactivate_validator_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        address in arb_address(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(address.clone());
        tx.add_code_from_hash(code_hash, Some(TX_REACTIVATE_VALIDATOR_WASM.to_owned()));
        (tx, TxData::ReactivateValidator(address))
    }
}

prop_compose! {
    // Generate an arbitrary consensus key change transaction
    pub fn arb_consensus_key_change_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        consensus_key_change in arb_consensus_key_change(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(consensus_key_change.clone());
        tx.add_code_from_hash(code_hash, Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_owned()));
        (tx, TxData::ConsensusKeyChange(consensus_key_change))
    }
}

prop_compose! {
    // Generate an arbitrary redelegation transaction
    pub fn arb_redelegation_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        redelegation in arb_redelegation(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(redelegation.clone());
        tx.add_code_from_hash(code_hash, Some(TX_REDELEGATE_WASM.to_owned()));
        (tx, TxData::Redelegation(redelegation))
    }
}

prop_compose! {
    // Generate an arbitrary redelegation transaction
    pub fn arb_update_steward_commission_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        update_steward_commission in arb_update_steward_commission(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(update_steward_commission.clone());
        tx.add_code_from_hash(code_hash, Some(TX_UPDATE_STEWARD_COMMISSION.to_owned()));
        (tx, TxData::UpdateStewardCommission(update_steward_commission))
    }
}

prop_compose! {
    // Generate an arbitrary redelegation transaction
    pub fn arb_resign_steward_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        steward in arb_address(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(steward.clone());
        tx.add_code_from_hash(code_hash, Some(TX_RESIGN_STEWARD.to_owned()));
        (tx, TxData::ResignSteward(steward))
    }
}

prop_compose! {
    // Generate an arbitrary pending transfer transaction
    pub fn arb_pending_transfer_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        pending_transfer in arb_pending_transfer(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        tx.add_data(pending_transfer.clone());
        tx.add_code_from_hash(code_hash, Some(TX_BRIDGE_POOL_WASM.to_owned()));
        (tx, TxData::PendingTransfer(pending_transfer))
    }
}

prop_compose! {
    // Generate an arbitrary IBC any transaction
    pub fn arb_ibc_any_tx()(
        mut header in arb_header(),
        wrapper in arb_wrapper_tx(),
        ibc_any in arb_ibc_any(),
        code_hash in arb_hash(),
    ) -> (Tx, TxData) {
        header.tx_type = TxType::Wrapper(Box::new(wrapper));
        let mut tx = Tx { header, sections: vec![] };
        let mut tx_data = vec![];
        ibc_any.encode(&mut tx_data).expect("unable to encode IBC data");
        tx.add_serialized_data(tx_data);
        tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
        (tx, TxData::IbcAny(ibc_any))
    }
}

// Generate an arbitrary tx
pub fn arb_tx() -> impl Strategy<Value = (Tx, TxData)> {
    arb_transfer_tx()
        .boxed()
        .prop_union(arb_bond_tx().boxed())
        .or(arb_unbond_tx().boxed())
        .or(arb_init_account_tx().boxed())
        .or(arb_init_validator_tx().boxed())
        .or(arb_init_proposal_tx().boxed())
        .or(arb_vote_proposal_tx().boxed())
        .or(arb_reveal_pk_tx().boxed())
        .or(arb_update_account_tx().boxed())
        .or(arb_withdraw_tx().boxed())
        .or(arb_claim_rewards_tx().boxed())
        .or(arb_commission_change_tx().boxed())
        .or(arb_metadata_change_tx().boxed())
        .or(arb_unjail_validator_tx().boxed())
        .or(arb_deactivate_validator_tx().boxed())
        .or(arb_reactivate_validator_tx().boxed())
        .or(arb_consensus_key_change_tx().boxed())
        .or(arb_redelegation_tx().boxed())
        .or(arb_update_steward_commission_tx().boxed())
        .or(arb_resign_steward_tx().boxed())
        .or(arb_pending_transfer_tx().boxed())
        .or(arb_ibc_any_tx().boxed())
}

#[tokio::main]
async fn main() -> Result<(), Reason> {
    let mut runner = TestRunner::default();
    let wallet = FsWalletUtils::new(PathBuf::from("wallet.toml"));
    let mut debug_vectors = vec![];
    let mut test_vectors = vec![];
    for i in 0..1000 {
        let (tx, tx_data) = arb_tx().new_tree(&mut runner)?.current();
        let mut ledger_vector = to_ledger_vector(&wallet, &tx)
            .await
            .expect("unable to construct test vector");
        ledger_vector.name = format!("{}_{}", i, ledger_vector.name);
        test_vectors.push(ledger_vector.clone());
        debug_vectors.push((ledger_vector, tx, tx_data));
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: namada-generator <vectors.json> <debugs.txt>");
        return Result::Err(Reason::from("Incorrect command line arguments."));
    }
    let json = serde_json::to_string(&test_vectors).expect("unable to serialize test vectors");
    std::fs::write(&args[1], json).expect("unable to save test vectors");
    std::fs::write(&args[2], format!("{:?}", debug_vectors)).expect("unable to save test vectors");
    Ok(())
}
