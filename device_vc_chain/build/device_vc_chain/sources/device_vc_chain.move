module device_vc_chain::device_vc_chain {
    use std::string::String;

    public struct DeviceVCRecord has key, store {
        id: iota::object::UID,
        device_pubkey_hash: String,
        vc_json: String,
    }

    public entry fun store_vc(
        device_pubkey_hash: String,
        vc_json: String,
        ctx: &mut iota::tx_context::TxContext,
    ) {
        let record = DeviceVCRecord {
            id: iota::object::new(ctx),
            device_pubkey_hash,
            vc_json,
        };
        iota::transfer::public_transfer(record, iota::tx_context::sender(ctx));
    }

    public fun device_pubkey_hash(record: &DeviceVCRecord): &String {
        &record.device_pubkey_hash
    }

    public fun vc_json(record: &DeviceVCRecord): &String {
        &record.vc_json
    }
}
