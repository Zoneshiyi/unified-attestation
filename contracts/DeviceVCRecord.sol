// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeviceVCRecord — 设备可验证凭证（VC）上链存储
/// @notice Verifier 在远程证明验证通过后，将 device_pubkey_hash 与 VC JSON 写入链上，
///         供 Relying Party 查询，实现去中心化的设备信任状态共享。
contract DeviceVCRecord {
    address public owner;

    struct VCEntry {
        string vcJson;
        uint256 timestamp;
    }

    /// device_pubkey_hash → VC 记录列表（按时间倒序，最新在前）
    mapping(bytes32 => VCEntry[]) private _vcs;

    event VCStored(bytes32 indexed devicePubkeyHash, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice 存储设备 VC。同一 pubkey hash 允许多次写入（过期后翻新），新记录追加到列表头部。
    /// @param devicePubkeyHash 设备公钥的 sha256 hex → bytes32
    /// @param vcJson W3C Verifiable Credential JSON 字符串
    function storeVC(bytes32 devicePubkeyHash, string calldata vcJson) external onlyOwner {
        _vcs[devicePubkeyHash].push(VCEntry({vcJson: vcJson, timestamp: block.timestamp}));
        emit VCStored(devicePubkeyHash, block.timestamp);
    }

    /// @notice 查询某设备的最新 VC
    /// @return vcJson 最新 VC JSON；无记录时返回空字符串
    /// @return timestamp 上链时间戳；无记录时返回 0
    function getVC(bytes32 devicePubkeyHash) external view returns (string memory vcJson, uint256 timestamp) {
        VCEntry[] storage entries = _vcs[devicePubkeyHash];
        if (entries.length == 0) {
            return ("", 0);
        }
        VCEntry storage latest = entries[entries.length - 1];
        return (latest.vcJson, latest.timestamp);
    }

    /// @notice 某设备的 VC 记录总数
    function vcCount(bytes32 devicePubkeyHash) external view returns (uint256) {
        return _vcs[devicePubkeyHash].length;
    }

    /// @notice 转移合约所有权
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
