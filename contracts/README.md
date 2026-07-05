# DeviceVCRecord 合约部署说明

## 前置条件

- [Foundry](https://book.getfoundry.sh/) 工具链：`forge`, `cast`
- EVM 兼容链的 RPC 端点
- 部署用私钥（需有 gas token）

## 部署

```bash
# 设置环境变量
export RPC_URL=<链 RPC 地址>
export PRIVATE_KEY=<部署者私钥>

# 部署合约
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  contracts/DeviceVCRecord.sol:DeviceVCRecord
```

部署完成后会输出合约地址（`Deployed to: 0x...`），该地址用于 verifier 配置中的 `CHAIN_CONTRACT_ADDRESS`。

## 交互示例

```bash
# 查询某设备的最新 VC（pubkey_hash 需转为 bytes32 hex）
cast call <CONTRACT_ADDRESS> \
  "getVC(bytes32)(string,uint256)" \
  <DEVICE_PUBKEY_HASH>

# 查询某设备的 VC 记录数
cast call <CONTRACT_ADDRESS> \
  "vcCount(bytes32)" \
  <DEVICE_PUBKEY_HASH>

# 查看 VCStored 事件
cast logs --address <CONTRACT_ADDRESS> \
  "VCStored(bytes32,uint256)"
```
