# OPNet Contract Audit Cheatsheet

## Critical Checks (Deployment Failures)
1. **super.onDeployment(calldata)** -- ALL subclasses of OP_NET, OP20, OP721, ReentrancyGuard MUST call super.onDeployment(calldata) first
2. **Address.fromString()** -- ALWAYS needs 2 params: (mldsaHash, tweakedPubkey). Single-param creates malformed Address
3. **Selectors** -- OPNet uses SHA256 first 4 bytes, NOT EVM Keccak256. Use encodeSelector() from btc-runtime
   - Known OPNet selectors: transfer=0x3b88ef57, balanceOf=0x5b46f8f6, increaseAllowance=0x8d645723
   - Known EVM selectors (WRONG): transfer=0xa9059cbb, approve=0x095ea7b3, balanceOf=0x70a08231
4. **approve vs increaseAllowance** -- OPNet OP20 uses increaseAllowance(), NOT approve()
5. **StoredU256 initialization** -- Use (pointer, EMPTY_POINTER) not (pointer, u256.Zero). EMPTY_POINTER is Uint8Array

## High Checks (Security)
6. **CEI Pattern** -- Update state BEFORE making Blockchain.call(). External calls at END of method
7. **SafeMath** -- ALL u256 arithmetic must use SafeMath.add/sub/mul/div. No raw operators
8. **No while loops** -- Use bounded for loops only. While loops can be infinite in WASM
9. **ReentrancyGuard** -- Any contract making Blockchain.call() should extend ReentrancyGuard
10. **onlyDeployer** -- Admin functions MUST check this.onlyDeployer(Blockchain.tx.sender)

## Medium Checks (Correctness)  
11. **Calldata validation** -- Every readAddress/readU256 result should be validated (isZero check)
12. **Blockchain.call return** -- Always check the return value. Failed calls can silently continue
13. **Pointer uniqueness** -- Every storage pointer must be unique. Collision = data corruption
14. **Event emission** -- State changes should emit events for indexing
15. **BytesWriter size** -- Pre-allocate correct size. Too small = truncation. Too large = waste

## OPNet-Specific Rules
16. **No CREATE/CREATE2** -- OPNet contracts cannot deploy other contracts. Use multi-tenant pattern
17. **CSV timelocks** -- All swap recipient addresses MUST use CheckSequenceVerify
18. **Constructor runs every call** -- Storage field initialization happens every interaction. Use onDeployment() for one-time init
19. **Blockchain.nextPointer** -- Auto-incrementing u16. Don't hardcode pointer values
20. **Cross-contract calls** -- Use BytesWriter with writeSelector() + writeAddress/writeU256, then Blockchain.call()

## Deploy Script Checks
21. **BinaryWriter.writeAddress()** -- Pass Address objects, NOT raw Uint8Array/hex bytes
22. **UTXO fetch** -- Always use optimize: false
23. **Mnemonic constructor** -- (phrase, passphrase, network, securityLevel) -- network is 3rd param
24. **linkMLDSAPublicKeyToAddress: true** -- Required in deployment params
25. **revealMLDSAPublicKey: true** -- Required in deployment params

## Common Pitfalls from Real Audits
- Maze pill.fun: 6 EVM selectors, approve() instead of increaseAllowance(), single-param Address.fromString
- Danny ordinals-bridge: Express instead of hyper-express, mnemonic in env vars, unauthenticated endpoints
- $SKIZO: ABIDataTypes not importable (injected by transform), u64 overflow in u256.fromU64()
- OpFlash: BigInt serialization in JSON.stringify (provider.getBlock returns BigInt, must convert to Number)
