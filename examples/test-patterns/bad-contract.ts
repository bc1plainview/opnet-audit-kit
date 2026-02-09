import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    encodeSelector,
    OP_NET,
    Revert,
    SafeMath,
    Selector,
    StoredAddress,
    StoredBoolean,
    StoredU256,
    EMPTY_POINTER,
} from '@btc-vision/btc-runtime/runtime';
import { CallResult } from '@btc-vision/btc-runtime/runtime/env/BlockchainEnvironment';

/**
 * A deliberately BAD contract that should trigger MANY findings.
 * Used for testing the opnet-analyzer tool.
 */
@final
export class BadToken extends OP_NET {
    // BUG: EVM selector for transfer (should be 0x3b88ef57)
    private readonly transferSelector: u32 = 0xa9059cbb;

    // BUG: EVM selector for balanceOf (should be 0x5b46f8f6)
    private readonly balanceOfSelector: u32 = 0x70a08231;

    // BUG: EVM selector for approve (should use increaseAllowance)
    private readonly approveSelector: Selector = encodeSelector('approve');

    // Storage pointers - using Blockchain.nextPointer
    private readonly totalSupplyPointer: u16 = Blockchain.nextPointer;
    private readonly balancesPointer: u16 = Blockchain.nextPointer;
    private readonly allowancesPointer: u16 = Blockchain.nextPointer;
    private readonly ownerPointer: u16 = Blockchain.nextPointer;
    private readonly namePointer: u16 = Blockchain.nextPointer;
    private readonly symbolPointer: u16 = Blockchain.nextPointer;
    private readonly decimalsPointer: u16 = Blockchain.nextPointer;
    private readonly pausedPointer: u16 = Blockchain.nextPointer;
    private readonly minterPointer: u16 = Blockchain.nextPointer;
    private readonly burnerPointer: u16 = Blockchain.nextPointer;
    private readonly feePointer: u16 = Blockchain.nextPointer;
    private readonly feeRecipientPointer: u16 = Blockchain.nextPointer;
    private readonly maxSupplyPointer: u16 = Blockchain.nextPointer;
    private readonly mintCountPointer: u16 = Blockchain.nextPointer;
    private readonly burnCountPointer: u16 = Blockchain.nextPointer;
    private readonly transferCountPointer: u16 = Blockchain.nextPointer;
    private readonly lastActivityPointer: u16 = Blockchain.nextPointer;
    private readonly versionPointer: u16 = Blockchain.nextPointer;
    private readonly createdAtPointer: u16 = Blockchain.nextPointer;
    private readonly updatedAtPointer: u16 = Blockchain.nextPointer;
    private readonly extraPointer1: u16 = Blockchain.nextPointer;

    // Storage instances
    private readonly totalSupply: StoredU256 = new StoredU256(
        this.totalSupplyPointer,
        EMPTY_POINTER,
    );
    private readonly ownerAddr: StoredAddress = new StoredAddress(this.ownerPointer);
    private readonly paused: StoredBoolean = new StoredBoolean(this.pausedPointer, EMPTY_POINTER);
    private readonly feeAmount: StoredU256 = new StoredU256(this.feePointer, EMPTY_POINTER);

    // BUG: Hardcoded address at class scope
    private readonly treasury: Address = Address.fromString('abcdef1234567890abcdef1234567890abcdef12');

    // BUG: single-param Address.fromString
    private readonly feeRecipient: Address = Address.fromString('1234567890abcdef1234567890abcdef12345678');

    public constructor() {
        super();
    }

    // BUG: Missing super.onDeployment(calldata)
    public override onDeployment(calldata: Calldata): void {
        const owner: Address = calldata.readAddress();
        const initialSupply: u256 = calldata.readU256();

        // BUG: No validation on calldata reads
        this.ownerAddr.value = owner;
        this.totalSupply.value = initialSupply;
    }

    // BUG: State-modifying @method without access control
    @method()
    public unsafeTransfer(calldata: Calldata): BytesWriter {
        const to: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();

        // BUG: Raw u256 arithmetic instead of SafeMath
        const newSupply: u256 = this.totalSupply.value - amount;
        this.totalSupply.value = newSupply;

        // BUG: No event emission for state change

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    // BUG: CEI violation - state write after external call
    @method()
    public unsafeSwap(calldata: Calldata): BytesWriter {
        const token: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();

        const swapCalldata: BytesWriter = new BytesWriter(36);
        swapCalldata.writeU256(amount);

        // External call
        const result: CallResult = Blockchain.call(token, swapCalldata);

        // BUG: Result not checked for success
        // BUG: State write AFTER external call (CEI violation)
        this.totalSupply.value = SafeMath.sub(this.totalSupply.value, amount);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    // BUG: While loop (should use bounded for loop)
    @method()
    public processBatch(calldata: Calldata): BytesWriter {
        const count: u256 = calldata.readU256();
        let i: u256 = u256.Zero;

        // BUG: while loop
        while (u256.lt(i, count)) {
            i = SafeMath.add(i, u256.One);
            // process something
        }

        // BUG: Another unbounded while
        while (true) {
            break;
        }

        // BUG: Empty BytesWriter
        return new BytesWriter(0);
    }

    // BUG: Blockchain.call without checking result
    private callExternal(target: Address): void {
        const data: BytesWriter = new BytesWriter(4);
        Blockchain.call(target, data);
    }
}
