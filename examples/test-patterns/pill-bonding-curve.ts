import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    OP_NET,
    Revert,
    SafeMath,
    Selector,
    StoredAddress,
    StoredU256,
    EMPTY_POINTER,
    NetEvent,
} from '@btc-vision/btc-runtime/runtime';
import { CallResult } from '@btc-vision/btc-runtime/runtime/env/BlockchainEnvironment';

/**
 * Pill Bonding Curve Contract - based on real Maze code patterns.
 * Contains known bugs: EVM selectors, single-param Address.fromString, etc.
 */

@final
class PurchaseEvent extends NetEvent {
    constructor(buyer: Address, amount: u256, cost: u256) {
        const data: BytesWriter = new BytesWriter(96);
        data.writeAddress(buyer);
        data.writeU256(amount);
        data.writeU256(cost);
        super('Purchase', data);
    }
}

@final
export class PillBondingCurve extends OP_NET {
    // BUG: EVM Keccak256 selectors instead of OPNet SHA256 selectors
    private readonly TRANSFER_SELECTOR: u32 = 0xa9059cbb;      // EVM transfer
    private readonly BALANCE_OF_SELECTOR: u32 = 0x70a08231;     // EVM balanceOf
    private readonly APPROVE_SELECTOR: u32 = 0x095ea7b3;        // EVM approve
    private readonly TRANSFER_FROM_SELECTOR: u32 = 0x23b872dd;  // EVM transferFrom
    private readonly ALLOWANCE_SELECTOR: u32 = 0xdd62ed3e;      // EVM allowance
    private readonly TOTAL_SUPPLY_SELECTOR: u32 = 0x18160ddd;   // EVM totalSupply

    // Storage pointers
    private readonly reservePointer: u16 = Blockchain.nextPointer;
    private readonly supplyPointer: u16 = Blockchain.nextPointer;
    private readonly pricePointer: u16 = Blockchain.nextPointer;
    private readonly ownerPointer: u16 = Blockchain.nextPointer;
    private readonly tokenAddressPointer: u16 = Blockchain.nextPointer;
    private readonly curveConstantPointer: u16 = Blockchain.nextPointer;

    // Storage
    private readonly reserve: StoredU256 = new StoredU256(this.reservePointer, EMPTY_POINTER);
    private readonly supply: StoredU256 = new StoredU256(this.supplyPointer, EMPTY_POINTER);
    private readonly currentPrice: StoredU256 = new StoredU256(this.pricePointer, EMPTY_POINTER);
    private readonly owner: StoredAddress = new StoredAddress(this.ownerPointer);
    private readonly tokenAddress: StoredAddress = new StoredAddress(this.tokenAddressPointer);
    private readonly curveConstant: StoredU256 = new StoredU256(this.curveConstantPointer, EMPTY_POINTER);

    // BUG: Hardcoded address with single param (needs 2 params)
    private readonly PILL_TOKEN: Address = Address.fromString('deadbeef1234567890abcdef1234567890deadbeef');

    // BUG: Another single-param Address.fromString with hardcoded value
    private readonly FEE_RECEIVER: Address = Address.fromString('cafebabe1234567890abcdef1234567890cafebabe');

    public constructor() {
        super();
    }

    // BUG: Missing super.onDeployment(calldata)
    public override onDeployment(calldata: Calldata): void {
        const ownerAddr: Address = calldata.readAddress();
        const tokenAddr: Address = calldata.readAddress();
        const initialPrice: u256 = calldata.readU256();
        const constant: u256 = calldata.readU256();

        // Only partial validation
        if (ownerAddr.isZero()) {
            throw new Revert('Invalid owner');
        }

        // BUG: tokenAddr not validated
        // BUG: initialPrice not validated
        // BUG: constant not validated

        this.owner.value = ownerAddr;
        this.tokenAddress.value = tokenAddr;
        this.currentPrice.value = initialPrice;
        this.curveConstant.value = constant;
        this.reserve.value = u256.Zero;
        this.supply.value = u256.Zero;
    }

    // BUG: @method with state writes but no access control
    @method()
    public buy(calldata: Calldata): BytesWriter {
        const amount: u256 = calldata.readU256();

        // BUG: amount not validated (unchecked calldata read)

        // Calculate cost using raw arithmetic (BUG)
        const cost: u256 = amount * this.currentPrice.value;
        const fee: u256 = cost / u256.fromU32(100);

        // State writes BEFORE external call (correct CEI for this part)
        const newSupply: u256 = SafeMath.add(this.supply.value, amount);
        this.supply.value = newSupply;

        // Transfer tokens from buyer
        const transferCalldata: BytesWriter = new BytesWriter(68);
        transferCalldata.writeU256(amount);

        const result: CallResult = Blockchain.call(this.PILL_TOKEN, transferCalldata);

        // BUG: CEI violation - state write after external call
        this.reserve.value = SafeMath.add(this.reserve.value, cost);
        this.currentPrice.value = SafeMath.add(this.currentPrice.value, this.curveConstant.value);

        // At least emits an event
        this.emitEvent(new PurchaseEvent(Blockchain.tx.sender, amount, cost));

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(cost);
        return writer;
    }

    // BUG: @method modifying state, no access control, no events
    @method()
    public sell(calldata: Calldata): BytesWriter {
        const amount: u256 = calldata.readU256();

        // BUG: raw arithmetic on u256
        const revenue: u256 = amount * this.currentPrice.value;

        this.supply.value = SafeMath.sub(this.supply.value, amount);
        this.reserve.value = SafeMath.sub(this.reserve.value, revenue);

        // External call
        const transferCalldata: BytesWriter = new BytesWriter(68);
        transferCalldata.writeU256(revenue);

        // BUG: Blockchain.call result not checked
        Blockchain.call(this.PILL_TOKEN, transferCalldata);

        // BUG: No event emission

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(revenue);
        return writer;
    }

    // Admin function - at least has access control
    @method()
    public setPrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newPrice: u256 = calldata.readU256();
        this.currentPrice.value = newPrice;

        // BUG: No event emission for admin action

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    // View function (should be clean)
    @method()
    public getPrice(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.currentPrice.value);
        return writer;
    }

    @method()
    public getReserve(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.reserve.value);
        return writer;
    }
}
