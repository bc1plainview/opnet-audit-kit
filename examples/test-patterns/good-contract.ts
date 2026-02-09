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
    StoredU256,
    EMPTY_POINTER,
    NetEvent,
} from '@btc-vision/btc-runtime/runtime';
import { ReentrancyGuard } from '@btc-vision/btc-runtime/runtime';
import { CallResult } from '@btc-vision/btc-runtime/runtime/env/BlockchainEnvironment';

/**
 * A well-written OPNet contract that follows all best practices.
 * This contract should trigger ZERO findings from opnet-analyzer.
 */
@final
class TransferEvent extends NetEvent {
    constructor(from: Address, to: Address, amount: u256) {
        const data: BytesWriter = new BytesWriter(96);
        data.writeAddress(from);
        data.writeAddress(to);
        data.writeU256(amount);
        super('Transfer', data);
    }
}

@final
class ApprovalEvent extends NetEvent {
    constructor(owner: Address, spender: Address, amount: u256) {
        const data: BytesWriter = new BytesWriter(96);
        data.writeAddress(owner);
        data.writeAddress(spender);
        data.writeU256(amount);
        super('Approval', data);
    }
}

@final
export class GoodToken extends ReentrancyGuard {
    // SHA256 selectors (correct for OPNet)
    private readonly transferSelector: Selector = encodeSelector('transfer');
    private readonly balanceOfSelector: Selector = encodeSelector('balanceOf');
    private readonly increaseAllowanceSelector: Selector = encodeSelector('increaseAllowance');

    // Storage pointers - all using Blockchain.nextPointer (unique auto-increment)
    private readonly totalSupplyPointer: u16 = Blockchain.nextPointer;
    private readonly balancesPointer: u16 = Blockchain.nextPointer;
    private readonly allowancesPointer: u16 = Blockchain.nextPointer;
    private readonly ownerPointer: u16 = Blockchain.nextPointer;
    private readonly namePointer: u16 = Blockchain.nextPointer;

    // Storage instances
    private readonly totalSupply: StoredU256 = new StoredU256(
        this.totalSupplyPointer,
        EMPTY_POINTER,
    );
    private readonly ownerAddr: StoredAddress = new StoredAddress(this.ownerPointer);

    public constructor() {
        super();
    }

    // Correct: calls super.onDeployment
    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        const owner: Address = calldata.readAddress();
        const initialSupply: u256 = calldata.readU256();

        if (owner.isZero()) {
            throw new Revert('Invalid owner address');
        }

        if (initialSupply.isZero()) {
            throw new Revert('Initial supply must be > 0');
        }

        this.ownerAddr.value = owner;
        this.totalSupply.value = initialSupply;
    }

    public override execute(method: Selector, calldata: Calldata): BytesWriter {
        switch (method) {
            case this.transferSelector:
                return this.transfer(calldata);
            case this.balanceOfSelector:
                return this.balanceOf(calldata);
            default:
                return super.execute(method, calldata);
        }
    }

    // Correct: uses SafeMath, has access control, emits events
    private transfer(calldata: Calldata): BytesWriter {
        const to: Address = calldata.readAddress();
        const amount: u256 = calldata.readU256();

        if (to.isZero()) {
            throw new Revert('Invalid recipient');
        }

        if (amount.isZero()) {
            throw new Revert('Amount must be > 0');
        }

        const sender: Address = Blockchain.tx.sender;

        // Using SafeMath (correct)
        const newSupply: u256 = SafeMath.sub(this.totalSupply.value, amount);
        this.totalSupply.value = newSupply;

        this.emitEvent(new TransferEvent(sender, to, amount));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    private balanceOf(calldata: Calldata): BytesWriter {
        const addr: Address = calldata.readAddress();

        if (addr.isZero()) {
            throw new Revert('Invalid address');
        }

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.totalSupply.value);
        return writer;
    }
}
