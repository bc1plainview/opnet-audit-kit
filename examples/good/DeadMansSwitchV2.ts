import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    bigEndianAdd,
    Blockchain,
    BytesWriter,
    Calldata,
    encodePointer,
    EMPTY_POINTER,
    NetEvent,
    OP_NET,
    Revert,
    SafeMath,
    StoredU256,
} from '@btc-vision/btc-runtime/runtime';

/** Status constants for a Dead Man's Switch. */
const STATUS_ACTIVE: u256 = u256.Zero;
const STATUS_TRIGGERED: u256 = u256.One;
const STATUS_CANCELLED: u256 = u256.fromU32(2);

/** Maximum number of 32-byte slots for a single stored byte array. */
const MAX_BYTE_SLOTS: u32 = 256;

/**
 * Event emitted when a new switch is created.
 */
@final
class SwitchCreatedEvent extends NetEvent {
    constructor(switchId: u256, owner: Address, beneficiary: Address) {
        const data: BytesWriter = new BytesWriter(32 + 32 + 32);
        data.writeU256(switchId);
        data.writeAddress(owner);
        data.writeAddress(beneficiary);

        super('SwitchCreated', data);
    }
}

/**
 * Event emitted when a switch owner checks in.
 */
@final
class CheckedInEvent extends NetEvent {
    constructor(switchId: u256, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeU256(switchId);
        data.writeU256(blockHeight);

        super('CheckedIn', data);
    }
}

/**
 * Event emitted when encrypted data is stored.
 */
@final
class DataStoredEvent extends NetEvent {
    constructor(switchId: u256, chunkIndex: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeU256(switchId);
        data.writeU256(chunkIndex);

        super('DataStored', data);
    }
}

/**
 * Event emitted when a switch is triggered.
 */
@final
class SwitchTriggeredEvent extends NetEvent {
    constructor(switchId: u256, beneficiary: Address, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32 + 32);
        data.writeU256(switchId);
        data.writeAddress(beneficiary);
        data.writeU256(blockHeight);

        super('SwitchTriggered', data);
    }
}

/**
 * Event emitted when a switch is cancelled during grace period.
 */
@final
class SwitchCancelledEvent extends NetEvent {
    constructor(switchId: u256, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeU256(switchId);
        data.writeU256(blockHeight);

        super('SwitchCancelled', data);
    }
}

/**
 * Event emitted when the beneficiary is updated.
 */
@final
class BeneficiaryUpdatedEvent extends NetEvent {
    constructor(switchId: u256, newBeneficiary: Address) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeU256(switchId);
        data.writeAddress(newBeneficiary);

        super('BeneficiaryUpdated', data);
    }
}

/**
 * Dead Man's Switch V2 - Multi-tenant factory contract for OPNet.
 *
 * Allows any user to create independent Dead Man's Switches within a single
 * contract instance. Each switch is identified by a unique auto-incrementing
 * switchId (starting at 1). No admin required - fully permissionless.
 *
 * Storage Layout (all pointers allocated via Blockchain.nextPointer):
 * - Pointer 0: nextSwitchId (auto-increment counter, starts at 1)
 * - Pointer 1: switchOwner map (switchId -> Address)
 * - Pointer 2: switchBeneficiary map (switchId -> Address)
 * - Pointer 3: switchInterval map (switchId -> u256)
 * - Pointer 4: switchGracePeriod map (switchId -> u256)
 * - Pointer 5: switchLastCheckin map (switchId -> u256)
 * - Pointer 6: switchStatus map (switchId -> u256)
 * - Pointer 7: switchTriggerBlock map (switchId -> u256)
 * - Pointer 8: switchChunkCount map (switchId -> u256)
 * - Pointer 9: switchEncryptedKey (switchId -> multi-slot bytes)
 * - Pointer 10: switchDataChunks (switchId+chunkIndex -> multi-slot bytes)
 * - Pointer 11: ownerSwitchCount map (owner Address -> u256)
 * - Pointer 12: ownerSwitchIndex map (owner Address + index -> switchId)
 */
@final
export class DeadMansSwitchV2 extends OP_NET {
    /** Pointer allocations via Blockchain.nextPointer. */
    private readonly nextSwitchIdPointer: u16 = Blockchain.nextPointer;
    private readonly switchOwnerPointer: u16 = Blockchain.nextPointer;
    private readonly switchBeneficiaryPointer: u16 = Blockchain.nextPointer;
    private readonly switchIntervalPointer: u16 = Blockchain.nextPointer;
    private readonly switchGracePeriodPointer: u16 = Blockchain.nextPointer;
    private readonly switchLastCheckinPointer: u16 = Blockchain.nextPointer;
    private readonly switchStatusPointer: u16 = Blockchain.nextPointer;
    private readonly switchTriggerBlockPointer: u16 = Blockchain.nextPointer;
    private readonly switchChunkCountPointer: u16 = Blockchain.nextPointer;
    private readonly switchEncryptedKeyPointer: u16 = Blockchain.nextPointer;
    private readonly switchDataChunksPointer: u16 = Blockchain.nextPointer;
    private readonly ownerSwitchCountPointer: u16 = Blockchain.nextPointer;
    private readonly ownerSwitchIndexPointer: u16 = Blockchain.nextPointer;

    /** Auto-increment counter for switch IDs. Starts at 1, 0 means "does not exist". */
    private readonly nextSwitchId: StoredU256 = new StoredU256(
        this.nextSwitchIdPointer,
        EMPTY_POINTER,
    );

    public constructor() {
        super();
    }

    /**
     * Initializes the counter to 1 on first deployment so switchId 0 is reserved.
     */
    public override onDeployment(_calldata: Calldata): void {
        this.nextSwitchId.value = u256.One;
    }

    /**
     * Creates a new switch. Any user can call this.
     *
     * @param calldata - beneficiary (Address), interval (u256), gracePeriod (u256)
     * @returns switchId (u256)
     */
    @method(
        { name: 'beneficiary', type: ABIDataTypes.ADDRESS },
        { name: 'interval', type: ABIDataTypes.UINT256 },
        { name: 'gracePeriod', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'switchId', type: ABIDataTypes.UINT256 })
    public createSwitch(calldata: Calldata): BytesWriter {
        const beneficiary: Address = calldata.readAddress();
        const interval: u256 = calldata.readU256();
        const gracePeriod: u256 = calldata.readU256();

        if (beneficiary.equals(Address.zero())) {
            throw new Revert('Beneficiary cannot be zero address');
        }

        if (interval.isZero()) {
            throw new Revert('Heartbeat interval must be greater than zero');
        }

        if (gracePeriod.isZero()) {
            throw new Revert('Grace period must be greater than zero');
        }

        const switchId: u256 = this.nextSwitchId.value;
        const sender: Address = Blockchain.tx.sender;
        const currentBlock: u256 = Blockchain.block.numberU256;

        // Store switch metadata
        this.storeSwitchOwner(switchId, sender);
        this.storeSwitchBeneficiary(switchId, beneficiary);
        this.storeSwitchInterval(switchId, interval);
        this.storeSwitchGracePeriod(switchId, gracePeriod);
        this.storeSwitchLastCheckin(switchId, currentBlock);
        this.storeSwitchStatus(switchId, STATUS_ACTIVE);
        this.storeSwitchTriggerBlock(switchId, u256.Zero);
        this.storeSwitchChunkCount(switchId, u256.Zero);

        // Track ownership: add this switchId to the owner's list
        this.addSwitchToOwner(sender, switchId);

        // Increment the global switch counter
        this.nextSwitchId.value = SafeMath.add(switchId, u256.One);

        this.emitEvent(new SwitchCreatedEvent(switchId, sender, beneficiary));

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(switchId);
        return writer;
    }

    /**
     * Owner checks in, resetting the heartbeat timer.
     *
     * @param calldata - switchId (u256)
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public checkin(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);
        this.ensureActive(switchId);

        const currentBlock: u256 = Blockchain.block.numberU256;
        this.storeSwitchLastCheckin(switchId, currentBlock);

        this.emitEvent(new CheckedInEvent(switchId, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Stores an encrypted data chunk for a switch.
     *
     * @param calldata - switchId (u256), chunkIndex (u256), encryptedData (bytes)
     */
    @method(
        { name: 'switchId', type: ABIDataTypes.UINT256 },
        { name: 'chunkIndex', type: ABIDataTypes.UINT256 },
        { name: 'encryptedData', type: ABIDataTypes.BYTES },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public storeData(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        const chunkIndex: u256 = calldata.readU256();
        const encryptedData: Uint8Array = calldata.readBytesWithLength();

        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);
        this.ensureActive(switchId);

        if (encryptedData.length === 0) {
            throw new Revert('Data cannot be empty');
        }

        // Build a compound sub-pointer from switchId + chunkIndex
        const subPtr: Uint8Array = this.compoundSubPointer(switchId, chunkIndex);
        this.storeMultiSlotBytes(this.switchDataChunksPointer, subPtr, encryptedData);

        // Update chunk count if needed
        const currentCount: u256 = this.loadSwitchChunkCount(switchId);
        const indexPlusOne: u256 = SafeMath.add(chunkIndex, u256.One);
        if (indexPlusOne > currentCount) {
            this.storeSwitchChunkCount(switchId, indexPlusOne);
        }

        this.emitEvent(new DataStoredEvent(switchId, chunkIndex));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Stores the encrypted decryption key for a switch's beneficiary.
     *
     * @param calldata - switchId (u256), encryptedKey (bytes)
     */
    @method(
        { name: 'switchId', type: ABIDataTypes.UINT256 },
        { name: 'encryptedKey', type: ABIDataTypes.BYTES },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public storeDecryptionKey(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        const encryptedKey: Uint8Array = calldata.readBytesWithLength();

        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);
        this.ensureActive(switchId);

        if (encryptedKey.length === 0) {
            throw new Revert('Encrypted key cannot be empty');
        }

        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        this.storeMultiSlotBytes(this.switchEncryptedKeyPointer, subPtr, encryptedKey);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Triggers a switch if the heartbeat has expired. Anyone can call this.
     *
     * @param calldata - switchId (u256)
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public trigger(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);

        const currentStatus: u256 = this.loadSwitchStatus(switchId);
        if (u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch already triggered');
        }
        if (u256.eq(currentStatus, STATUS_CANCELLED)) {
            throw new Revert('Switch has been cancelled');
        }

        const currentBlock: u256 = Blockchain.block.numberU256;
        const lastCheck: u256 = this.loadSwitchLastCheckin(switchId);
        const interval: u256 = this.loadSwitchInterval(switchId);
        const deadline: u256 = SafeMath.add(lastCheck, interval);

        if (currentBlock <= deadline) {
            throw new Revert('Heartbeat has not expired yet');
        }

        this.storeSwitchStatus(switchId, STATUS_TRIGGERED);
        this.storeSwitchTriggerBlock(switchId, currentBlock);

        const beneficiary: Address = this.loadSwitchBeneficiary(switchId);
        this.emitEvent(new SwitchTriggeredEvent(switchId, beneficiary, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Owner cancels a triggered switch within the grace period.
     *
     * @param calldata - switchId (u256)
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public cancel(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);

        const currentStatus: u256 = this.loadSwitchStatus(switchId);
        if (!u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch is not triggered');
        }

        const currentBlock: u256 = Blockchain.block.numberU256;
        const trigBlock: u256 = this.loadSwitchTriggerBlock(switchId);
        const grace: u256 = this.loadSwitchGracePeriod(switchId);
        const graceDeadline: u256 = SafeMath.add(trigBlock, grace);

        if (currentBlock > graceDeadline) {
            throw new Revert('Grace period has expired');
        }

        this.storeSwitchStatus(switchId, STATUS_ACTIVE);
        this.storeSwitchLastCheckin(switchId, currentBlock);
        this.storeSwitchTriggerBlock(switchId, u256.Zero);

        this.emitEvent(new SwitchCancelledEvent(switchId, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Updates the beneficiary address for a switch. Owner only, must be active.
     *
     * @param calldata - switchId (u256), newBeneficiary (Address)
     */
    @method(
        { name: 'switchId', type: ABIDataTypes.UINT256 },
        { name: 'newBeneficiary', type: ABIDataTypes.ADDRESS },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public updateBeneficiary(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        const newBeneficiary: Address = calldata.readAddress();

        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);
        this.ensureActive(switchId);

        if (newBeneficiary.equals(Address.zero())) {
            throw new Revert('Beneficiary cannot be zero address');
        }

        this.storeSwitchBeneficiary(switchId, newBeneficiary);

        this.emitEvent(new BeneficiaryUpdatedEvent(switchId, newBeneficiary));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Updates the heartbeat interval for a switch. Owner only, must be active.
     *
     * @param calldata - switchId (u256), newInterval (u256)
     */
    @method(
        { name: 'switchId', type: ABIDataTypes.UINT256 },
        { name: 'newInterval', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public updateInterval(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        const newInterval: u256 = calldata.readU256();

        this.ensureSwitchExists(switchId);
        this.ensureOwner(switchId);
        this.ensureActive(switchId);

        if (newInterval.isZero()) {
            throw new Revert('Interval must be greater than zero');
        }

        this.storeSwitchInterval(switchId, newInterval);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Returns all metadata for a given switch.
     *
     * @param calldata - switchId (u256)
     * @returns owner, beneficiary, interval, gracePeriod, lastCheckin, status, triggerBlock, chunkCount
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns(
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'beneficiary', type: ABIDataTypes.ADDRESS },
        { name: 'interval', type: ABIDataTypes.UINT256 },
        { name: 'gracePeriod', type: ABIDataTypes.UINT256 },
        { name: 'lastCheckin', type: ABIDataTypes.UINT256 },
        { name: 'status', type: ABIDataTypes.UINT256 },
        { name: 'triggerBlock', type: ABIDataTypes.UINT256 },
        { name: 'chunkCount', type: ABIDataTypes.UINT256 },
    )
    public getSwitch(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);

        const owner: Address = this.loadSwitchOwner(switchId);
        const beneficiary: Address = this.loadSwitchBeneficiary(switchId);
        const interval: u256 = this.loadSwitchInterval(switchId);
        const gracePeriod: u256 = this.loadSwitchGracePeriod(switchId);
        const lastCheckin: u256 = this.loadSwitchLastCheckin(switchId);
        const status: u256 = this.loadSwitchStatus(switchId);
        const triggerBlock: u256 = this.loadSwitchTriggerBlock(switchId);
        const chunkCount: u256 = this.loadSwitchChunkCount(switchId);

        // 32 bytes per Address, 32 bytes per u256 = 2*32 + 6*32 = 256 bytes
        const writer: BytesWriter = new BytesWriter(256);
        writer.writeAddress(owner);
        writer.writeAddress(beneficiary);
        writer.writeU256(interval);
        writer.writeU256(gracePeriod);
        writer.writeU256(lastCheckin);
        writer.writeU256(status);
        writer.writeU256(triggerBlock);
        writer.writeU256(chunkCount);
        return writer;
    }

    /**
     * Returns the encrypted data chunk at the given index for a switch.
     *
     * @param calldata - switchId (u256), chunkIndex (u256)
     */
    @method(
        { name: 'switchId', type: ABIDataTypes.UINT256 },
        { name: 'chunkIndex', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'data', type: ABIDataTypes.BYTES })
    public getData(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        const chunkIndex: u256 = calldata.readU256();

        this.ensureSwitchExists(switchId);

        const count: u256 = this.loadSwitchChunkCount(switchId);
        if (chunkIndex >= count) {
            throw new Revert('Chunk index out of bounds');
        }

        const subPtr: Uint8Array = this.compoundSubPointer(switchId, chunkIndex);
        const data: Uint8Array = this.loadMultiSlotBytes(this.switchDataChunksPointer, subPtr);

        const writer: BytesWriter = new BytesWriter(i32(data.length) + 4);
        writer.writeBytesWithLength(data);
        return writer;
    }

    /**
     * Returns the encrypted decryption key for a switch. Only accessible after triggered.
     *
     * @param calldata - switchId (u256)
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'encryptedKey', type: ABIDataTypes.BYTES })
    public getDecryptionKey(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);

        const currentStatus: u256 = this.loadSwitchStatus(switchId);
        if (!u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch has not been triggered');
        }

        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        const key: Uint8Array = this.loadMultiSlotBytes(this.switchEncryptedKeyPointer, subPtr);

        const writer: BytesWriter = new BytesWriter(i32(key.length) + 4);
        writer.writeBytesWithLength(key);
        return writer;
    }

    /**
     * Returns the total number of switches created.
     */
    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getSwitchCount(_calldata: Calldata): BytesWriter {
        // nextSwitchId starts at 1, so total created = nextSwitchId - 1
        const nextId: u256 = this.nextSwitchId.value;
        const count: u256 = SafeMath.sub(nextId, u256.One);

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(count);
        return writer;
    }

    /**
     * Returns whether a switch's heartbeat timer has expired.
     *
     * @param calldata - switchId (u256)
     */
    @method({ name: 'switchId', type: ABIDataTypes.UINT256 })
    @returns({ name: 'expired', type: ABIDataTypes.BOOL })
    public isExpired(calldata: Calldata): BytesWriter {
        const switchId: u256 = calldata.readU256();
        this.ensureSwitchExists(switchId);

        const currentBlock: u256 = Blockchain.block.numberU256;
        const lastCheck: u256 = this.loadSwitchLastCheckin(switchId);
        const interval: u256 = this.loadSwitchInterval(switchId);
        const deadline: u256 = SafeMath.add(lastCheck, interval);

        const expired: bool = currentBlock > deadline;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(expired);
        return writer;
    }

    /**
     * Returns the switchIds owned by a given address.
     * Uses the per-owner counter + index mapping pattern.
     *
     * @param calldata - owner (Address)
     * @returns count (u256) followed by array of switchIds (u256[])
     */
    @method({ name: 'owner', type: ABIDataTypes.ADDRESS })
    @returns(
        { name: 'count', type: ABIDataTypes.UINT256 },
        { name: 'switchIds', type: ABIDataTypes.UINT256 },
    )
    public getSwitchesByOwner(calldata: Calldata): BytesWriter {
        const owner: Address = calldata.readAddress();
        const count: u256 = this.getOwnerSwitchCount(owner);

        // Bounded iteration: max 100 switches per response to prevent gas explosion
        const MAX_RETURN: u256 = u256.fromU32(100);
        const returnCount: u256 = count > MAX_RETURN ? MAX_RETURN : count;
        const returnCountU32: u32 = returnCount.toU32();

        // 32 bytes for count + 32 bytes per switchId
        const writer: BytesWriter = new BytesWriter(i32(32 + returnCountU32 * 32));
        writer.writeU256(count);

        for (let i: u32 = 0; i < returnCountU32; i++) {
            const index: u256 = u256.fromU32(i);
            const switchId: u256 = this.getOwnerSwitchAtIndex(owner, index);
            writer.writeU256(switchId);
        }

        return writer;
    }

    // =========================================================================
    // Storage accessor helpers - using encodePointer for map-like lookups
    // =========================================================================

    /**
     * Stores an Address value into a map keyed by switchId.
     * Address extends Uint8Array (32 bytes), so we write it directly.
     */
    private setAddressForSwitch(pointer: u16, switchId: u256, addr: Address): void {
        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        const key: Uint8Array = encodePointer(pointer, subPtr, true, 'SwitchAddr');
        Blockchain.setStorageAt(key, addr);
    }

    /**
     * Loads an Address from a map keyed by switchId.
     */
    private getAddressForSwitch(pointer: u16, switchId: u256): Address {
        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        const key: Uint8Array = encodePointer(pointer, subPtr, true, 'SwitchAddr');
        const slot: Uint8Array = Blockchain.getStorageAt(key);
        return Address.fromUint8Array(slot);
    }

    /**
     * Stores a u256 value into a map keyed by switchId.
     */
    private setU256ForSwitch(pointer: u16, switchId: u256, value: u256): void {
        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        const key: Uint8Array = encodePointer(pointer, subPtr, true, 'SwitchU256');
        Blockchain.setStorageAt(key, value.toUint8Array(true));
    }

    /**
     * Loads a u256 value from a map keyed by switchId.
     */
    private getU256ForSwitch(pointer: u16, switchId: u256): u256 {
        const subPtr: Uint8Array = this.u256ToSubPointer(switchId);
        const key: Uint8Array = encodePointer(pointer, subPtr, true, 'SwitchU256');
        const slot: Uint8Array = Blockchain.getStorageAt(key);
        return u256.fromUint8ArrayBE(slot);
    }

    // Per-switch typed accessors

    private storeSwitchOwner(switchId: u256, owner: Address): void {
        this.setAddressForSwitch(this.switchOwnerPointer, switchId, owner);
    }

    private loadSwitchOwner(switchId: u256): Address {
        return this.getAddressForSwitch(this.switchOwnerPointer, switchId);
    }

    private storeSwitchBeneficiary(switchId: u256, beneficiary: Address): void {
        this.setAddressForSwitch(this.switchBeneficiaryPointer, switchId, beneficiary);
    }

    private loadSwitchBeneficiary(switchId: u256): Address {
        return this.getAddressForSwitch(this.switchBeneficiaryPointer, switchId);
    }

    private storeSwitchInterval(switchId: u256, interval: u256): void {
        this.setU256ForSwitch(this.switchIntervalPointer, switchId, interval);
    }

    private loadSwitchInterval(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchIntervalPointer, switchId);
    }

    private storeSwitchGracePeriod(switchId: u256, gracePeriod: u256): void {
        this.setU256ForSwitch(this.switchGracePeriodPointer, switchId, gracePeriod);
    }

    private loadSwitchGracePeriod(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchGracePeriodPointer, switchId);
    }

    private storeSwitchLastCheckin(switchId: u256, lastCheckin: u256): void {
        this.setU256ForSwitch(this.switchLastCheckinPointer, switchId, lastCheckin);
    }

    private loadSwitchLastCheckin(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchLastCheckinPointer, switchId);
    }

    private storeSwitchStatus(switchId: u256, status: u256): void {
        this.setU256ForSwitch(this.switchStatusPointer, switchId, status);
    }

    private loadSwitchStatus(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchStatusPointer, switchId);
    }

    private storeSwitchTriggerBlock(switchId: u256, triggerBlock: u256): void {
        this.setU256ForSwitch(this.switchTriggerBlockPointer, switchId, triggerBlock);
    }

    private loadSwitchTriggerBlock(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchTriggerBlockPointer, switchId);
    }

    private storeSwitchChunkCount(switchId: u256, count: u256): void {
        this.setU256ForSwitch(this.switchChunkCountPointer, switchId, count);
    }

    private loadSwitchChunkCount(switchId: u256): u256 {
        return this.getU256ForSwitch(this.switchChunkCountPointer, switchId);
    }

    // =========================================================================
    // Owner-to-switch tracking
    // =========================================================================

    /**
     * Gets the number of switches owned by an address.
     */
    private getOwnerSwitchCount(owner: Address): u256 {
        const subPtr: Uint8Array = this.addressToSubPointer(owner);
        const key: Uint8Array = encodePointer(
            this.ownerSwitchCountPointer,
            subPtr,
            true,
            'OwnerCount',
        );
        const slot: Uint8Array = Blockchain.getStorageAt(key);
        return u256.fromUint8ArrayBE(slot);
    }

    /**
     * Sets the number of switches owned by an address.
     */
    private setOwnerSwitchCount(owner: Address, count: u256): void {
        const subPtr: Uint8Array = this.addressToSubPointer(owner);
        const key: Uint8Array = encodePointer(
            this.ownerSwitchCountPointer,
            subPtr,
            true,
            'OwnerCount',
        );
        Blockchain.setStorageAt(key, count.toUint8Array(true));
    }

    /**
     * Gets the switchId at a given index for an owner.
     */
    private getOwnerSwitchAtIndex(owner: Address, index: u256): u256 {
        const subPtr: Uint8Array = this.addressIndexSubPointer(owner, index);
        const key: Uint8Array = encodePointer(
            this.ownerSwitchIndexPointer,
            subPtr,
            true,
            'OwnerIdx',
        );
        const slot: Uint8Array = Blockchain.getStorageAt(key);
        return u256.fromUint8ArrayBE(slot);
    }

    /**
     * Sets the switchId at a given index for an owner.
     */
    private setOwnerSwitchAtIndex(owner: Address, index: u256, switchId: u256): void {
        const subPtr: Uint8Array = this.addressIndexSubPointer(owner, index);
        const key: Uint8Array = encodePointer(
            this.ownerSwitchIndexPointer,
            subPtr,
            true,
            'OwnerIdx',
        );
        Blockchain.setStorageAt(key, switchId.toUint8Array(true));
    }

    /**
     * Adds a switchId to an owner's tracking list.
     */
    private addSwitchToOwner(owner: Address, switchId: u256): void {
        const currentCount: u256 = this.getOwnerSwitchCount(owner);
        this.setOwnerSwitchAtIndex(owner, currentCount, switchId);
        this.setOwnerSwitchCount(owner, SafeMath.add(currentCount, u256.One));
    }

    // =========================================================================
    // Validation helpers
    // =========================================================================

    /**
     * Ensures a switchId refers to an existing switch (switchId >= 1 and < nextSwitchId).
     */
    private ensureSwitchExists(switchId: u256): void {
        const nextId: u256 = this.nextSwitchId.value;
        if (switchId.isZero() || switchId >= nextId) {
            throw new Revert('Switch does not exist');
        }
    }

    /**
     * Ensures the caller is the owner of the given switch.
     */
    private ensureOwner(switchId: u256): void {
        const owner: Address = this.loadSwitchOwner(switchId);
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Only owner can call this method');
        }
    }

    /**
     * Ensures the switch is in ACTIVE status.
     */
    private ensureActive(switchId: u256): void {
        const currentStatus: u256 = this.loadSwitchStatus(switchId);
        if (!u256.eq(currentStatus, STATUS_ACTIVE)) {
            throw new Revert('Switch is not active');
        }
    }

    // =========================================================================
    // Sub-pointer encoding helpers
    // =========================================================================

    /**
     * Converts a u256 to a 30-byte sub-pointer (last 30 bytes of BE representation).
     */
    private u256ToSubPointer(value: u256): Uint8Array {
        const bytes32: Uint8Array = value.toUint8Array(true);
        const sub: Uint8Array = new Uint8Array(30);
        for (let i: u32 = 0; i < 30; i++) {
            sub[i] = bytes32[i + 2];
        }
        return sub;
    }

    /**
     * Converts an Address (32 bytes) to a 30-byte sub-pointer.
     * Takes the last 30 bytes of the address.
     */
    private addressToSubPointer(addr: Address): Uint8Array {
        const sub: Uint8Array = new Uint8Array(30);
        // Address is 32 bytes; take bytes [2..31] (last 30 bytes)
        for (let i: i32 = 0; i < 30; i++) {
            sub[i] = addr[i + 2];
        }
        return sub;
    }

    /**
     * Creates a compound sub-pointer from an Address and an index (u256).
     * XORs the two 30-byte representations to create a unique derived key.
     */
    private addressIndexSubPointer(addr: Address, index: u256): Uint8Array {
        const addrSub: Uint8Array = this.addressToSubPointer(addr);
        const idxSub: Uint8Array = this.u256ToSubPointer(index);
        const result: Uint8Array = new Uint8Array(30);
        for (let i: i32 = 0; i < 30; i++) {
            result[i] = addrSub[i] ^ idxSub[i];
        }
        return result;
    }

    /**
     * Creates a compound sub-pointer from two u256 values (switchId + chunkIndex).
     * XORs the two 30-byte representations to create a unique derived key.
     */
    private compoundSubPointer(a: u256, b: u256): Uint8Array {
        const aSub: Uint8Array = this.u256ToSubPointer(a);
        const bSub: Uint8Array = this.u256ToSubPointer(b);
        const result: Uint8Array = new Uint8Array(30);
        for (let i: i32 = 0; i < 30; i++) {
            result[i] = aSub[i] ^ bSub[i];
        }
        return result;
    }

    // =========================================================================
    // Multi-slot byte storage (same pattern as V1)
    // =========================================================================

    /**
     * Stores a variable-length byte array across multiple 32-byte storage slots.
     *
     * Slot 0: first 4 bytes = length (big-endian u32), next 28 bytes = data start
     * Slot N (N > 0): 32 bytes of data each
     *
     * @param pointer - The storage pointer identifier
     * @param subPointer - The sub-pointer (compound key as Uint8Array)
     * @param data - The byte array to store
     */
    private storeMultiSlotBytes(pointer: u16, subPointer: Uint8Array, data: Uint8Array): void {
        const length: u32 = u32(data.length);
        const maxDataBytes: u32 = MAX_BYTE_SLOTS * 32 - 4;

        if (length > maxDataBytes) {
            throw new Revert('Data exceeds maximum storage capacity');
        }

        const baseKey: Uint8Array = encodePointer(pointer, subPointer, true, 'MultiSlotBytes');

        // Slot 0: [4 bytes length BE][28 bytes data]
        const slot0: Uint8Array = new Uint8Array(32);
        slot0[0] = u8((length >> 24) & 0xff);
        slot0[1] = u8((length >> 16) & 0xff);
        slot0[2] = u8((length >> 8) & 0xff);
        slot0[3] = u8(length & 0xff);

        const firstChunkSize: u32 = length < 28 ? length : 28;
        for (let i: u32 = 0; i < firstChunkSize; i++) {
            slot0[i + 4] = data[i];
        }

        Blockchain.setStorageAt(baseKey, slot0);

        // Subsequent slots: 32 bytes each
        let offset: u32 = 28;
        let slotIndex: u64 = 1;

        for (; offset < length; slotIndex++) {
            const slotKey: Uint8Array = bigEndianAdd(baseKey, slotIndex);
            const slotData: Uint8Array = new Uint8Array(32);
            const remaining: u32 = length - offset;
            const toCopy: u32 = remaining < 32 ? remaining : 32;

            for (let i: u32 = 0; i < toCopy; i++) {
                slotData[i] = data[offset + i];
            }

            Blockchain.setStorageAt(slotKey, slotData);
            offset += 32;
        }
    }

    /**
     * Loads a variable-length byte array from multiple 32-byte storage slots.
     *
     * @param pointer - The storage pointer identifier
     * @param subPointer - The sub-pointer (compound key as Uint8Array)
     * @returns The reconstructed byte array
     */
    private loadMultiSlotBytes(pointer: u16, subPointer: Uint8Array): Uint8Array {
        const baseKey: Uint8Array = encodePointer(pointer, subPointer, true, 'MultiSlotBytes');

        // Read slot 0 to get length
        const slot0: Uint8Array = Blockchain.getStorageAt(baseKey);

        const b0: u32 = u32(slot0[0]);
        const b1: u32 = u32(slot0[1]);
        const b2: u32 = u32(slot0[2]);
        const b3: u32 = u32(slot0[3]);
        const length: u32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

        if (length === 0) {
            return new Uint8Array(0);
        }

        const result: Uint8Array = new Uint8Array(length);

        // Read first 28 bytes from slot 0
        const firstChunkSize: u32 = length < 28 ? length : 28;
        for (let i: u32 = 0; i < firstChunkSize; i++) {
            result[i] = slot0[i + 4];
        }

        // Read subsequent slots
        let offset: u32 = 28;
        let slotIndex: u64 = 1;

        for (; offset < length; slotIndex++) {
            const slotKey: Uint8Array = bigEndianAdd(baseKey, slotIndex);
            const slotData: Uint8Array = Blockchain.getStorageAt(slotKey);
            const remaining: u32 = length - offset;
            const toCopy: u32 = remaining < 32 ? remaining : 32;

            for (let i: u32 = 0; i < toCopy; i++) {
                result[offset + i] = slotData[i];
            }

            offset += 32;
        }

        return result;
    }
}
