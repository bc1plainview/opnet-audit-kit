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
    StoredAddress,
    StoredU256,
} from '@btc-vision/btc-runtime/runtime';

/** Status constants for the Dead Man's Switch. */
const STATUS_ACTIVE: u256 = u256.Zero;
const STATUS_TRIGGERED: u256 = u256.One;
const STATUS_CANCELLED: u256 = u256.fromU32(2);

/** Maximum number of 32-byte slots for a single stored byte array. */
const MAX_BYTE_SLOTS: u32 = 256;

/**
 * Event emitted when the owner checks in.
 */
@final
class CheckedInEvent extends NetEvent {
    constructor(owner: Address, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeAddress(owner);
        data.writeU256(blockHeight);

        super('CheckedIn', data);
    }
}

/**
 * Event emitted when encrypted data is stored.
 */
@final
class DataStoredEvent extends NetEvent {
    constructor(chunkIndex: u256, dataSize: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeU256(chunkIndex);
        data.writeU256(dataSize);

        super('DataStored', data);
    }
}

/**
 * Event emitted when the switch is triggered.
 */
@final
class TriggeredEvent extends NetEvent {
    constructor(beneficiary: Address, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeAddress(beneficiary);
        data.writeU256(blockHeight);

        super('Triggered', data);
    }
}

/**
 * Event emitted when the switch is cancelled after trigger.
 */
@final
class CancelledEvent extends NetEvent {
    constructor(owner: Address, blockHeight: u256) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeAddress(owner);
        data.writeU256(blockHeight);

        super('Cancelled', data);
    }
}

/**
 * Event emitted when the beneficiary is updated.
 */
@final
class BeneficiaryUpdatedEvent extends NetEvent {
    constructor(oldBeneficiary: Address, newBeneficiary: Address) {
        const data: BytesWriter = new BytesWriter(32 + 32);
        data.writeAddress(oldBeneficiary);
        data.writeAddress(newBeneficiary);

        super('BeneficiaryUpdated', data);
    }
}

/**
 * Dead Man's Switch contract for OPNet.
 *
 * Allows an owner to store encrypted data on-chain with a heartbeat mechanism.
 * If the owner fails to check in within the heartbeat interval, anyone can
 * trigger the switch, which makes the encrypted decryption key accessible
 * to the beneficiary.
 */
@final
export class DeadMansSwitch extends OP_NET {
    /**
     * Storage pointer allocations - each must be unique.
     *
     * Layout:
     * Pointer 0: lastCheckin (StoredU256)
     * Pointer 1: heartbeatInterval (StoredU256)
     * Pointer 2: gracePeriod (StoredU256)
     * Pointer 3: status (StoredU256)
     * Pointer 4: chunkCount (StoredU256)
     * Pointer 5: triggerBlock (StoredU256)
     * Pointer 6: owner (StoredAddress)
     * Pointer 7: beneficiary (StoredAddress)
     * Pointer 8: encryptedKey (multi-slot bytes)
     * Pointer 9: dataChunks (multi-slot bytes, sub-keyed by chunk index)
     */
    private readonly lastCheckinPointer: u16 = Blockchain.nextPointer;
    private readonly heartbeatIntervalPointer: u16 = Blockchain.nextPointer;
    private readonly gracePeriodPointer: u16 = Blockchain.nextPointer;
    private readonly statusPointer: u16 = Blockchain.nextPointer;
    private readonly chunkCountPointer: u16 = Blockchain.nextPointer;
    private readonly triggerBlockPointer: u16 = Blockchain.nextPointer;
    private readonly ownerPointer: u16 = Blockchain.nextPointer;
    private readonly beneficiaryPointer: u16 = Blockchain.nextPointer;
    private readonly encryptedKeyPointer: u16 = Blockchain.nextPointer;
    private readonly dataChunksPointer: u16 = Blockchain.nextPointer;

    /** Stored u256 values. */
    private readonly lastCheckin: StoredU256 = new StoredU256(
        this.lastCheckinPointer,
        EMPTY_POINTER,
    );

    private readonly heartbeatInterval: StoredU256 = new StoredU256(
        this.heartbeatIntervalPointer,
        EMPTY_POINTER,
    );

    private readonly gracePeriod: StoredU256 = new StoredU256(
        this.gracePeriodPointer,
        EMPTY_POINTER,
    );

    private readonly status: StoredU256 = new StoredU256(
        this.statusPointer,
        EMPTY_POINTER,
    );

    private readonly chunkCount: StoredU256 = new StoredU256(
        this.chunkCountPointer,
        EMPTY_POINTER,
    );

    private readonly triggerBlock: StoredU256 = new StoredU256(
        this.triggerBlockPointer,
        EMPTY_POINTER,
    );

    /** Stored addresses. */
    private readonly owner: StoredAddress = new StoredAddress(this.ownerPointer);
    private readonly beneficiary: StoredAddress = new StoredAddress(this.beneficiaryPointer);

    public constructor() {
        super();
    }

    /**
     * Initializes the Dead Man's Switch on first deployment.
     *
     * Calldata format:
     * - ownerAddress: Address (32 bytes)
     * - beneficiaryAddress: Address (32 bytes)
     * - heartbeatInterval: u256 (block count)
     * - gracePeriod: u256 (block count)
     */
    public override onDeployment(calldata: Calldata): void {
        const ownerAddr: Address = calldata.readAddress();
        const beneficiaryAddr: Address = calldata.readAddress();
        const interval: u256 = calldata.readU256();
        const grace: u256 = calldata.readU256();

        if (ownerAddr.equals(Address.zero())) {
            throw new Revert('Owner cannot be zero address');
        }

        if (beneficiaryAddr.equals(Address.zero())) {
            throw new Revert('Beneficiary cannot be zero address');
        }

        if (interval.isZero()) {
            throw new Revert('Heartbeat interval must be greater than zero');
        }

        if (grace.isZero()) {
            throw new Revert('Grace period must be greater than zero');
        }

        this.owner.value = ownerAddr;
        this.beneficiary.value = beneficiaryAddr;
        this.heartbeatInterval.value = interval;
        this.gracePeriod.value = grace;
        this.lastCheckin.value = Blockchain.block.numberU256;
        this.status.value = STATUS_ACTIVE;
        this.chunkCount.value = u256.Zero;
        this.triggerBlock.value = u256.Zero;
    }

    /**
     * Owner checks in, resetting the heartbeat timer.
     * Only callable when the switch is ACTIVE.
     */
    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public checkin(_calldata: Calldata): BytesWriter {
        this.ensureOwner();
        this.ensureActive();

        const currentBlock: u256 = Blockchain.block.numberU256;
        this.lastCheckin.value = currentBlock;

        this.emitEvent(new CheckedInEvent(this.owner.value, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Stores an encrypted data chunk at the given index.
     * Data is stored across multiple 32-byte storage slots.
     *
     * Calldata: chunkIndex (u256), encryptedData (length-prefixed bytes)
     */
    @method(
        { name: 'chunkIndex', type: ABIDataTypes.UINT256 },
        { name: 'encryptedData', type: ABIDataTypes.BYTES },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public storeData(calldata: Calldata): BytesWriter {
        this.ensureOwner();
        this.ensureActive();

        const chunkIndex: u256 = calldata.readU256();
        const encryptedData: Uint8Array = calldata.readBytesWithLength();

        if (encryptedData.length === 0) {
            throw new Revert('Data cannot be empty');
        }

        const subPtr: Uint8Array = this.u256ToSubPointer(chunkIndex);
        this.storeMultiSlotBytes(this.dataChunksPointer, subPtr, encryptedData);

        const currentCount: u256 = this.chunkCount.value;
        const indexPlusOne: u256 = SafeMath.add(chunkIndex, u256.One);
        if (indexPlusOne > currentCount) {
            this.chunkCount.value = indexPlusOne;
        }

        this.emitEvent(
            new DataStoredEvent(chunkIndex, u256.fromU32(encryptedData.length)),
        );

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Stores the encrypted decryption key (encrypted to the beneficiary's ML-DSA public key).
     * The key is stored across multiple 32-byte storage slots.
     *
     * Calldata: encryptedKey (length-prefixed bytes)
     */
    @method({ name: 'encryptedKey', type: ABIDataTypes.BYTES })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public storeDecryptionKey(calldata: Calldata): BytesWriter {
        this.ensureOwner();
        this.ensureActive();

        const encryptedKey: Uint8Array = calldata.readBytesWithLength();

        if (encryptedKey.length === 0) {
            throw new Revert('Encrypted key cannot be empty');
        }

        this.storeMultiSlotBytes(this.encryptedKeyPointer, EMPTY_POINTER, encryptedKey);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Triggers the switch if the heartbeat timer has expired.
     * Anyone can call this method.
     * Emits a Triggered event.
     */
    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public trigger(_calldata: Calldata): BytesWriter {
        const currentStatus: u256 = this.status.value;
        if (u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch already triggered');
        }

        if (u256.eq(currentStatus, STATUS_CANCELLED)) {
            throw new Revert('Switch has been cancelled');
        }

        const currentBlock: u256 = Blockchain.block.numberU256;
        const lastCheck: u256 = this.lastCheckin.value;
        const interval: u256 = this.heartbeatInterval.value;
        const deadline: u256 = SafeMath.add(lastCheck, interval);

        if (currentBlock <= deadline) {
            throw new Revert('Heartbeat has not expired yet');
        }

        this.status.value = STATUS_TRIGGERED;
        this.triggerBlock.value = currentBlock;

        const beneficiaryAddr: Address = this.beneficiary.value;
        this.emitEvent(new TriggeredEvent(beneficiaryAddr, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Owner cancels the triggered switch within the grace period.
     * Resets the switch back to ACTIVE and updates the last checkin.
     */
    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public cancel(_calldata: Calldata): BytesWriter {
        this.ensureOwner();

        const currentStatus: u256 = this.status.value;
        if (!u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch is not triggered');
        }

        const currentBlock: u256 = Blockchain.block.numberU256;
        const trigBlock: u256 = this.triggerBlock.value;
        const grace: u256 = this.gracePeriod.value;
        const graceDeadline: u256 = SafeMath.add(trigBlock, grace);

        if (currentBlock > graceDeadline) {
            throw new Revert('Grace period has expired');
        }

        this.status.value = STATUS_ACTIVE;
        this.lastCheckin.value = currentBlock;
        this.triggerBlock.value = u256.Zero;

        this.emitEvent(new CancelledEvent(this.owner.value, currentBlock));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Updates the beneficiary address. Only callable by the owner when ACTIVE.
     *
     * Calldata: newBeneficiary (Address)
     */
    @method({ name: 'newBeneficiary', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public updateBeneficiary(calldata: Calldata): BytesWriter {
        this.ensureOwner();
        this.ensureActive();

        const newBeneficiary: Address = calldata.readAddress();
        if (newBeneficiary.equals(Address.zero())) {
            throw new Revert('Beneficiary cannot be zero address');
        }

        const oldBeneficiary: Address = this.beneficiary.value;
        this.beneficiary.value = newBeneficiary;

        this.emitEvent(new BeneficiaryUpdatedEvent(oldBeneficiary, newBeneficiary));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Updates the heartbeat interval. Only callable by the owner when ACTIVE.
     *
     * Calldata: newInterval (u256)
     */
    @method({ name: 'newInterval', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public updateInterval(calldata: Calldata): BytesWriter {
        this.ensureOwner();
        this.ensureActive();

        const newInterval: u256 = calldata.readU256();
        if (newInterval.isZero()) {
            throw new Revert('Interval must be greater than zero');
        }

        this.heartbeatInterval.value = newInterval;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Returns the current status: 0 = ACTIVE, 1 = TRIGGERED, 2 = CANCELLED.
     */
    @method()
    @returns({ name: 'status', type: ABIDataTypes.UINT256 })
    public getStatus(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.status.value);
        return writer;
    }

    /**
     * Returns the block number of the last check-in.
     */
    @method()
    @returns({ name: 'lastCheckin', type: ABIDataTypes.UINT256 })
    public getLastCheckin(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.lastCheckin.value);
        return writer;
    }

    /**
     * Returns the encrypted data chunk at the given index.
     *
     * Calldata: chunkIndex (u256)
     */
    @method({ name: 'chunkIndex', type: ABIDataTypes.UINT256 })
    @returns({ name: 'data', type: ABIDataTypes.BYTES })
    public getData(calldata: Calldata): BytesWriter {
        const chunkIndex: u256 = calldata.readU256();
        const count: u256 = this.chunkCount.value;

        if (chunkIndex >= count) {
            throw new Revert('Chunk index out of bounds');
        }

        const subPtr: Uint8Array = this.u256ToSubPointer(chunkIndex);
        const data: Uint8Array = this.loadMultiSlotBytes(this.dataChunksPointer, subPtr);

        const writer: BytesWriter = new BytesWriter(i32(data.length) + 4);
        writer.writeBytesWithLength(data);
        return writer;
    }

    /**
     * Returns the encrypted decryption key. Only accessible after the switch is triggered.
     */
    @method()
    @returns({ name: 'encryptedKey', type: ABIDataTypes.BYTES })
    public getDecryptionKey(_calldata: Calldata): BytesWriter {
        const currentStatus: u256 = this.status.value;
        if (!u256.eq(currentStatus, STATUS_TRIGGERED)) {
            throw new Revert('Switch has not been triggered');
        }

        const key: Uint8Array = this.loadMultiSlotBytes(this.encryptedKeyPointer, EMPTY_POINTER);

        const writer: BytesWriter = new BytesWriter(i32(key.length) + 4);
        writer.writeBytesWithLength(key);
        return writer;
    }

    /**
     * Returns the number of stored data chunks.
     */
    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getChunkCount(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this.chunkCount.value);
        return writer;
    }

    /**
     * Returns whether the heartbeat timer has expired.
     */
    @method()
    @returns({ name: 'expired', type: ABIDataTypes.BOOL })
    public isExpired(_calldata: Calldata): BytesWriter {
        const currentBlock: u256 = Blockchain.block.numberU256;
        const lastCheck: u256 = this.lastCheckin.value;
        const interval: u256 = this.heartbeatInterval.value;
        const deadline: u256 = SafeMath.add(lastCheck, interval);

        const expired: bool = currentBlock > deadline;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(expired);
        return writer;
    }

    /**
     * Asserts that the caller is the owner.
     */
    private ensureOwner(): void {
        const ownerAddr: Address = this.owner.value;
        if (!Blockchain.tx.sender.equals(ownerAddr)) {
            throw new Revert('Only owner can call this method');
        }
    }

    /**
     * Asserts that the switch status is ACTIVE.
     */
    private ensureActive(): void {
        const currentStatus: u256 = this.status.value;
        if (!u256.eq(currentStatus, STATUS_ACTIVE)) {
            throw new Revert('Switch is not active');
        }
    }

    /**
     * Stores a variable-length byte array across multiple 32-byte storage slots.
     *
     * Slot 0: first 4 bytes = length (big-endian u32), next 28 bytes = data start
     * Slot N (N > 0): 32 bytes of data each
     *
     * @param pointer - The storage pointer identifier
     * @param subPointer - The sub-pointer (e.g., chunk index as Uint8Array)
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
     * @param subPointer - The sub-pointer (e.g., chunk index as Uint8Array)
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

    /**
     * Converts a u256 to a 30-byte Uint8Array for use as a sub-pointer.
     * Takes the last 30 bytes of the u256's 32-byte big-endian representation.
     */
    private u256ToSubPointer(value: u256): Uint8Array {
        const bytes32: Uint8Array = value.toUint8Array(true);
        const sub: Uint8Array = new Uint8Array(30);
        for (let i: u32 = 0; i < 30; i++) {
            sub[i] = bytes32[i + 2];
        }
        return sub;
    }
}
