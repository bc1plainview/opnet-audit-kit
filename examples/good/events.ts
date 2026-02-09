import { u256 } from '@btc-vision/as-bignum/assembly';
import { BytesWriter } from '@btc-vision/btc-runtime/runtime/buffer/BytesWriter';
import { Address } from '@btc-vision/btc-runtime/runtime/types/Address';
import { NetEvent } from '@btc-vision/btc-runtime/runtime/events/NetEvent';
import { ADDRESS_BYTE_LENGTH, U256_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils';

/**
 * Emitted when a new listing is created.
 */
@final
export class ListingCreatedEvent extends NetEvent {
    constructor(
        listingId: u256,
        collection: Address,
        tokenId: u256,
        seller: Address,
        price: u256,
    ) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH,
        );
        data.writeU256(listingId);
        data.writeAddress(collection);
        data.writeU256(tokenId);
        data.writeAddress(seller);
        data.writeU256(price);

        super('ListingCreated', data);
    }
}

/**
 * Emitted when a listing is cancelled.
 */
@final
export class ListingCancelledEvent extends NetEvent {
    constructor(listingId: u256) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        data.writeU256(listingId);

        super('ListingCancelled', data);
    }
}

/**
 * Emitted when a listing results in a sale.
 */
@final
export class ListingSoldEvent extends NetEvent {
    constructor(listingId: u256, buyer: Address, price: u256) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH,
        );
        data.writeU256(listingId);
        data.writeAddress(buyer);
        data.writeU256(price);

        super('ListingSold', data);
    }
}

/**
 * Emitted when a new bid is placed.
 */
@final
export class BidPlacedEvent extends NetEvent {
    constructor(
        bidId: u256,
        collection: Address,
        tokenId: u256,
        bidder: Address,
        amount: u256,
    ) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH,
        );
        data.writeU256(bidId);
        data.writeAddress(collection);
        data.writeU256(tokenId);
        data.writeAddress(bidder);
        data.writeU256(amount);

        super('BidPlaced', data);
    }
}

/**
 * Emitted when a bid is cancelled.
 */
@final
export class BidCancelledEvent extends NetEvent {
    constructor(bidId: u256) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        data.writeU256(bidId);

        super('BidCancelled', data);
    }
}

/**
 * Emitted when a bid is accepted.
 */
@final
export class BidAcceptedEvent extends NetEvent {
    constructor(bidId: u256, seller: Address) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH);
        data.writeU256(bidId);
        data.writeAddress(seller);

        super('BidAccepted', data);
    }
}

/**
 * Emitted when a collection is registered.
 */
@final
export class CollectionRegisteredEvent extends NetEvent {
    constructor(collection: Address, royaltyBps: u256) {
        const data: BytesWriter = new BytesWriter(ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH);
        data.writeAddress(collection);
        data.writeU256(royaltyBps);

        super('CollectionRegistered', data);
    }
}
