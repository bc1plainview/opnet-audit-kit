import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    AddressMemoryMap,
    Blockchain,
    BytesWriter,
    Calldata,
    encodeSelector,
    OP_NET,
    Revert,
    SafeMath,
    Selector,
    StoredAddress,
    StoredMapU256,
    StoredU256,
    EMPTY_POINTER,
} from '@btc-vision/btc-runtime/runtime';

import { CallResult } from '@btc-vision/btc-runtime/runtime/env/BlockchainEnvironment';

import {
    ListingCreatedEvent,
    ListingCancelledEvent,
    ListingSoldEvent,
    BidPlacedEvent,
    BidCancelledEvent,
    BidAcceptedEvent,
    CollectionRegisteredEvent,
} from './events';

/**
 * OPNet OP721 NFT Marketplace Contract.
 *
 * Multi-tenant marketplace managing listings and bids for any OP721 collection.
 * Extends OP_NET base (not OP721) and interacts with OP721 collections via cross-contract calls.
 *
 * Storage Layout:
 * - Listings: nextListingId, collection, tokenId, seller, price, active
 * - Bids: nextBidId, collection, tokenId, bidder, amount, active
 * - Collections: royaltyBps, royaltyRecipient, registered
 * - Platform: feeBps, feeRecipient, totalVolume, totalListings
 */
@final
export class NFTMarketplace extends OP_NET {
    /** OP721 cross-contract call selectors (SHA256 first 4 bytes) */
    private readonly safeTransferFromSelector: Selector = encodeSelector('safeTransferFrom');
    private readonly isApprovedForAllSelector: Selector = encodeSelector('isApprovedForAll');
    private readonly ownerOfSelector: Selector = encodeSelector('ownerOf');

    /** Custom method selectors for this marketplace */
    private readonly listNFTSelector: Selector = encodeSelector('listNFT');
    private readonly cancelListingSelector: Selector = encodeSelector('cancelListing');
    private readonly buyNFTSelector: Selector = encodeSelector('buyNFT');
    private readonly placeBidSelector: Selector = encodeSelector('placeBid');
    private readonly cancelBidSelector: Selector = encodeSelector('cancelBid');
    private readonly acceptBidSelector: Selector = encodeSelector('acceptBid');
    private readonly registerCollectionSelector: Selector = encodeSelector('registerCollection');
    private readonly setPlatformFeeSelector: Selector = encodeSelector('setPlatformFee');
    private readonly setPlatformFeeRecipientSelector: Selector = encodeSelector('setPlatformFeeRecipient');
    private readonly updateRoyaltySelector: Selector = encodeSelector('updateRoyalty');
    private readonly getListingSelector: Selector = encodeSelector('getListing');
    private readonly getBidSelector: Selector = encodeSelector('getBid');
    private readonly getCollectionInfoSelector: Selector = encodeSelector('getCollectionInfo');
    private readonly getPlatformInfoSelector: Selector = encodeSelector('getPlatformInfo');

    /** Listing storage pointers */
    private readonly nextListingIdPointer: u16 = Blockchain.nextPointer;
    private readonly listingCollectionPointer: u16 = Blockchain.nextPointer;
    private readonly listingTokenIdPointer: u16 = Blockchain.nextPointer;
    private readonly listingSellerPointer: u16 = Blockchain.nextPointer;
    private readonly listingPricePointer: u16 = Blockchain.nextPointer;
    private readonly listingActivePointer: u16 = Blockchain.nextPointer;

    /** Bid storage pointers */
    private readonly nextBidIdPointer: u16 = Blockchain.nextPointer;
    private readonly bidCollectionPointer: u16 = Blockchain.nextPointer;
    private readonly bidTokenIdPointer: u16 = Blockchain.nextPointer;
    private readonly bidBidderPointer: u16 = Blockchain.nextPointer;
    private readonly bidAmountPointer: u16 = Blockchain.nextPointer;
    private readonly bidActivePointer: u16 = Blockchain.nextPointer;

    /** Collection/Royalty storage pointers */
    private readonly collectionRoyaltyBpsPointer: u16 = Blockchain.nextPointer;
    private readonly collectionRoyaltyRecipientPointer: u16 = Blockchain.nextPointer;
    private readonly collectionRegisteredPointer: u16 = Blockchain.nextPointer;

    /** Platform storage pointers */
    private readonly platformFeeBpsPointer: u16 = Blockchain.nextPointer;
    private readonly platformFeeRecipientPointer: u16 = Blockchain.nextPointer;
    private readonly totalVolumePointer: u16 = Blockchain.nextPointer;
    private readonly totalListingsPointer: u16 = Blockchain.nextPointer;

    /**
     * Listing storage: uses StoredMapU256 for u256 -> u256 mappings.
     * Addresses are stored as u256 (32-byte big-endian).
     */
    private readonly nextListingId: StoredU256 = new StoredU256(
        this.nextListingIdPointer,
        EMPTY_POINTER,
    );

    private readonly listingCollectionMap: StoredMapU256 = new StoredMapU256(
        this.listingCollectionPointer,
    );

    private readonly listingTokenIdMap: StoredMapU256 = new StoredMapU256(
        this.listingTokenIdPointer,
    );

    private readonly listingSellerMap: StoredMapU256 = new StoredMapU256(
        this.listingSellerPointer,
    );

    private readonly listingPriceMap: StoredMapU256 = new StoredMapU256(
        this.listingPricePointer,
    );

    private readonly listingActiveMap: StoredMapU256 = new StoredMapU256(
        this.listingActivePointer,
    );

    /** Bid storage: u256 -> u256 mappings for all bid fields */
    private readonly nextBidId: StoredU256 = new StoredU256(
        this.nextBidIdPointer,
        EMPTY_POINTER,
    );

    private readonly bidCollectionMap: StoredMapU256 = new StoredMapU256(
        this.bidCollectionPointer,
    );

    private readonly bidTokenIdMap: StoredMapU256 = new StoredMapU256(
        this.bidTokenIdPointer,
    );

    private readonly bidBidderMap: StoredMapU256 = new StoredMapU256(
        this.bidBidderPointer,
    );

    private readonly bidAmountMap: StoredMapU256 = new StoredMapU256(
        this.bidAmountPointer,
    );

    private readonly bidActiveMap: StoredMapU256 = new StoredMapU256(
        this.bidActivePointer,
    );

    /** Collection/Royalty storage: keyed by collection address */
    private readonly collectionRoyaltyBpsMap: AddressMemoryMap = new AddressMemoryMap(
        this.collectionRoyaltyBpsPointer,
    );

    private readonly collectionRoyaltyRecipientMap: StoredMapU256 = new StoredMapU256(
        this.collectionRoyaltyRecipientPointer,
    );

    private readonly collectionRegisteredMap: AddressMemoryMap = new AddressMemoryMap(
        this.collectionRegisteredPointer,
    );

    /** Platform storage */
    private readonly platformFeeBps: StoredU256 = new StoredU256(
        this.platformFeeBpsPointer,
        EMPTY_POINTER,
    );

    private readonly platformFeeRecipient: StoredAddress = new StoredAddress(
        this.platformFeeRecipientPointer,
    );

    private readonly totalVolume: StoredU256 = new StoredU256(
        this.totalVolumePointer,
        EMPTY_POINTER,
    );

    private readonly totalListings: StoredU256 = new StoredU256(
        this.totalListingsPointer,
        EMPTY_POINTER,
    );

    /** Basis point constants */
    private readonly BPS_DENOMINATOR: u256 = u256.fromU32(10000);
    private readonly MAX_ROYALTY_BPS: u256 = u256.fromU32(1000);
    private readonly MAX_PLATFORM_FEE_BPS: u256 = u256.fromU32(500);
    private readonly ACTIVE: u256 = u256.One;
    private readonly INACTIVE: u256 = u256.Zero;

    public constructor() {
        super();
    }

    /**
     * Called once on deployment. Initializes platform fee recipient and fee bps.
     *
     * @param calldata - Contains: address (fee recipient), u256 (fee bps)
     */
    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);

        const feeRecipient: Address = calldata.readAddress();
        const feeBps: u256 = calldata.readU256();

        if (feeRecipient.isZero()) {
            throw new Revert('Invalid fee recipient');
        }

        if (u256.gt(feeBps, this.MAX_PLATFORM_FEE_BPS)) {
            throw new Revert('Fee exceeds maximum');
        }

        this.platformFeeRecipient.value = feeRecipient;
        this.platformFeeBps.value = feeBps;
        this.nextListingId.value = u256.One;
        this.nextBidId.value = u256.One;
    }

    /**
     * Routes method calls to the appropriate handler.
     */
    public override execute(method: Selector, calldata: Calldata): BytesWriter {
        switch (method) {
            case this.listNFTSelector:
                return this.listNFT(calldata);
            case this.cancelListingSelector:
                return this.cancelListing(calldata);
            case this.buyNFTSelector:
                return this.buyNFT(calldata);
            case this.placeBidSelector:
                return this.placeBid(calldata);
            case this.cancelBidSelector:
                return this.cancelBid(calldata);
            case this.acceptBidSelector:
                return this.acceptBid(calldata);
            case this.registerCollectionSelector:
                return this.registerCollection(calldata);
            case this.setPlatformFeeSelector:
                return this.setPlatformFee(calldata);
            case this.setPlatformFeeRecipientSelector:
                return this.setPlatformFeeRecipient(calldata);
            case this.updateRoyaltySelector:
                return this.updateRoyalty(calldata);
            case this.getListingSelector:
                return this.getListing(calldata);
            case this.getBidSelector:
                return this.getBid(calldata);
            case this.getCollectionInfoSelector:
                return this.getCollectionInfo(calldata);
            case this.getPlatformInfoSelector:
                return this.getPlatformInfo(calldata);
            default:
                return super.execute(method, calldata);
        }
    }

    /**
     * Converts an Address to u256 for storage in StoredMapU256.
     */
    private addressToU256(addr: Address): u256 {
        return u256.fromUint8ArrayBE(addr);
    }

    /**
     * Converts a u256 from storage back to an Address.
     */
    private u256ToAddress(val: u256): Address {
        return Address.fromUint8Array(val.toUint8Array(true));
    }

    /**
     * Creates a new listing for an NFT.
     * Caller must have approved the marketplace via setApprovalForAll on the OP721 collection.
     *
     * @param calldata - Contains: address (collection), u256 (tokenId), u256 (price in satoshis)
     * @returns BytesWriter containing the new listing ID
     */
    private listNFT(calldata: Calldata): BytesWriter {
        const collectionAddr: Address = calldata.readAddress();
        const tokenId: u256 = calldata.readU256();
        const price: u256 = calldata.readU256();
        const sender: Address = Blockchain.tx.sender;

        if (collectionAddr.isZero()) {
            throw new Revert('Invalid collection address');
        }

        if (u256.eq(price, u256.Zero)) {
            throw new Revert('Price must be greater than zero');
        }

        this.verifyOwnership(collectionAddr, tokenId, sender);
        this.verifyApproval(collectionAddr, sender);

        const listingId: u256 = this.nextListingId.value;
        this.nextListingId.value = SafeMath.add(listingId, u256.One);

        this.listingCollectionMap.set(listingId, this.addressToU256(collectionAddr));
        this.listingTokenIdMap.set(listingId, tokenId);
        this.listingSellerMap.set(listingId, this.addressToU256(sender));
        this.listingPriceMap.set(listingId, price);
        this.listingActiveMap.set(listingId, this.ACTIVE);

        this.totalListings.value = SafeMath.add(this.totalListings.value, u256.One);

        this.emitListingCreated(listingId, collectionAddr, tokenId, sender, price);

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(listingId);
        return writer;
    }

    /**
     * Cancels an active listing. Only the seller can cancel.
     *
     * @param calldata - Contains: u256 (listingId)
     */
    private cancelListing(calldata: Calldata): BytesWriter {
        const listingId: u256 = calldata.readU256();
        const sender: Address = Blockchain.tx.sender;

        this.requireActiveListing(listingId);

        const sellerU256: u256 = this.listingSellerMap.get(listingId);
        const seller: Address = this.u256ToAddress(sellerU256);

        if (!sender.equals(seller)) {
            throw new Revert('Only seller can cancel');
        }

        this.listingActiveMap.set(listingId, this.INACTIVE);

        this.emitListingCancelled(listingId);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Buys an NFT from an active listing.
     * Executes the NFT transfer from seller to buyer.
     * BTC payment is coordinated at the Bitcoin transaction level.
     *
     * @param calldata - Contains: u256 (listingId)
     */
    private buyNFT(calldata: Calldata): BytesWriter {
        const listingId: u256 = calldata.readU256();
        const buyer: Address = Blockchain.tx.sender;

        this.requireActiveListing(listingId);

        const collectionAddr: Address = this.u256ToAddress(this.listingCollectionMap.get(listingId));
        const tokenId: u256 = this.listingTokenIdMap.get(listingId);
        const seller: Address = this.u256ToAddress(this.listingSellerMap.get(listingId));
        const price: u256 = this.listingPriceMap.get(listingId);

        if (buyer.equals(seller)) {
            throw new Revert('Buyer cannot be seller');
        }

        this.listingActiveMap.set(listingId, this.INACTIVE);
        this.totalVolume.value = SafeMath.add(this.totalVolume.value, price);

        this.executeNFTTransfer(collectionAddr, seller, buyer, tokenId);

        this.emitListingSold(listingId, buyer, price);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Places a bid on an NFT.
     *
     * @param calldata - Contains: address (collection), u256 (tokenId), u256 (bid amount in satoshis)
     * @returns BytesWriter containing the new bid ID
     */
    private placeBid(calldata: Calldata): BytesWriter {
        const collectionAddr: Address = calldata.readAddress();
        const tokenId: u256 = calldata.readU256();
        const bidAmountSatoshis: u256 = calldata.readU256();
        const sender: Address = Blockchain.tx.sender;

        if (collectionAddr.isZero()) {
            throw new Revert('Invalid collection address');
        }

        if (u256.eq(bidAmountSatoshis, u256.Zero)) {
            throw new Revert('Bid amount must be greater than zero');
        }

        const bidId: u256 = this.nextBidId.value;
        this.nextBidId.value = SafeMath.add(bidId, u256.One);

        this.bidCollectionMap.set(bidId, this.addressToU256(collectionAddr));
        this.bidTokenIdMap.set(bidId, tokenId);
        this.bidBidderMap.set(bidId, this.addressToU256(sender));
        this.bidAmountMap.set(bidId, bidAmountSatoshis);
        this.bidActiveMap.set(bidId, this.ACTIVE);

        this.emitBidPlaced(bidId, collectionAddr, tokenId, sender, bidAmountSatoshis);

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(bidId);
        return writer;
    }

    /**
     * Cancels an active bid. Only the bidder can cancel.
     *
     * @param calldata - Contains: u256 (bidId)
     */
    private cancelBid(calldata: Calldata): BytesWriter {
        const bidId: u256 = calldata.readU256();
        const sender: Address = Blockchain.tx.sender;

        this.requireActiveBid(bidId);

        const bidderU256: u256 = this.bidBidderMap.get(bidId);
        const bidder: Address = this.u256ToAddress(bidderU256);

        if (!sender.equals(bidder)) {
            throw new Revert('Only bidder can cancel');
        }

        this.bidActiveMap.set(bidId, this.INACTIVE);

        this.emitBidCancelled(bidId);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Accepts a bid on an NFT. Only the NFT owner can accept.
     * Transfers NFT from caller (owner) to bidder.
     *
     * @param calldata - Contains: u256 (bidId)
     */
    private acceptBid(calldata: Calldata): BytesWriter {
        const bidId: u256 = calldata.readU256();
        const sender: Address = Blockchain.tx.sender;

        this.requireActiveBid(bidId);

        const collectionAddr: Address = this.u256ToAddress(this.bidCollectionMap.get(bidId));
        const tokenId: u256 = this.bidTokenIdMap.get(bidId);
        const bidder: Address = this.u256ToAddress(this.bidBidderMap.get(bidId));
        const amount: u256 = this.bidAmountMap.get(bidId);

        this.verifyOwnership(collectionAddr, tokenId, sender);

        this.bidActiveMap.set(bidId, this.INACTIVE);
        this.totalVolume.value = SafeMath.add(this.totalVolume.value, amount);

        this.executeNFTTransfer(collectionAddr, sender, bidder, tokenId);

        this.emitBidAccepted(bidId, sender);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Registers a new collection with royalty info. Only deployer can call.
     *
     * @param calldata - Contains: address (collection), u256 (royaltyBps), address (royaltyRecipient)
     */
    private registerCollection(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const collectionAddr: Address = calldata.readAddress();
        const royaltyBps: u256 = calldata.readU256();
        const royaltyRecipient: Address = calldata.readAddress();

        if (collectionAddr.isZero()) {
            throw new Revert('Invalid collection address');
        }

        if (u256.gt(royaltyBps, this.MAX_ROYALTY_BPS)) {
            throw new Revert('Royalty exceeds maximum 10%');
        }

        if (royaltyRecipient.isZero()) {
            throw new Revert('Invalid royalty recipient');
        }

        this.collectionRegisteredMap.set(collectionAddr, u256.One);
        this.collectionRoyaltyBpsMap.set(collectionAddr, royaltyBps);

        const collectionKey: u256 = this.addressToU256(collectionAddr);
        this.collectionRoyaltyRecipientMap.set(collectionKey, this.addressToU256(royaltyRecipient));

        this.emitCollectionRegistered(collectionAddr, royaltyBps);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Sets the platform fee in basis points. Max 500 (5%). Only deployer.
     *
     * @param calldata - Contains: u256 (newFeeBps)
     */
    private setPlatformFee(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newFeeBps: u256 = calldata.readU256();

        if (u256.gt(newFeeBps, this.MAX_PLATFORM_FEE_BPS)) {
            throw new Revert('Fee exceeds maximum 5%');
        }

        this.platformFeeBps.value = newFeeBps;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Sets the platform fee recipient address. Only deployer.
     *
     * @param calldata - Contains: address (newRecipient)
     */
    private setPlatformFeeRecipient(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newRecipient: Address = calldata.readAddress();

        if (newRecipient.isZero()) {
            throw new Revert('Invalid recipient address');
        }

        this.platformFeeRecipient.value = newRecipient;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Updates royalty info for a collection. Only deployer.
     *
     * @param calldata - Contains: address (collection), u256 (newBps), address (newRecipient)
     */
    private updateRoyalty(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const collectionAddr: Address = calldata.readAddress();
        const newBps: u256 = calldata.readU256();
        const newRecipient: Address = calldata.readAddress();

        const isRegistered: u256 = this.collectionRegisteredMap.get(collectionAddr);
        if (u256.eq(isRegistered, u256.Zero)) {
            throw new Revert('Collection not registered');
        }

        if (u256.gt(newBps, this.MAX_ROYALTY_BPS)) {
            throw new Revert('Royalty exceeds maximum 10%');
        }

        if (newRecipient.isZero()) {
            throw new Revert('Invalid royalty recipient');
        }

        this.collectionRoyaltyBpsMap.set(collectionAddr, newBps);

        const collectionKey: u256 = this.addressToU256(collectionAddr);
        this.collectionRoyaltyRecipientMap.set(collectionKey, this.addressToU256(newRecipient));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Returns all listing data for a given listing ID.
     *
     * @param calldata - Contains: u256 (listingId)
     * @returns BytesWriter with collection(32), tokenId(32), seller(32), price(32), active(32)
     */
    private getListing(calldata: Calldata): BytesWriter {
        const listingId: u256 = calldata.readU256();

        const collectionU256: u256 = this.listingCollectionMap.get(listingId);
        const tokenId: u256 = this.listingTokenIdMap.get(listingId);
        const sellerU256: u256 = this.listingSellerMap.get(listingId);
        const price: u256 = this.listingPriceMap.get(listingId);
        const active: u256 = this.listingActiveMap.get(listingId);

        const writer: BytesWriter = new BytesWriter(160);
        writer.writeU256(collectionU256);
        writer.writeU256(tokenId);
        writer.writeU256(sellerU256);
        writer.writeU256(price);
        writer.writeU256(active);
        return writer;
    }

    /**
     * Returns all bid data for a given bid ID.
     *
     * @param calldata - Contains: u256 (bidId)
     * @returns BytesWriter with collection(32), tokenId(32), bidder(32), amount(32), active(32)
     */
    private getBid(calldata: Calldata): BytesWriter {
        const bidId: u256 = calldata.readU256();

        const collectionU256: u256 = this.bidCollectionMap.get(bidId);
        const tokenId: u256 = this.bidTokenIdMap.get(bidId);
        const bidderU256: u256 = this.bidBidderMap.get(bidId);
        const amount: u256 = this.bidAmountMap.get(bidId);
        const active: u256 = this.bidActiveMap.get(bidId);

        const writer: BytesWriter = new BytesWriter(160);
        writer.writeU256(collectionU256);
        writer.writeU256(tokenId);
        writer.writeU256(bidderU256);
        writer.writeU256(amount);
        writer.writeU256(active);
        return writer;
    }

    /**
     * Returns royalty info for a collection.
     *
     * @param calldata - Contains: address (collection)
     * @returns BytesWriter with registered(32), royaltyBps(32), royaltyRecipient(32)
     */
    private getCollectionInfo(calldata: Calldata): BytesWriter {
        const collectionAddr: Address = calldata.readAddress();

        const isRegistered: u256 = this.collectionRegisteredMap.get(collectionAddr);
        const royaltyBps: u256 = this.collectionRoyaltyBpsMap.get(collectionAddr);

        const collectionKey: u256 = this.addressToU256(collectionAddr);
        const recipientU256: u256 = this.collectionRoyaltyRecipientMap.get(collectionKey);

        const writer: BytesWriter = new BytesWriter(96);
        writer.writeU256(isRegistered);
        writer.writeU256(royaltyBps);
        writer.writeU256(recipientU256);
        return writer;
    }

    /**
     * Returns platform info: fee bps, fee recipient, total volume, total listings.
     *
     * @returns BytesWriter with platformFeeBps(32), platformFeeRecipient(32), totalVolume(32), totalListings(32)
     */
    private getPlatformInfo(_calldata: Calldata): BytesWriter {
        const feeBps: u256 = this.platformFeeBps.value;
        const recipient: Address = this.platformFeeRecipient.value;
        const volume: u256 = this.totalVolume.value;
        const listings: u256 = this.totalListings.value;

        const writer: BytesWriter = new BytesWriter(128);
        writer.writeU256(feeBps);
        writer.writeAddress(recipient);
        writer.writeU256(volume);
        writer.writeU256(listings);
        return writer;
    }

    /**
     * Verifies that the given address owns the specified token in the OP721 collection.
     */
    private verifyOwnership(collection: Address, tokenId: u256, expectedOwner: Address): void {
        const ownerOfCalldata: BytesWriter = new BytesWriter(36);
        ownerOfCalldata.writeSelector(this.ownerOfSelector);
        ownerOfCalldata.writeU256(tokenId);

        const result: CallResult = Blockchain.call(collection, ownerOfCalldata);

        if (!result.success) {
            throw new Revert('ownerOf call failed');
        }

        const ownerAddress: Address = result.data.readAddress();

        if (!ownerAddress.equals(expectedOwner)) {
            throw new Revert('Caller is not the token owner');
        }
    }

    /**
     * Verifies that the marketplace is approved to transfer tokens on behalf of the owner.
     */
    private verifyApproval(collection: Address, owner: Address): void {
        const approvalCalldata: BytesWriter = new BytesWriter(68);
        approvalCalldata.writeSelector(this.isApprovedForAllSelector);
        approvalCalldata.writeAddress(owner);
        approvalCalldata.writeAddress(this.address);

        const result: CallResult = Blockchain.call(collection, approvalCalldata);

        if (!result.success) {
            throw new Revert('isApprovedForAll call failed');
        }

        const approved: boolean = result.data.readBoolean();

        if (!approved) {
            throw new Revert('Marketplace not approved for transfers');
        }
    }

    /**
     * Executes an NFT transfer via cross-contract call to safeTransferFrom.
     */
    private executeNFTTransfer(
        collection: Address,
        from: Address,
        to: Address,
        tokenId: u256,
    ): void {
        const transferCalldata: BytesWriter = new BytesWriter(100);
        transferCalldata.writeSelector(this.safeTransferFromSelector);
        transferCalldata.writeAddress(from);
        transferCalldata.writeAddress(to);
        transferCalldata.writeU256(tokenId);

        const result: CallResult = Blockchain.call(collection, transferCalldata);

        if (!result.success) {
            throw new Revert('NFT transfer failed');
        }
    }

    /**
     * Validates that a listing exists and is active.
     */
    private requireActiveListing(listingId: u256): void {
        const currentNextId: u256 = this.nextListingId.value;
        if (u256.ge(listingId, currentNextId) || u256.eq(listingId, u256.Zero)) {
            throw new Revert('Listing does not exist');
        }

        const active: u256 = this.listingActiveMap.get(listingId);
        if (u256.eq(active, this.INACTIVE)) {
            throw new Revert('Listing is not active');
        }
    }

    /**
     * Validates that a bid exists and is active.
     */
    private requireActiveBid(bidId: u256): void {
        const currentNextId: u256 = this.nextBidId.value;
        if (u256.ge(bidId, currentNextId) || u256.eq(bidId, u256.Zero)) {
            throw new Revert('Bid does not exist');
        }

        const active: u256 = this.bidActiveMap.get(bidId);
        if (u256.eq(active, this.INACTIVE)) {
            throw new Revert('Bid is not active');
        }
    }

    /**
     * Emits ListingCreated event.
     */
    private emitListingCreated(
        listingId: u256,
        collection: Address,
        tokenId: u256,
        seller: Address,
        price: u256,
    ): void {
        this.emitEvent(new ListingCreatedEvent(listingId, collection, tokenId, seller, price));
    }

    /**
     * Emits ListingCancelled event.
     */
    private emitListingCancelled(listingId: u256): void {
        this.emitEvent(new ListingCancelledEvent(listingId));
    }

    /**
     * Emits ListingSold event.
     */
    private emitListingSold(listingId: u256, buyer: Address, price: u256): void {
        this.emitEvent(new ListingSoldEvent(listingId, buyer, price));
    }

    /**
     * Emits BidPlaced event.
     */
    private emitBidPlaced(
        bidId: u256,
        collection: Address,
        tokenId: u256,
        bidder: Address,
        amount: u256,
    ): void {
        this.emitEvent(new BidPlacedEvent(bidId, collection, tokenId, bidder, amount));
    }

    /**
     * Emits BidCancelled event.
     */
    private emitBidCancelled(bidId: u256): void {
        this.emitEvent(new BidCancelledEvent(bidId));
    }

    /**
     * Emits BidAccepted event.
     */
    private emitBidAccepted(bidId: u256, seller: Address): void {
        this.emitEvent(new BidAcceptedEvent(bidId, seller));
    }

    /**
     * Emits CollectionRegistered event.
     */
    private emitCollectionRegistered(collection: Address, royaltyBps: u256): void {
        this.emitEvent(new CollectionRegisteredEvent(collection, royaltyBps));
    }
}
