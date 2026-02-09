import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    OP721,
    OP721InitParameters,
    Blockchain,
    Address,
    Calldata,
    BytesWriter,
    SafeMath,
    Revert,
} from '@btc-vision/btc-runtime/runtime';

@final
export class SimpleNFT extends OP721 {
    public constructor() {
        super();
    }

    public override onDeployment(calldata: Calldata): void {
        const name: string = calldata.readStringWithLength();
        const symbol: string = calldata.readStringWithLength();
        const baseURI: string = calldata.readStringWithLength();
        const maxSupply: u256 = calldata.readU256();

        this.instantiate(
            new OP721InitParameters(name, symbol, baseURI, maxSupply),
        );
    }

    @method({ name: 'to', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'tokenId', type: ABIDataTypes.UINT256 })
    @emit('Transferred')
    public mint(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const to: Address = calldata.readAddress();
        const tokenId: u256 = this._nextTokenId.value;

        this._mint(to, tokenId);
        this._nextTokenId.value = SafeMath.add(tokenId, u256.One);

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(tokenId);
        return writer;
    }

    @method({ name: 'quantity', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    @emit('Transferred')
    public batchMint(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const quantity: u256 = calldata.readU256();
        const currentSupply: u256 = this.totalSupply;
        const max: u256 = this.maxSupply;

        if (SafeMath.add(currentSupply, quantity) > max) {
            throw new Revert('Exceeds max supply');
        }

        const to: Address = Blockchain.tx.sender;
        const maxMint: u256 = u256.fromU32(50);
        if (quantity > maxMint) {
            throw new Revert('Max 50 per batch');
        }

        for (let i: u256 = u256.Zero; i < quantity; i = SafeMath.add(i, u256.One)) {
            const tokenId: u256 = this._nextTokenId.value;
            this._mint(to, tokenId);
            this._nextTokenId.value = SafeMath.add(tokenId, u256.One);
        }

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }
}
