import {
  createSignature,
  getEthAddressFromKMS,
} from "@yoheinishikubo/eth-signer-kms";

import {
  getPublicKey,
  getEthereumAddress,
  requestKmsSignature,
  determineCorrectV
} from 'ethers-gcp-kms-signer/dist/util/gcp-kms-utils'

import { KMS } from "aws-sdk";
import { BigNumber, utils } from "ethers";
import { keccak256 } from "ethers/lib/utils";
import { rpcTransactionRequest } from "hardhat/internal/core/jsonrpc/types/input/transactionRequest";
import { validateParams } from "hardhat/internal/core/jsonrpc/types/input/validation";
import { ProviderWrapperWithChainId } from "hardhat/internal/core/providers/chainId";
import { EIP1193Provider, RequestArguments } from "hardhat/types";
import { GcpKmsSignerCredentials } from "./type-extensions";

import { toHexString } from "./utils";

export class KMSSigner extends ProviderWrapperWithChainId {
  public kmsKeyId: string;
  public kmsInstance: KMS;
  public ethAddress?: string;

  constructor(provider: EIP1193Provider, kmsKeyId: string) {
    super(provider);
    this.kmsKeyId = kmsKeyId;
    this.kmsInstance = new KMS();
  }

  public async request(args: RequestArguments): Promise<unknown> {
    const method = args.method;
    const params = this._getParams(args);
    const sender = await this._getSender();
    if (method === "eth_sendTransaction") {
      const [txRequest] = validateParams(params, rpcTransactionRequest);
      const tx = await utils.resolveProperties(txRequest);
      const nonce = tx.nonce ?? (await this._getNonce(sender));
      const baseTx: utils.UnsignedTransaction = {
        chainId: (await this._getChainId()) || undefined,
        data: tx.data,
        gasLimit: tx.gas,
        gasPrice: tx.gasPrice,
        nonce: Number(nonce),
        type: 2,
        to: toHexString(tx.to),
        value: tx.value,
        maxFeePerGas: tx.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas?.toString(),
      };

      if (
        baseTx.maxFeePerGas === undefined &&
        baseTx.maxPriorityFeePerGas === undefined
      ) {
        baseTx.type = 0;
        delete baseTx.maxFeePerGas;
        delete baseTx.maxPriorityFeePerGas;
      }

      const unsignedTx = utils.serializeTransaction(baseTx);
      const hash = keccak256(utils.arrayify(unsignedTx));
      const sig = await createSignature({
        kmsInstance: this.kmsInstance,
        keyId: this.kmsKeyId,
        message: hash,
        address: sender,
      });

      const rawTx = utils.serializeTransaction(baseTx, sig);

      return this._wrappedProvider.request({
        method: "eth_sendRawTransaction",
        params: [rawTx],
      });
    } else if (
      args.method === "eth_accounts" ||
      args.method === "eth_requestAccounts"
    ) {
      return [sender];
    }

    return this._wrappedProvider.request(args);
  }

  private async _getSender(): Promise<string> {
    if (!this.ethAddress) {
      this.ethAddress = await getEthAddressFromKMS({
        keyId: this.kmsKeyId,
        kmsInstance: this.kmsInstance,
      });
    }
    return this.ethAddress;
  }

  private async _getNonce(address: string): Promise<number> {
    const response = await this._wrappedProvider.request({
      method: "eth_getTransactionCount",
      params: [address, "pending"],
    });

    return BigNumber.from(response).toNumber();
  }
}

export class GCPSigner extends ProviderWrapperWithChainId {
  private kmsCredentials: GcpKmsSignerCredentials;
  public ethAddress?: string;

  constructor(
    provider: EIP1193Provider,
    kmsCredentials: GcpKmsSignerCredentials
  ) {
    super(provider);
    this.kmsCredentials = kmsCredentials;
  }

  public async request(args: RequestArguments): Promise<unknown> {
    const method = args.method;
    const params = this._getParams(args);
    const sender = await this._getSender();
    if (method === "eth_sendTransaction") {
      const [txRequest] = validateParams(params, rpcTransactionRequest);
      const tx = await utils.resolveProperties(txRequest);
      const nonce = tx.nonce ?? (await this._getNonce(sender));
      const baseTx: utils.UnsignedTransaction = {
        chainId: (await this._getChainId()) || undefined,
        data: tx.data,
        gasLimit: tx.gas,
        gasPrice: tx.gasPrice,
        nonce: Number(nonce),
        type: 2,
        to: toHexString(tx.to),
        value: tx.value,
        maxFeePerGas: tx.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas?.toString(),
      };

      if (
        baseTx.maxFeePerGas === undefined &&
        baseTx.maxPriorityFeePerGas === undefined
      ) {
        baseTx.type = 0;
        delete baseTx.maxFeePerGas;
        delete baseTx.maxPriorityFeePerGas;
      }

      const unsignedTx = utils.serializeTransaction(baseTx);
      const hash = keccak256(utils.arrayify(unsignedTx));
      const sig = await this._signDigest(hash);

      const rawTx = utils.serializeTransaction(baseTx, sig);

      return this._wrappedProvider.request({
        method: "eth_sendRawTransaction",
        params: [rawTx],
      });
    } else if (
      args.method === "eth_accounts" ||
      args.method === "eth_requestAccounts"
    ) {
      return [sender];
    }

    return this._wrappedProvider.request(args);
  }

  private async _getSender(): Promise<string> {
    if (!this.ethAddress) {

      const publicKey = await getPublicKey(this.kmsCredentials)
      this.ethAddress = await getEthereumAddress(publicKey)
    }
    return this.ethAddress;
  }

  private async _getNonce(address: string): Promise<number> {
    const response = await this._wrappedProvider.request({
      method: "eth_getTransactionCount",
      params: [address, "pending"],
    });

    return BigNumber.from(response).toNumber();
  }

  async _signDigest(digestString: string): Promise<string> {
    const digestBuffer = Buffer.from(utils.arrayify(digestString))
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials)
    const ethAddr = await this._getSender()
    const { v } = determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr)
    return utils.joinSignature({
      v,
      r: `0x${sig.r.toString('hex')}`,
      s: `0x${sig.s.toString('hex')}`
    })
  }
}
