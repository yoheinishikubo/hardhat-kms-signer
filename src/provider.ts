import {
  createSignature,
  getEthAddressFromKMS,
} from "@yoheinishikubo/eth-signer-kms";

import {
  getPublicKey,
  getEthereumAddress,
  requestKmsSignature,
  determineCorrectV,
} from "ethers-gcp-kms-signer/dist/util/gcp-kms-utils";

import { KMS } from "@aws-sdk/client-kms";
import { BigNumber, utils } from "ethers";
import {
  TypedDataDomain,
  TypedDataField,
} from "@ethersproject/abstract-signer"; // For EIP-712 types
import { keccak256, toUtf8Bytes } from "ethers/lib/utils"; // Import toUtf8Bytes
import { rpcTransactionRequest } from "hardhat/internal/core/jsonrpc/types/input/transactionRequest";
import { validateParams } from "hardhat/internal/core/jsonrpc/types/input/validation";
import { ProviderWrapperWithChainId } from "hardhat/internal/core/providers/chainId";
import { EIP1193Provider, RequestArguments } from "hardhat/types";
import { GcpKmsSignerCredentials } from "./type-extensions"; // Assuming this defines the GCP credentials structure

import { toHexString } from "./utils"; // Assuming this utility exists

// Structure for EIP-712 typed data (adjust based on actual usage if needed)
interface TypedData {
  types: Record<string, Array<TypedDataField>>;
  primaryType: string;
  domain: TypedDataDomain;
  message: Record<string, any>;
}

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

    // Validate sender address if provided in params for signing methods
    const validateSender = (addressFromParams: string) => {
      if (utils.getAddress(addressFromParams) !== utils.getAddress(sender)) {
        throw new Error(
          `Requested sender (${addressFromParams}) does not match KMS key address (${sender})`
        );
      }
    };

    if (method === "eth_sendTransaction") {
      const [txRequest] = validateParams(params, rpcTransactionRequest);
      if (
        txRequest.from &&
        utils.getAddress(utils.hexlify(txRequest.from)) !==
          utils.getAddress(sender)
      ) {
        throw new Error(
          `Requested sender (${txRequest.from}) does not match KMS key address (${sender})`
        );
      }

      const tx = await utils.resolveProperties(txRequest);
      const nonce = tx.nonce ?? (await this._getNonce(sender));
      const baseTx: utils.UnsignedTransaction = {
        chainId: (await this._getChainId()) || undefined,
        data: tx.data,
        gasLimit: tx.gas,
        gasPrice: tx.gasPrice,
        nonce: Number(nonce),
        type: 2, // Default to EIP-1559
        to: toHexString(tx.to),
        value: tx.value,
        maxFeePerGas: tx.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas?.toString(),
      };

      // Handle legacy transaction type
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
      const sig = await this._signDigest(hash); // Use helper method

      const rawTx = utils.serializeTransaction(baseTx, sig);

      return this._wrappedProvider.request({
        method: "eth_sendRawTransaction",
        params: [rawTx],
      });
    } else if (method === "personal_sign") {
      // Params usually are [message, address]
      const [messageHex, address] = params as [string, string];
      validateSender(address);

      const messageBytes = utils.arrayify(messageHex);
      const messagePrefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
      const prefixBytes = toUtf8Bytes(messagePrefix);
      const messageToSign = utils.concat([prefixBytes, messageBytes]);
      const hash = keccak256(messageToSign);

      return this._signDigest(hash);
    } else if (method === "eth_signTypedData_v4") {
      // Params usually are [address, typedDataJsonString]
      const [address, typedDataJsonString] = params as [string, string];
      validateSender(address);

      const typedData: TypedData = JSON.parse(typedDataJsonString);

      // ethers.js utility handles EIP-712 encoding and hashing
      const hash = utils._TypedDataEncoder.hash(
        typedData.domain,
        typedData.types,
        typedData.message
      );

      return this._signDigest(hash);
    } else if (
      args.method === "eth_accounts" ||
      args.method === "eth_requestAccounts"
    ) {
      return [sender];
    }

    // Fallback to wrapped provider for other methods
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

  // Helper to sign an arbitrary digest (hash)
  private async _signDigest(digest: string): Promise<string> {
    const sender = await this._getSender(); // Ensure sender is available
    // createSignature from @yoheinishikubo/eth-signer-kms already returns
    // the joined signature {r, s, v} needed by ethers
    const sig = await createSignature({
      kmsInstance: this.kmsInstance,
      keyId: this.kmsKeyId,
      message: digest, // Pass the digest directly
      address: sender,
    });

    // createSignature should return the full signature string including 'v'
    // If it only returns {r, s}, you'd need to reconstruct 'v' and join.
    // Assuming it returns the full signature string like '0x...'
    return utils.joinSignature(sig); // Ensure it's in the correct format
  }
}

// ==========================================================================
// GCP Signer
// ==========================================================================

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

    // Validate sender address if provided in params for signing methods
    const validateSender = (addressFromParams: string) => {
      if (utils.getAddress(addressFromParams) !== utils.getAddress(sender)) {
        throw new Error(
          `Requested sender (${addressFromParams}) does not match KMS key address (${sender})`
        );
      }
    };

    if (method === "eth_sendTransaction") {
      const [txRequest] = validateParams(params, rpcTransactionRequest);
      if (
        txRequest.from &&
        utils.getAddress(utils.hexlify(txRequest.from)) !==
          utils.getAddress(sender)
      ) {
        throw new Error(
          `Requested sender (${txRequest.from}) does not match KMS key address (${sender})`
        );
      }

      const tx = await utils.resolveProperties(txRequest);
      const nonce = tx.nonce ?? (await this._getNonce(sender));
      const baseTx: utils.UnsignedTransaction = {
        chainId: (await this._getChainId()) || undefined,
        data: tx.data,
        gasLimit: tx.gas,
        gasPrice: tx.gasPrice,
        nonce: Number(nonce),
        type: 2, // Default to EIP-1559
        to: toHexString(tx.to),
        value: tx.value,
        maxFeePerGas: tx.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas?.toString(),
      };

      // Handle legacy transaction type
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
      const sig = await this._signDigest(hash); // Use existing helper

      const rawTx = utils.serializeTransaction(baseTx, sig);

      return this._wrappedProvider.request({
        method: "eth_sendRawTransaction",
        params: [rawTx],
      });
    } else if (method === "personal_sign") {
      // Params are [message, address]
      const [messageHex, address] = params as [string, string];
      validateSender(address);

      const messageBytes = utils.arrayify(messageHex);
      const messagePrefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
      const prefixBytes = toUtf8Bytes(messagePrefix);
      const messageToSign = utils.concat([prefixBytes, messageBytes]);
      const hash = keccak256(messageToSign);

      return this._signDigest(hash);
    } else if (method === "eth_signTypedData_v4") {
      // Params are [address, typedDataJsonString]
      const [address, typedDataJsonString] = params as [string, string];
      validateSender(address);

      // 1. Parse the full typed data JSON
      const typedData: TypedData = JSON.parse(typedDataJsonString);

      // 2. **CRITICAL STEP:** Create a copy of the types and remove EIP712Domain
      //    The original `typedData.types` object received from the client *should*
      //    contain EIP712Domain as per the spec. We remove it specifically for
      //    the ethers.js low-level hash function.
      const types = { ...typedData.types }; // Create a shallow copy

      // Ensure the primaryType exists in the parsed data
      if (!typedData.primaryType || !types[typedData.primaryType]) {
        throw new Error("Invalid typed data: Missing or invalid primaryType.");
      }

      // Remove EIP712Domain if it exists
      delete types.EIP712Domain;

      // 3. Hash using the separated domain, the *modified* types, and the message
      const hash = utils._TypedDataEncoder.hash(
        typedData.domain,
        types, // Pass the modified types object (without EIP712Domain)
        typedData.message
      );

      // 4. Sign the resulting hash
      return this._signDigest(hash);
    } else if (
      args.method === "eth_accounts" ||
      args.method === "eth_requestAccounts"
    ) {
      return [sender];
    }

    // Fallback to wrapped provider for other methods
    return this._wrappedProvider.request(args);
  }

  private async _getSender(): Promise<string> {
    if (!this.ethAddress) {
      const publicKey = await getPublicKey(this.kmsCredentials);
      this.ethAddress = await getEthereumAddress(publicKey); // Ensure this returns checksummed address or checksum it
      this.ethAddress = utils.getAddress(this.ethAddress); // Checksum address
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

  // Existing helper to sign an arbitrary digest (hash)
  async _signDigest(digestString: string): Promise<string> {
    // Ensure digest is 32 bytes hex string
    const digestBuffer = Buffer.from(utils.arrayify(digestString)); // Convert hex string digest to Buffer
    if (digestBuffer.length !== 32) {
      throw new Error(
        `Invalid digest length. Expected 32 bytes, got ${digestBuffer.length}`
      );
    }
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials); // Pass Buffer
    const ethAddr = await this._getSender();
    // determineCorrectV likely needs the digest as a Buffer too
    const { v } = determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr);
    return utils.joinSignature({
      v,
      r: `0x${sig.r.toString("hex")}`,
      s: `0x${sig.s.toString("hex")}`,
    });
  }
}
