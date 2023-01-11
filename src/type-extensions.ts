import "hardhat/types/config";

export interface GcpKmsSignerCredentials {
  projectId: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  keyVersion: string;
}

declare module "hardhat/types/config" {
  export interface HttpNetworkUserConfig {
    kmsKeyId?: string;
    cpKmsSignerCredentials?: GcpKmsSignerCredentials;
    minMaxFeePerGas?: string | number;
    minMaxPriorityFeePerGas?: string | number;
  }

  export interface HardhatNetworkUserConfig {
    kmsKeyId?: string;
    cpKmsSignerCredentials?: GcpKmsSignerCredentials;
    minMaxFeePerGas?: string | number;
    minMaxPriorityFeePerGas?: string | number;
  }
  export interface HttpNetworkConfig {
    kmsKeyId?: string;
    cpKmsSignerCredentials?: GcpKmsSignerCredentials;
    minMaxFeePerGas?: string | number;
    minMaxPriorityFeePerGas?: string | number;
  }
  export interface HardhatNetworkConfig {
    kmsKeyId?: string;
    cpKmsSignerCredentials?: GcpKmsSignerCredentials;
    minMaxFeePerGas?: string | number;
    minMaxPriorityFeePerGas?: string | number;
  }
}
