import {BlockCipher} from './BlockCipher.js';
import {CipherModes, CipherModesObject} from './CipherModes.js';

export type CipherAlgorithmFactory = () => unknown;

export type CipherNamespaceObject = {
  algorithms: Record<string, CipherAlgorithmFactory>;
  modes: CipherModesObject;
  createCipher: (algorithm: string | unknown, key: unknown) => BlockCipher;
  createDecipher: (algorithm: string | unknown, key: unknown) => BlockCipher;
  registerAlgorithm: (name: string, algorithm: CipherAlgorithmFactory) => void;
  getAlgorithm: (name: string) => CipherAlgorithmFactory | null;
  BlockCipher: typeof BlockCipher;
};

export class CipherNamespace {
  static createCertkitNamespace(): CipherNamespaceObject {
    const algorithms: Record<string, CipherAlgorithmFactory> = {};
    const modes = CipherModes.createCertkitModes();

    const cipher: CipherNamespaceObject = {
      algorithms,
      modes,
      BlockCipher,
      createCipher(algorithm: string | unknown, key: unknown): BlockCipher {
        let api = algorithm;
        if (typeof api === 'string') {
          api = cipher.getAlgorithm(api);
          if (api) {
            api = (api as CipherAlgorithmFactory)();
          }
        }
        if (!api) {
          throw new Error('Unsupported algorithm: ' + algorithm);
        }

        return new BlockCipher({
          algorithm: api as BlockCipher extends {algorithm: infer A} ? A : never,
          key: key as string,
          decrypt: false
        });
      },
      createDecipher(algorithm: string | unknown, key: unknown): BlockCipher {
        let api = algorithm;
        if (typeof api === 'string') {
          api = cipher.getAlgorithm(api);
          if (api) {
            api = (api as CipherAlgorithmFactory)();
          }
        }
        if (!api) {
          throw new Error('Unsupported algorithm: ' + algorithm);
        }

        return new BlockCipher({
          algorithm: api as BlockCipher extends {algorithm: infer A} ? A : never,
          key: key as string,
          decrypt: true
        });
      },
      registerAlgorithm(name: string, algorithm: CipherAlgorithmFactory): void {
        name = name.toUpperCase();
        algorithms[name] = algorithm;
      },
      getAlgorithm(name: string): CipherAlgorithmFactory | null {
        name = name.toUpperCase();
        if (name in algorithms) {
          return algorithms[name]!;
        }
        return null;
      }
    };

    return cipher;
  }
}

export default CipherNamespace;
