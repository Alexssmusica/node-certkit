import { BlockCipher } from './BlockCipher.js';
import { CipherModes } from './CipherModes.js';
import type { CipherAlgorithm, CipherAlgorithmFactory, CipherNamespaceObject } from './CipherTypes.js';

export class CipherNamespace {
  static createCertkitNamespace(): CipherNamespaceObject {
    const algorithms: Record<string, CipherAlgorithmFactory> = {};
    const modes = CipherModes.createCertkitModes();

    const cipher = {
      algorithms,
      modes,
      BlockCipher,
      createCipher(algorithm: string | CipherAlgorithmFactory, key: string): BlockCipher {
        let api: string | CipherAlgorithmFactory | CipherAlgorithm = algorithm;
        if (typeof api === 'string') {
          const factory = cipher.getAlgorithm(api);
          api = factory ? factory() : api;
        } else if (typeof api === 'function') {
          api = api();
        }
        if (!api || typeof api !== 'object') {
          const algorithmLabel = typeof algorithm === 'string' ? algorithm : 'object';
          throw new Error('Unsupported algorithm: ' + algorithmLabel);
        }

        return new BlockCipher({
          algorithm: api,
          key,
          decrypt: false
        });
      },
      createDecipher(algorithm: string | CipherAlgorithmFactory, key: string): BlockCipher {
        let api: string | CipherAlgorithmFactory | CipherAlgorithm = algorithm;
        if (typeof api === 'string') {
          const factory = cipher.getAlgorithm(api);
          api = factory ? factory() : api;
        } else if (typeof api === 'function') {
          api = api();
        }
        if (!api || typeof api !== 'object') {
          const algorithmLabel = typeof algorithm === 'string' ? algorithm : 'object';
          throw new Error('Unsupported algorithm: ' + algorithmLabel);
        }

        return new BlockCipher({
          algorithm: api,
          key,
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
          return algorithms[name];
        }
        return null;
      }
    };

    return cipher as CipherNamespaceObject;
  }
}

export default CipherNamespace;
