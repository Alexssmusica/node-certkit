/**
 * Message digest algorithm registry.
 */
import type {MdRegistry} from './MdRegistry.js';

export class DigestRegistry {
  readonly algorithms: Record<string, unknown> = {};

  static createCertkitNamespace(): MdRegistry {
    const registry = new DigestRegistry();
    const md = {
      algorithms: registry.algorithms
    } as MdRegistry;
    return md;
  }
}

export default DigestRegistry;
