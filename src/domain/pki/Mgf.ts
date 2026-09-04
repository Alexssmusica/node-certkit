import { Mgf1 } from './Mgf1.js';
import type { MgfNamespaceObject } from './MgfTypes.js';

export class Mgf {
  static createCertkitNamespace(mgf1: ReturnType<typeof Mgf1.createCertkitNamespace>): MgfNamespaceObject {
    return {
      mgf1
    };
  }
}

export default Mgf;
