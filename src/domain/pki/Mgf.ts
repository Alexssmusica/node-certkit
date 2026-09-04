import {Mgf1} from './Mgf1.js';

export type MgfNamespaceObject = {
  mgf1: ReturnType<typeof Mgf1.createCertkitNamespace>;
};

export class Mgf {
  static createCertkitNamespace(mgf1: ReturnType<typeof Mgf1.createCertkitNamespace>): MgfNamespaceObject {
    return {
      mgf1
    };
  }
}

export default Mgf;
