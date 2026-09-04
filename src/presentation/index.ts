/**
 * Node-only certkit entry point and composition root.
 */
import {createInfrastructure} from '../infrastructure/index.js';
import {LoadPkcs12UseCase, type LoadPkcs12CertkitApi} from '../application/certificate/LoadPkcs12UseCase.js';
import createCertkit from './createCertkit.js';

const certkit = createCertkit();

export function createLoadPkcs12UseCase(): LoadPkcs12UseCase {
  return new LoadPkcs12UseCase(createInfrastructure(), certkit as unknown as LoadPkcs12CertkitApi);
}

export default certkit;
export {certkit, createCertkit};
export {LoadPkcs12UseCase};
