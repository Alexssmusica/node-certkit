import {EcbMode} from './EcbMode.js';
import {CbcMode} from './CbcMode.js';
import {CfbMode} from './CfbMode.js';
import {OfbMode} from './OfbMode.js';
import {CtrMode} from './CtrMode.js';
import {GcmMode} from './GcmMode.js';

export type CipherModesObject = {
  ecb: typeof EcbMode;
  cbc: typeof CbcMode;
  cfb: typeof CfbMode;
  ofb: typeof OfbMode;
  ctr: typeof CtrMode;
  gcm: typeof GcmMode;
};

export class CipherModes {
  static createCertkitModes(): CipherModesObject {
    return {
      ecb: EcbMode,
      cbc: CbcMode,
      cfb: CfbMode,
      ofb: OfbMode,
      ctr: CtrMode,
      gcm: GcmMode
    };
  }
}

export default CipherModes;
