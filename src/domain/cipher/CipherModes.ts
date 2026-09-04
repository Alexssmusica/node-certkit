import { EcbMode } from './EcbMode.js';
import { CbcMode } from './CbcMode.js';
import { CfbMode } from './CfbMode.js';
import { OfbMode } from './OfbMode.js';
import { CtrMode } from './CtrMode.js';
import { GcmMode } from './GcmMode.js';
import type { CipherModesObject } from './CipherTypes.js';

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
