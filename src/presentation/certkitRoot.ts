/**
 * Mutable certkit root object assembled by the presentation layer.
 */
import type { CertkitOptions } from './CertkitTypes.js';

const certkit: { options: CertkitOptions } = {
  options: {
    usePureJavaScript: false
  }
};

export default certkit;
