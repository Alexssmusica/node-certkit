import os from 'node:os';

type EstimateCoresCallback = (err: null, cores: number) => void;
type EstimateCoresOptions = { update?: boolean };

export class EnvInfo {
  static nextTick = process.nextTick.bind(process);

  static setImmediate: typeof setImmediate | typeof EnvInfo.nextTick = typeof setImmediate === 'function' ? setImmediate : EnvInfo.nextTick;

  static isNodejs = true;

  static globalScope = globalThis;

  static estimateCores(
    target: { cores?: number },
    options: EstimateCoresOptions | EstimateCoresCallback,
    callback?: EstimateCoresCallback
  ): void {
    let opts: EstimateCoresOptions;
    let cb: EstimateCoresCallback;
    if (typeof options === 'function') {
      cb = options;
      opts = {};
    } else {
      opts = options;
      cb = callback!;
    }
    if ('cores' in target && !opts.update) {
      return cb(null, target.cores!);
    }
    target.cores = Math.max(1, os.cpus().length);
    return cb(null, target.cores);
  }
}
