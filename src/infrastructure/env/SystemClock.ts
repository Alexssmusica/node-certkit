import type {Clock} from '../../domain/ports/index.js';

export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}
