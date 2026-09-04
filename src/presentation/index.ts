/**
 * Node-only certkit entry point and composition root.
 */
import createCertkit from './createCertkit.js';

const certkit = createCertkit();

export default certkit;
export {certkit, createCertkit};
