// Cross-platform bcrypt wrapper: tries native 'bcrypt' first, falls back to 'bcryptjs'.
// Exposes Promise-based hash() and compare() so existing `await` code works unchanged.
let impl;
try {
  impl = require('bcrypt');
} catch (_) {
  impl = require('bcryptjs');
}

function isPromise(x) {
  return x && typeof x.then === 'function';
}

function hash(password, saltRounds = 10) {
  try {
    // If implementation supports promise when no callback is passed
    const maybe = impl.hash && impl.hash(password, saltRounds);
    if (isPromise(maybe)) return maybe;
  } catch (_) { /* fall through */ }
  return new Promise((resolve, reject) => {
    if (impl.hash) {
      // bcryptjs signature supports callback
      impl.hash(password, saltRounds, (err, out) => (err ? reject(err) : resolve(out)));
    } else if (impl.hashSync) {
      try { resolve(impl.hashSync(password, saltRounds)); } catch (e) { reject(e); }
    } else {
      reject(new Error('No bcrypt implementation available'));
    }
  });
}

function compare(password, hashed) {
  try {
    const maybe = impl.compare && impl.compare(password, hashed);
    if (isPromise(maybe)) return maybe;
  } catch (_) { /* fall through */ }
  return new Promise((resolve, reject) => {
    if (impl.compare) {
      impl.compare(password, hashed, (err, same) => (err ? reject(err) : resolve(same)));
    } else if (impl.compareSync) {
      try { resolve(impl.compareSync(password, hashed)); } catch (e) { reject(e); }
    } else {
      resolve(false);
    }
  });
}

module.exports = { hash, compare };
