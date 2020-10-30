module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete installedModules[moduleId];
/******/ 		}
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "P7tk");
/******/ })
/************************************************************************/
/******/ ({

/***/ "+00W":
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__("RF0s").default;
module.exports.default = module.exports;


/***/ }),

/***/ "+6AY":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = {
    applyToDefaults: __webpack_require__("xkC2"),
    assert: __webpack_require__("2BAz"),
    Bench: __webpack_require__("OAWW"),
    block: __webpack_require__("6nrT"),
    clone: __webpack_require__("JT7C"),
    contain: __webpack_require__("5sA0"),
    deepEqual: __webpack_require__("bkX/"),
    Error: __webpack_require__("p9XZ"),
    escapeHeaderAttribute: __webpack_require__("kYX4"),
    escapeHtml: __webpack_require__("9qEa"),
    escapeJson: __webpack_require__("bDas"),
    escapeRegex: __webpack_require__("3AyT"),
    flatten: __webpack_require__("Nfr/"),
    ignore: __webpack_require__("NqRk"),
    intersect: __webpack_require__("fk1j"),
    isPromise: __webpack_require__("awVX"),
    merge: __webpack_require__("8AeH"),
    once: __webpack_require__("YTOW"),
    reach: __webpack_require__("eq/D"),
    reachTemplate: __webpack_require__("B2tm"),
    stringify: __webpack_require__("PX5Q"),
    wait: __webpack_require__("/yrF")
};


/***/ }),

/***/ "+du+":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const handlers_1 = tslib_1.__importDefault(__webpack_require__("PC/d"));
const oidc_client_1 = tslib_1.__importDefault(__webpack_require__("O3E8"));
const cookie_store_1 = tslib_1.__importDefault(__webpack_require__("qQzh"));
const settings_1 = tslib_1.__importDefault(__webpack_require__("Mu3n"));
function createInstance(settings) {
    if (!settings.domain) {
        throw new Error('A valid Auth0 Domain must be provided');
    }
    if (!settings.clientId) {
        throw new Error('A valid Auth0 Client ID must be provided');
    }
    if (!settings.clientSecret) {
        throw new Error('A valid Auth0 Client Secret must be provided');
    }
    if (!settings.session) {
        throw new Error('The session configuration is required');
    }
    if (!settings.session.cookieSecret) {
        throw new Error('A valid session cookie secret is required');
    }
    const clientProvider = oidc_client_1.default(settings);
    const sessionSettings = new settings_1.default(settings.session);
    const store = new cookie_store_1.default(sessionSettings);
    return {
        handleLogin: handlers_1.default.LoginHandler(settings, clientProvider),
        handleLogout: handlers_1.default.LogoutHandler(settings, sessionSettings, clientProvider, store),
        handleCallback: handlers_1.default.CallbackHandler(settings, clientProvider, store),
        handleProfile: handlers_1.default.ProfileHandler(store, clientProvider),
        getSession: handlers_1.default.SessionHandler(store),
        requireAuthentication: handlers_1.default.RequireAuthentication(store),
        tokenCache: handlers_1.default.TokenCache(clientProvider, store)
    };
}
exports.default = createInstance;
//# sourceMappingURL=instance.node.js.map

/***/ }),

/***/ "//Cd":
/***/ (function(module, exports, __webpack_require__) {

const { strict: assert } = __webpack_require__("Qs3B")
const { inspect } = __webpack_require__("jK02")
const { EOL } = __webpack_require__("jle/")

const { keyObjectSupported } = __webpack_require__("pDDt")
const { createPublicKey } = __webpack_require__("1ALl")
const { keyObjectToJWK } = __webpack_require__("gXwc")
const {
  THUMBPRINT_MATERIAL, PUBLIC_MEMBERS, PRIVATE_MEMBERS, JWK_MEMBERS, KEYOBJECT,
  USES_MAPPING, OPS, USES
} = __webpack_require__("ehsS")
const isObject = __webpack_require__("kF1/")
const thumbprint = __webpack_require__("uk5n")
const errors = __webpack_require__("yt7c")

const privateApi = Symbol('privateApi')
const { JWK } = __webpack_require__("N+nT")

class Key {
  constructor (keyObject, { alg, use, kid, key_ops: ops, x5c, x5t, 'x5t#S256': x5t256 } = {}) {
    if (use !== undefined) {
      if (typeof use !== 'string' || !USES.has(use)) {
        throw new TypeError('`use` must be either "sig" or "enc" string when provided')
      }
    }

    if (alg !== undefined) {
      if (typeof alg !== 'string' || !alg) {
        throw new TypeError('`alg` must be a non-empty string when provided')
      }
    }

    if (kid !== undefined) {
      if (typeof kid !== 'string' || !kid) {
        throw new TypeError('`kid` must be a non-empty string when provided')
      }
    }

    if (ops !== undefined) {
      if (!Array.isArray(ops) || !ops.length || ops.some(o => typeof o !== 'string')) {
        throw new TypeError('`key_ops` must be a non-empty array of strings when provided')
      }
      ops = Array.from(new Set(ops)).filter(x => OPS.has(x))
    }

    if (ops && use) {
      if (
        (use === 'enc' && ops.some(x => USES_MAPPING.sig.has(x))) ||
        (use === 'sig' && ops.some(x => USES_MAPPING.enc.has(x)))
      ) {
        throw new errors.JWKInvalid('inconsistent JWK "use" and "key_ops"')
      }
    }

    if (keyObjectSupported && x5c !== undefined) {
      if (!Array.isArray(x5c) || !x5c.length || x5c.some(c => typeof c !== 'string')) {
        throw new TypeError('`x5c` must be an array of one or more PKIX certificates when provided')
      }

      x5c.forEach((cert, i) => {
        let publicKey
        try {
          publicKey = createPublicKey({
            key: `-----BEGIN CERTIFICATE-----${EOL}${(cert.match(/.{1,64}/g) || []).join(EOL)}${EOL}-----END CERTIFICATE-----`, format: 'pem'
          })
        } catch (err) {
          throw new errors.JWKInvalid(`\`x5c\` member at index ${i} is not a valid base64-encoded DER PKIX certificate`)
        }
        if (i === 0) {
          try {
            assert.deepEqual(
              publicKey.export({ type: 'spki', format: 'der' }),
              (keyObject.type === 'public' ? keyObject : createPublicKey(keyObject)).export({ type: 'spki', format: 'der' })
            )
          } catch (err) {
            throw new errors.JWKInvalid('The key in the first `x5c` certificate MUST match the public key represented by the JWK')
          }
        }
      })
    }

    Object.defineProperties(this, {
      [KEYOBJECT]: { value: isObject(keyObject) ? undefined : keyObject },
      keyObject: {
        get () {
          if (!keyObjectSupported) {
            throw new errors.JOSENotSupported('KeyObject class is not supported in your Node.js runtime version')
          }

          return this[KEYOBJECT]
        }
      },
      type: { value: keyObject.type },
      private: { value: keyObject.type === 'private' },
      public: { value: keyObject.type === 'public' },
      secret: { value: keyObject.type === 'secret' },
      alg: { value: alg, enumerable: alg !== undefined },
      use: { value: use, enumerable: use !== undefined },
      x5c: {
        enumerable: x5c !== undefined,
        ...(x5c ? { get () { return [...x5c] } } : { value: undefined })
      },
      key_ops: {
        enumerable: ops !== undefined,
        ...(ops ? { get () { return [...ops] } } : { value: undefined })
      },
      kid: {
        enumerable: true,
        ...(kid ? { value: kid } : {
          get () {
            Object.defineProperty(this, 'kid', { value: this.thumbprint, configurable: false })
            return this.kid
          },
          configurable: true
        })
      },
      ...(x5c ? {
        x5t: {
          enumerable: true,
          ...(x5t ? { value: x5t } : {
            get () {
              Object.defineProperty(this, 'x5t', { value: thumbprint.x5t(this.x5c[0]), configurable: false })
              return this.x5t
            },
            configurable: true
          })
        }
      } : undefined),
      ...(x5c ? {
        'x5t#S256': {
          enumerable: true,
          ...(x5t256 ? { value: x5t256 } : {
            get () {
              Object.defineProperty(this, 'x5t#S256', { value: thumbprint['x5t#S256'](this.x5c[0]), configurable: false })
              return this['x5t#S256']
            },
            configurable: true
          })
        }
      } : undefined),
      thumbprint: {
        get () {
          Object.defineProperty(this, 'thumbprint', { value: thumbprint.kid(this[THUMBPRINT_MATERIAL]()), configurable: false })
          return this.thumbprint
        },
        configurable: true
      }
    })
  }

  toPEM (priv = false, encoding = {}) {
    if (this.secret) {
      throw new TypeError('symmetric keys cannot be exported as PEM')
    }

    if (priv && this.public === true) {
      throw new TypeError('public key cannot be exported as private')
    }

    const { type = priv ? 'pkcs8' : 'spki', cipher, passphrase } = encoding

    let keyObject = this[KEYOBJECT]

    if (!priv) {
      if (this.private) {
        keyObject = createPublicKey(keyObject)
      }
      if (cipher || passphrase) {
        throw new TypeError('cipher and passphrase can only be applied when exporting private keys')
      }
    }

    if (priv) {
      return keyObject.export({ format: 'pem', type, cipher, passphrase })
    }

    return keyObject.export({ format: 'pem', type })
  }

  toJWK (priv = false) {
    if (priv && this.public === true) {
      throw new TypeError('public key cannot be exported as private')
    }

    const components = [...this.constructor[priv ? PRIVATE_MEMBERS : PUBLIC_MEMBERS]]
      .map(k => [k, this[k]])

    const result = {}

    Object.keys(components).forEach((key) => {
      const [k, v] = components[key]

      result[k] = v
    })

    result.kty = this.kty
    result.kid = this.kid

    if (this.alg) {
      result.alg = this.alg
    }

    if (this.key_ops && this.key_ops.length) {
      result.key_ops = this.key_ops
    }

    if (this.use) {
      result.use = this.use
    }

    if (this.x5c) {
      result.x5c = this.x5c
    }

    if (this.x5t) {
      result.x5t = this.x5t
    }

    if (this['x5t#S256']) {
      result['x5t#S256'] = this['x5t#S256']
    }

    return result
  }

  [JWK_MEMBERS] () {
    const props = this[KEYOBJECT].type === 'private' ? this.constructor[PRIVATE_MEMBERS] : this.constructor[PUBLIC_MEMBERS]
    Object.defineProperties(this, [...props].reduce((acc, component) => {
      acc[component] = {
        get () {
          const jwk = keyObjectToJWK(this[KEYOBJECT])
          Object.defineProperties(
            this,
            Object.entries(jwk)
              .filter(([key]) => props.has(key))
              .reduce((acc, [key, value]) => {
                acc[key] = { value, enumerable: this.constructor[PUBLIC_MEMBERS].has(key), configurable: false }
                return acc
              }, {})
          )

          return this[component]
        },
        enumerable: this.constructor[PUBLIC_MEMBERS].has(component),
        configurable: true
      }
      return acc
    }, {}))
  }

  /* c8 ignore next 8 */
  [inspect.custom] () {
    return `${this.constructor.name} ${inspect(this.toJWK(false), {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true
    })}`
  }

  /* c8 ignore next 3 */
  [THUMBPRINT_MATERIAL] () {
    throw new Error(`"[THUMBPRINT_MATERIAL]()" is not implemented on ${this.constructor.name}`)
  }

  algorithms (operation, /* the rest is private API */ int, opts) {
    const { use = this.use, alg = this.alg, key_ops: ops = this.key_ops } = int === privateApi ? opts : {}
    if (alg) {
      return new Set(this.algorithms(operation, privateApi, { alg: null, use, key_ops: ops }).has(alg) ? [alg] : undefined)
    }

    if (typeof operation === 'symbol') {
      try {
        return this[operation]()
      } catch (err) {
        return new Set()
      }
    }

    if (operation && ops && !ops.includes(operation)) {
      return new Set()
    }

    switch (operation) {
      case 'decrypt':
      case 'deriveKey':
      case 'encrypt':
      case 'sign':
      case 'unwrapKey':
      case 'verify':
      case 'wrapKey':
        return new Set(Object.entries(JWK[this.kty][operation]).map(([alg, fn]) => fn(this) ? alg : undefined).filter(Boolean))
      case undefined:
        return new Set([
          ...this.algorithms('sign'),
          ...this.algorithms('verify'),
          ...this.algorithms('decrypt'),
          ...this.algorithms('encrypt'),
          ...this.algorithms('unwrapKey'),
          ...this.algorithms('wrapKey'),
          ...this.algorithms('deriveKey')
        ])
      default:
        throw new TypeError('invalid key operation')
    }
  }

  /* c8 ignore next 3 */
  static async generate () {
    throw new Error(`"static async generate()" is not implemented on ${this.name}`)
  }

  /* c8 ignore next 3 */
  static generateSync () {
    throw new Error(`"static generateSync()" is not implemented on ${this.name}`)
  }

  /* c8 ignore next 3 */
  static get [PUBLIC_MEMBERS] () {
    throw new Error(`"static get [PUBLIC_MEMBERS]()" is not implemented on ${this.name}`)
  }

  /* c8 ignore next 3 */
  static get [PRIVATE_MEMBERS] () {
    throw new Error(`"static get [PRIVATE_MEMBERS]()" is not implemented on ${this.name}`)
  }
}

module.exports = Key


/***/ }),

/***/ "/0p4":
/***/ (function(module, exports) {

module.exports = require("events");

/***/ }),

/***/ "/JKO":
/***/ (function(module, exports, __webpack_require__) {

const jose = __webpack_require__("xZSz");

const { assertIssuerConfiguration } = __webpack_require__("N+si");
const { random } = __webpack_require__("iAgo");
const now = __webpack_require__("PbSP");
const request = __webpack_require__("UwMm");
const instance = __webpack_require__("0pkK");
const merge = __webpack_require__("GFHV");

const formUrlEncode = (value) => encodeURIComponent(value).replace(/%20/g, '+');

async function clientAssertion(endpoint, payload) {
  let alg = this[`${endpoint}_endpoint_auth_signing_alg`];
  if (!alg) {
    assertIssuerConfiguration(this.issuer, `${endpoint}_endpoint_auth_signing_alg_values_supported`);
  }

  if (this[`${endpoint}_endpoint_auth_method`] === 'client_secret_jwt') {
    const key = await this.joseSecret();

    if (!alg) {
      const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
      alg = Array.isArray(supported) && supported.find((signAlg) => key.algorithms('sign').has(signAlg));
    }

    return jose.JWS.sign(payload, key, { alg, typ: 'JWT' });
  }

  const keystore = instance(this).get('keystore');

  if (!keystore) {
    throw new TypeError('no client jwks provided for signing a client assertion with');
  }

  if (!alg) {
    const algs = new Set();

    keystore.all().forEach((key) => {
      key.algorithms('sign').forEach(Set.prototype.add.bind(algs));
    });

    const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
    alg = Array.isArray(supported) && supported.find((signAlg) => algs.has(signAlg));
  }

  const key = keystore.get({ alg, use: 'sig' });
  if (!key) {
    throw new TypeError(`no key found in client jwks to sign a client assertion with using alg ${alg}`);
  }
  return jose.JWS.sign(payload, key, { alg, typ: 'JWT', kid: key.kid });
}

async function authFor(endpoint, { clientAssertionPayload } = {}) {
  const authMethod = this[`${endpoint}_endpoint_auth_method`];
  switch (authMethod) {
    case 'self_signed_tls_client_auth':
    case 'tls_client_auth':
    case 'none':
      return { body: { client_id: this.client_id } };
    case 'client_secret_post':
      if (!this.client_secret) {
        throw new TypeError('client_secret_post client authentication method requires a client_secret');
      }
      return { body: { client_id: this.client_id, client_secret: this.client_secret } };
    case 'private_key_jwt':
    case 'client_secret_jwt': {
      const timestamp = now();
      const assertion = await clientAssertion.call(this, endpoint, {
        iat: timestamp,
        exp: timestamp + 60,
        jti: random(),
        iss: this.client_id,
        sub: this.client_id,
        aud: this.issuer[`${endpoint}_endpoint`], // TODO: in v4.x pass the issuer instead (for now clientAssertionPayload can be used for that)
        ...clientAssertionPayload,
      });

      return {
        body: {
          client_id: this.client_id,
          client_assertion: assertion,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        },
      };
    }
    default: { // client_secret_basic
      // This is correct behaviour, see https://tools.ietf.org/html/rfc6749#section-2.3.1 and the
      // related appendix. (also https://github.com/panva/node-openid-client/pull/91)
      // > The client identifier is encoded using the
      // > "application/x-www-form-urlencoded" encoding algorithm per
      // > Appendix B, and the encoded value is used as the username; the client
      // > password is encoded using the same algorithm and used as the
      // > password.
      if (!this.client_secret) {
        throw new TypeError('client_secret_basic client authentication method requires a client_secret');
      }
      const encoded = `${formUrlEncode(this.client_id)}:${formUrlEncode(this.client_secret)}`;
      const value = Buffer.from(encoded).toString('base64');
      return { headers: { Authorization: `Basic ${value}` } };
    }
  }
}

function resolveResponseType() {
  const { length, 0: value } = this.response_types;

  if (length === 1) {
    return value;
  }

  return undefined;
}

function resolveRedirectUri() {
  const { length, 0: value } = this.redirect_uris || [];

  if (length === 1) {
    return value;
  }

  return undefined;
}

async function authenticatedPost(endpoint, opts, {
  clientAssertionPayload, endpointAuthMethod = endpoint,
} = {}) {
  const auth = await authFor.call(this, endpointAuthMethod, { clientAssertionPayload });
  const requestOpts = merge(opts, auth, { form: true });

  const mTLS = this[`${endpointAuthMethod}_endpoint_auth_method`].includes('tls_client_auth')
    || (endpoint === 'token' && this.tls_client_certificate_bound_access_tokens);

  let targetUrl;
  if (mTLS && this.issuer.mtls_endpoint_aliases) {
    targetUrl = this.issuer.mtls_endpoint_aliases[`${endpoint}_endpoint`];
  }

  targetUrl = targetUrl || this.issuer[`${endpoint}_endpoint`];

  if ('body' in requestOpts) {
    for (const [key, value] of Object.entries(requestOpts.body)) { // eslint-disable-line no-restricted-syntax, max-len
      if (typeof value === 'undefined') {
        delete requestOpts.body[key];
      }
    }
  }

  return request.call(this, {
    ...requestOpts,
    method: 'POST',
    url: targetUrl,
  }, { mTLS });
}

module.exports = {
  resolveResponseType,
  resolveRedirectUri,
  authFor,
  authenticatedPost,
};


/***/ }),

/***/ "/SMw":
/***/ (function(module, exports) {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = function() { return []; };
webpackEmptyContext.resolve = webpackEmptyContext;
module.exports = webpackEmptyContext;
webpackEmptyContext.id = "/SMw";

/***/ }),

/***/ "/co4":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable no-underscore-dangle */

const url = __webpack_require__("bzos");
const { format } = __webpack_require__("jK02");

const cloneDeep = __webpack_require__("nqRS");
const { RPError, OPError } = __webpack_require__("L71r");
const { BaseClient } = __webpack_require__("HrFp");
const { random, codeChallenge } = __webpack_require__("iAgo");
const pick = __webpack_require__("LZmR");
const { resolveResponseType, resolveRedirectUri } = __webpack_require__("/JKO");

function verified(err, user, info = {}) {
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(info);
  } else {
    this.success(user, info);
  }
}

/**
 * @name constructor
 * @api public
 */
function OpenIDConnectStrategy({
  client,
  params = {},
  passReqToCallback = false,
  sessionKey,
  usePKCE = false,
} = {}, verify) {
  if (!(client instanceof BaseClient)) {
    throw new TypeError('client must be an instance of openid-client Client');
  }

  if (typeof verify !== 'function') {
    throw new TypeError('verify callback must be a function');
  }

  if (!client.issuer || !client.issuer.issuer) {
    throw new TypeError('client must have an issuer with an identifier');
  }

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._passReqToCallback = passReqToCallback;
  this._usePKCE = usePKCE;
  this._key = sessionKey || `oidc:${url.parse(this._issuer.issuer).hostname}`;
  this._params = cloneDeep(params);

  if (this._usePKCE === true) {
    const supportedMethods = this._issuer.code_challenge_methods_supported;
    if (!Array.isArray(supportedMethods)) {
      throw new TypeError('code_challenge_methods_supported is not properly set on issuer');
    }
    if (supportedMethods.includes('S256')) {
      this._usePKCE = 'S256';
    } else if (supportedMethods.includes('plain')) {
      this._usePKCE = 'plain';
    } else {
      throw new TypeError('neither supported code_challenge_method is supported by the issuer');
    }
  } else if (typeof this._usePKCE === 'string' && !['plain', 'S256'].includes(this._usePKCE)) {
    throw new TypeError(`${this._usePKCE} is not valid/implemented PKCE code_challenge_method`);
  }

  this.name = url.parse(client.issuer.issuer).hostname;

  if (!this._params.response_type) this._params.response_type = resolveResponseType.call(client);
  if (!this._params.redirect_uri) this._params.redirect_uri = resolveRedirectUri.call(client);
  if (!this._params.scope) this._params.scope = 'openid';
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  (async () => {
    const client = this._client;
    if (!req.session) {
      throw new TypeError('authentication requires session support');
    }
    const reqParams = client.callbackParams(req);
    const sessionKey = this._key;

    /* start authentication request */
    if (Object.keys(reqParams).length === 0) {
      // provide options object with extra authentication parameters
      const params = {
        state: random(),
        ...this._params,
        ...options,
      };

      if (!params.nonce && params.response_type.includes('id_token')) {
        params.nonce = random();
      }

      req.session[sessionKey] = pick(params, 'nonce', 'state', 'max_age', 'response_type');

      if (this._usePKCE) {
        const verifier = random();
        req.session[sessionKey].code_verifier = verifier;

        switch (this._usePKCE) { // eslint-disable-line default-case
          case 'S256':
            params.code_challenge = codeChallenge(verifier);
            params.code_challenge_method = 'S256';
            break;
          case 'plain':
            params.code_challenge = verifier;
            break;
        }
      }

      this.redirect(client.authorizationUrl(params));
      return;
    }
    /* end authentication request */

    /* start authentication response */

    const session = req.session[sessionKey];
    if (Object.keys(session || {}).length === 0) {
      throw new Error(format('did not find expected authorization request details in session, req.session["%s"] is %j', sessionKey, session));
    }

    const {
      state, nonce, max_age: maxAge, code_verifier: codeVerifier, response_type: responseType,
    } = session;

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    const opts = {
      redirect_uri: this._params.redirect_uri,
      ...options,
    };

    const checks = {
      state,
      nonce,
      max_age: maxAge,
      code_verifier: codeVerifier,
      response_type: responseType,
    };

    const tokenset = await client.callback(opts.redirect_uri, reqParams, checks);

    const passReq = this._passReqToCallback;
    const loadUserinfo = this._verify.length > (passReq ? 3 : 2) && client.issuer.userinfo_endpoint;

    const args = [tokenset, verified.bind(this)];

    if (loadUserinfo) {
      if (!tokenset.access_token) {
        throw new RPError({
          message: 'expected access_token to be returned when asking for userinfo in verify callback',
          tokenset,
        });
      }
      const userinfo = await client.userinfo(tokenset);
      args.splice(1, 0, userinfo);
    }

    if (passReq) {
      args.unshift(req);
    }

    this._verify(...args);
    /* end authentication response */
  })().catch((error) => {
    if (
      (error instanceof OPError && error.error !== 'server_error' && !error.error.startsWith('invalid'))
      || error instanceof RPError
    ) {
      this.fail(error);
    } else {
      this.error(error);
    }
  });
};

module.exports = OpenIDConnectStrategy;


/***/ }),

/***/ "/hdj":
/***/ (function(module, exports, __webpack_require__) {

const { deflateRawSync } = __webpack_require__("FMKJ")

const { KEYOBJECT } = __webpack_require__("ehsS")
const generateIV = __webpack_require__("X3uD")
const base64url = __webpack_require__("Xab3")
const getKey = __webpack_require__("oGTz")
const isObject = __webpack_require__("kF1/")
const { createSecretKey } = __webpack_require__("1ALl")
const deepClone = __webpack_require__("O9d4")
const importKey = __webpack_require__("GhER")
const { JWEInvalid } = __webpack_require__("yt7c")
const { check, keyManagementEncrypt, encrypt } = __webpack_require__("FUB/")

const serializers = __webpack_require__("ARPQ")
const generateCEK = __webpack_require__("RGIU")
const validateHeaders = __webpack_require__("OHZa")

const PROCESS_RECIPIENT = Symbol('PROCESS_RECIPIENT')

class Encrypt {
  // TODO: in v2.x swap unprotectedHeader and aad
  constructor (cleartext, protectedHeader, unprotectedHeader, aad) {
    if (!Buffer.isBuffer(cleartext) && typeof cleartext !== 'string') {
      throw new TypeError('cleartext argument must be a Buffer or a string')
    }
    cleartext = Buffer.from(cleartext)

    if (aad !== undefined && !Buffer.isBuffer(aad) && typeof aad !== 'string') {
      throw new TypeError('aad argument must be a Buffer or a string when provided')
    }
    aad = aad ? Buffer.from(aad) : undefined

    if (protectedHeader !== undefined && !isObject(protectedHeader)) {
      throw new TypeError('protectedHeader argument must be a plain object when provided')
    }

    if (unprotectedHeader !== undefined && !isObject(unprotectedHeader)) {
      throw new TypeError('unprotectedHeader argument must be a plain object when provided')
    }

    this._recipients = []
    this._cleartext = cleartext
    this._aad = aad
    this._unprotected = unprotectedHeader ? deepClone(unprotectedHeader) : undefined
    this._protected = protectedHeader ? deepClone(protectedHeader) : undefined
  }

  /*
   * @public
   */
  recipient (key, header) {
    key = getKey(key)

    if (header !== undefined && !isObject(header)) {
      throw new TypeError('header argument must be a plain object when provided')
    }

    this._recipients.push({
      key,
      header: header ? deepClone(header) : undefined
    })

    return this
  }

  /*
   * @private
   */
  [PROCESS_RECIPIENT] (recipient) {
    const unprotectedHeader = this._unprotected
    const protectedHeader = this._protected
    const { length: recipientCount } = this._recipients

    const jweHeader = {
      ...protectedHeader,
      ...unprotectedHeader,
      ...recipient.header
    }
    const { key } = recipient

    const enc = jweHeader.enc
    let alg = jweHeader.alg

    if (key.use === 'sig') {
      throw new TypeError('a key with "use":"sig" is not usable for encryption')
    }

    if (alg === 'dir') {
      check(key, 'encrypt', enc)
    } else if (alg) {
      check(key, 'keyManagementEncrypt', alg)
    } else {
      alg = key.alg || [...key.algorithms('wrapKey')][0] || [...key.algorithms('deriveKey')][0]

      if (alg === 'ECDH-ES' && recipientCount !== 1) {
        alg = [...key.algorithms('deriveKey')][1]
      }

      if (!alg) {
        throw new JWEInvalid('could not resolve a usable "alg" for a recipient')
      }

      if (recipientCount === 1) {
        if (protectedHeader) {
          protectedHeader.alg = alg
        } else {
          this._protected = { alg }
        }
      } else {
        if (recipient.header) {
          recipient.header.alg = alg
        } else {
          recipient.header = { alg }
        }
      }
    }

    let wrapped
    let generatedHeader

    if (key.kty === 'oct' && alg === 'dir') {
      this._cek = importKey(key[KEYOBJECT], { use: 'enc', alg: enc })
    } else {
      check(this._cek, 'encrypt', enc)
      ;({ wrapped, header: generatedHeader } = keyManagementEncrypt(alg, key, this._cek[KEYOBJECT].export(), { enc, alg }))
      if (alg === 'ECDH-ES') {
        this._cek = importKey(createSecretKey(wrapped), { use: 'enc', alg: enc })
      }
    }

    if (alg === 'dir' || alg === 'ECDH-ES') {
      recipient.encrypted_key = ''
    } else {
      recipient.encrypted_key = base64url.encodeBuffer(wrapped)
    }

    if (generatedHeader) {
      recipient.generatedHeader = generatedHeader
    }
  }

  /*
   * @public
   */
  encrypt (serialization) {
    const serializer = serializers[serialization]
    if (!serializer) {
      throw new TypeError('serialization must be one of "compact", "flattened", "general"')
    }

    if (!this._recipients.length) {
      throw new JWEInvalid('missing recipients')
    }

    serializer.validate(this._protected, this._unprotected, this._aad, this._recipients)

    let enc = validateHeaders(this._protected, this._unprotected, this._recipients, false, this._protected ? this._protected.crit : undefined)
    if (!enc) {
      enc = 'A128CBC-HS256'
      if (this._protected) {
        this._protected.enc = enc
      } else {
        this._protected = { enc }
      }
    }
    const final = {}
    this._cek = generateCEK(enc)

    for (const recipient of this._recipients) {
      this[PROCESS_RECIPIENT](recipient)
    }

    const iv = generateIV(enc)
    final.iv = base64url.encodeBuffer(iv)

    if (this._recipients.length === 1 && this._recipients[0].generatedHeader) {
      const [{ generatedHeader }] = this._recipients
      delete this._recipients[0].generatedHeader
      this._protected = {
        ...this._protected,
        ...generatedHeader
      }
    }

    if (this._protected) {
      final.protected = base64url.JSON.encode(this._protected)
    }
    final.unprotected = this._unprotected

    let aad
    if (this._aad) {
      final.aad = base64url.encode(this._aad)
      aad = Buffer.concat([
        Buffer.from(final.protected || ''),
        Buffer.from('.'),
        Buffer.from(final.aad)
      ])
    } else {
      aad = Buffer.from(final.protected || '')
    }

    let cleartext = this._cleartext
    if (this._protected && 'zip' in this._protected) {
      cleartext = deflateRawSync(cleartext)
    }

    const { ciphertext, tag } = encrypt(enc, this._cek, cleartext, { iv, aad })
    final.tag = base64url.encodeBuffer(tag)
    final.ciphertext = base64url.encodeBuffer(ciphertext)

    return serializer(final, this._recipients)
  }
}

module.exports = Encrypt


/***/ }),

/***/ "/sST":
/***/ (function(module, exports, __webpack_require__) {

const { sign: signOneShot, verify: verifyOneShot, createSign, createVerify, getCurves } = __webpack_require__("PJMN")

const { derToJose, joseToDer } = __webpack_require__("f0Nx")
const { KEYOBJECT } = __webpack_require__("ehsS")
const resolveNodeAlg = __webpack_require__("uGJc")
const { asInput } = __webpack_require__("1ALl")
const { dsaEncodingSupported } = __webpack_require__("pDDt")
const { name: secp256k1 } = __webpack_require__("F/JS")

let sign, verify

if (dsaEncodingSupported) {
  sign = (jwaAlg, nodeAlg, { [KEYOBJECT]: keyObject }, payload) => {
    if (typeof payload === 'string') {
      payload = Buffer.from(payload)
    }
    return signOneShot(nodeAlg, payload, { key: asInput(keyObject, false), dsaEncoding: 'ieee-p1363' })
  }
  verify = (jwaAlg, nodeAlg, { [KEYOBJECT]: keyObject }, payload, signature) => {
    try {
      return verifyOneShot(nodeAlg, payload, { key: asInput(keyObject, true), dsaEncoding: 'ieee-p1363' }, signature)
    } catch (err) {
      return false
    }
  }
} else {
  sign = (jwaAlg, nodeAlg, { [KEYOBJECT]: keyObject }, payload) => {
    return derToJose(createSign(nodeAlg).update(payload).sign(asInput(keyObject, false)), jwaAlg)
  }
  verify = (jwaAlg, nodeAlg, { [KEYOBJECT]: keyObject }, payload, signature) => {
    try {
      return createVerify(nodeAlg).update(payload).verify(asInput(keyObject, true), joseToDer(signature, jwaAlg))
    } catch (err) {
      return false
    }
  }
}

const crvToAlg = (crv) => {
  switch (crv) {
    case 'P-256':
      return 'ES256'
    case secp256k1:
      return 'ES256K'
    case 'P-384':
      return 'ES384'
    case 'P-521':
      return 'ES512'
  }
}

module.exports = (JWA, JWK) => {
  const algs = []

  if (getCurves().includes('prime256v1')) {
    algs.push('ES256')
  }

  if (getCurves().includes('secp256k1')) {
    algs.push('ES256K')
  }

  if (getCurves().includes('secp384r1')) {
    algs.push('ES384')
  }

  if (getCurves().includes('secp521r1')) {
    algs.push('ES512')
  }

  algs.forEach((jwaAlg) => {
    const nodeAlg = resolveNodeAlg(jwaAlg)
    JWA.sign.set(jwaAlg, sign.bind(undefined, jwaAlg, nodeAlg))
    JWA.verify.set(jwaAlg, verify.bind(undefined, jwaAlg, nodeAlg))
    JWK.EC.sign[jwaAlg] = key => key.private && JWK.EC.verify[jwaAlg](key)
    JWK.EC.verify[jwaAlg] = key => (key.use === 'sig' || key.use === undefined) && crvToAlg(key.crv) === jwaAlg
  })
}


/***/ }),

/***/ "/yrF":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (timeout) {

    return new Promise((resolve) => setTimeout(resolve, timeout));
};


/***/ }),

/***/ "0/Ix":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


exports = module.exports = {
    array: Array.prototype,
    buffer: Buffer && Buffer.prototype,             // $lab:coverage:ignore$
    date: Date.prototype,
    error: Error.prototype,
    generic: Object.prototype,
    map: Map.prototype,
    promise: Promise.prototype,
    regex: RegExp.prototype,
    set: Set.prototype,
    weakMap: WeakMap.prototype,
    weakSet: WeakSet.prototype
};


internals.typeMap = new Map([
    ['[object Error]', exports.error],
    ['[object Map]', exports.map],
    ['[object Promise]', exports.promise],
    ['[object Set]', exports.set],
    ['[object WeakMap]', exports.weakMap],
    ['[object WeakSet]', exports.weakSet]
]);


exports.getInternalProto = function (obj) {

    if (Array.isArray(obj)) {
        return exports.array;
    }

    if (Buffer && obj instanceof Buffer) {          // $lab:coverage:ignore$
        return exports.buffer;
    }

    if (obj instanceof Date) {
        return exports.date;
    }

    if (obj instanceof RegExp) {
        return exports.regex;
    }

    if (obj instanceof Error) {
        return exports.error;
    }

    const objName = Object.prototype.toString.call(obj);
    return internals.typeMap.get(objName) || exports.generic;
};


/***/ }),

/***/ "0Aai":
/***/ (function(module, exports) {

const REGISTRY = new Map();

module.exports = REGISTRY;


/***/ }),

/***/ "0Kms":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const session_token_cache_1 = tslib_1.__importDefault(__webpack_require__("zgCa"));
function tokenCacheHandler(clientProvider, sessionStore) {
    return (req, res) => {
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        return new session_token_cache_1.default(sessionStore, clientProvider, req, res);
    };
}
exports.default = tokenCacheHandler;
//# sourceMappingURL=token-cache.js.map

/***/ }),

/***/ "0LeV":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("xG1e");


const internals = {};


module.exports = function (obj, chain, options) {

    if (chain === false ||
        chain === null ||
        chain === undefined) {

        return obj;
    }

    options = options || {};
    if (typeof options === 'string') {
        options = { separator: options };
    }

    const isChainArray = Array.isArray(chain);

    Assert(!isChainArray || !options.separator, 'Separator option no valid for array-based chain');

    const path = isChainArray ? chain : chain.split(options.separator || '.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        let key = path[i];
        const type = options.iterables && internals.iterables(ref);

        if (Array.isArray(ref) ||
            type === 'set') {

            const number = Number(key);
            if (Number.isInteger(number)) {
                key = number < 0 ? ref.length + number : number;
            }
        }

        if (!ref ||
            typeof ref === 'function' && options.functions === false ||         // Defaults to true
            !type && ref[key] === undefined) {

            Assert(!options.strict || i + 1 === path.length, 'Missing segment', key, 'in reach path ', chain);
            Assert(typeof ref === 'object' || options.functions === true || typeof ref !== 'function', 'Invalid segment', key, 'in reach path ', chain);
            ref = options.default;
            break;
        }

        if (!type) {
            ref = ref[key];
        }
        else if (type === 'set') {
            ref = [...ref][key];
        }
        else {  // type === 'map'
            ref = ref.get(key);
        }
    }

    return ref;
};


internals.iterables = function (ref) {

    if (ref instanceof Set) {
        return 'set';
    }

    if (ref instanceof Map) {
        return 'map';
    }
};


/***/ }),

/***/ "0pkK":
/***/ (function(module, exports) {

const privateProps = new WeakMap();

module.exports = (ctx) => {
  if (!privateProps.has(ctx)) {
    privateProps.set(ctx, new Map([['metadata', new Map()]]));
  }
  return privateProps.get(ctx);
};


/***/ }),

/***/ "10GS":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const fs = __webpack_require__("mw/K");
const util = __webpack_require__("jK02");
const is = __webpack_require__("6mOv");
const isFormData = __webpack_require__("faWz");

module.exports = async options => {
	const {body} = options;

	if (options.headers['content-length']) {
		return Number(options.headers['content-length']);
	}

	if (!body && !options.stream) {
		return 0;
	}

	if (is.string(body)) {
		return Buffer.byteLength(body);
	}

	if (isFormData(body)) {
		return util.promisify(body.getLength.bind(body))();
	}

	if (body instanceof fs.ReadStream) {
		const {size} = await util.promisify(fs.stat)(body.path);
		return size;
	}

	return null;
};


/***/ }),

/***/ "1ALl":
/***/ (function(module, exports, __webpack_require__) {

/* global BigInt */

const { keyObjectSupported } = __webpack_require__("pDDt")

let createPublicKey
let createPrivateKey
let createSecretKey
let KeyObject
let asInput

if (keyObjectSupported) {
  ({ createPublicKey, createPrivateKey, createSecretKey, KeyObject } = __webpack_require__("PJMN"))
  asInput = (input) => input
} else {
  const { EOL } = __webpack_require__("jle/")

  const errors = __webpack_require__("yt7c")
  const isObject = __webpack_require__("kF1/")
  const asn1 = __webpack_require__("u88T")
  const toInput = Symbol('toInput')

  const namedCurve = Symbol('namedCurve')

  asInput = (keyObject, needsPublic) => {
    if (keyObject instanceof KeyObject) {
      return keyObject[toInput](needsPublic)
    }

    return createSecretKey(keyObject)[toInput](needsPublic)
  }

  const pemToDer = pem => Buffer.from(pem.replace(/(?:-----(?:BEGIN|END)(?: (?:RSA|EC))? (?:PRIVATE|PUBLIC) KEY-----|\s)/g, ''), 'base64')
  const derToPem = (der, label) => `-----BEGIN ${label}-----${EOL}${(der.toString('base64').match(/.{1,64}/g) || []).join(EOL)}${EOL}-----END ${label}-----`
  const unsupported = (input) => {
    const label = typeof input === 'string' ? input : `OID ${input.join('.')}`
    throw new errors.JOSENotSupported(`${label} is not supported in your Node.js runtime version`)
  }

  KeyObject = class KeyObject {
    export ({ cipher, passphrase, type, format } = {}) {
      if (this._type === 'secret') {
        return this._buffer
      }

      if (this._type === 'public') {
        if (this.asymmetricKeyType === 'rsa') {
          switch (type) {
            case 'pkcs1':
              if (format === 'pem') {
                return this._pem
              }

              return pemToDer(this._pem)
            case 'spki': {
              const PublicKeyInfo = asn1.get('PublicKeyInfo')
              const pem = PublicKeyInfo.encode({
                algorithm: {
                  algorithm: 'rsaEncryption',
                  parameters: { type: 'null' }
                },
                publicKey: {
                  unused: 0,
                  data: pemToDer(this._pem)
                }
              }, 'pem', { label: 'PUBLIC KEY' })

              return format === 'pem' ? pem : pemToDer(pem)
            }
            default:
              throw new TypeError(`The value ${type} is invalid for option "type"`)
          }
        }

        if (this.asymmetricKeyType === 'ec') {
          if (type !== 'spki') {
            throw new TypeError(`The value ${type} is invalid for option "type"`)
          }

          if (format === 'pem') {
            return this._pem
          }

          return pemToDer(this._pem)
        }
      }

      if (this._type === 'private') {
        if (passphrase !== undefined || cipher !== undefined) {
          throw new errors.JOSENotSupported('encrypted private keys are not supported in your Node.js runtime version')
        }

        if (type === 'pkcs8') {
          if (this._pkcs8) {
            if (format === 'der' && typeof this._pkcs8 === 'string') {
              return pemToDer(this._pkcs8)
            }

            if (format === 'pem' && Buffer.isBuffer(this._pkcs8)) {
              return derToPem(this._pkcs8, 'PRIVATE KEY')
            }

            return this._pkcs8
          }

          if (this.asymmetricKeyType === 'rsa') {
            const parsed = this._asn1
            const RSAPrivateKey = asn1.get('RSAPrivateKey')
            const privateKey = RSAPrivateKey.encode(parsed)
            const PrivateKeyInfo = asn1.get('PrivateKeyInfo')
            const pkcs8 = PrivateKeyInfo.encode({
              version: 0,
              privateKey,
              algorithm: {
                algorithm: 'rsaEncryption',
                parameters: { type: 'null' }
              }
            })

            this._pkcs8 = pkcs8

            return this.export({ type, format })
          }

          if (this.asymmetricKeyType === 'ec') {
            const parsed = this._asn1
            const ECPrivateKey = asn1.get('ECPrivateKey')
            const privateKey = ECPrivateKey.encode({
              version: parsed.version,
              privateKey: parsed.privateKey,
              publicKey: parsed.publicKey
            })
            const PrivateKeyInfo = asn1.get('PrivateKeyInfo')
            const pkcs8 = PrivateKeyInfo.encode({
              version: 0,
              privateKey,
              algorithm: {
                algorithm: 'ecPublicKey',
                parameters: this._asn1.parameters
              }
            })

            this._pkcs8 = pkcs8

            return this.export({ type, format })
          }
        }

        if (this.asymmetricKeyType === 'rsa' && type === 'pkcs1') {
          if (format === 'pem') {
            return this._pem
          }

          return pemToDer(this._pem)
        } else if (this.asymmetricKeyType === 'ec' && type === 'sec1') {
          if (format === 'pem') {
            return this._pem
          }

          return pemToDer(this._pem)
        } else {
          throw new TypeError(`The value ${type} is invalid for option "type"`)
        }
      }
    }

    get type () {
      return this._type
    }

    get asymmetricKeyType () {
      return this._asymmetricKeyType
    }

    get symmetricKeySize () {
      return this._symmetricKeySize
    }

    [toInput] (needsPublic) {
      switch (this._type) {
        case 'secret':
          return this._buffer
        case 'public':
          return this._pem
        default:
          if (needsPublic) {
            if (!('_pub' in this)) {
              this._pub = createPublicKey(this)
            }

            return this._pub[toInput](false)
          }

          return this._pem
      }
    }
  }

  createSecretKey = (buffer) => {
    if (!Buffer.isBuffer(buffer) || !buffer.length) {
      throw new TypeError('input must be a non-empty Buffer instance')
    }

    const keyObject = new KeyObject()
    keyObject._buffer = Buffer.from(buffer)
    keyObject._symmetricKeySize = buffer.length
    keyObject._type = 'secret'

    return keyObject
  }

  createPublicKey = (input) => {
    if (input instanceof KeyObject) {
      if (input.type !== 'private') {
        throw new TypeError(`Invalid key object type ${input.type}, expected private.`)
      }

      switch (input.asymmetricKeyType) {
        case 'ec': {
          const PublicKeyInfo = asn1.get('PublicKeyInfo')
          const key = PublicKeyInfo.encode({
            algorithm: {
              algorithm: 'ecPublicKey',
              parameters: input._asn1.parameters
            },
            publicKey: input._asn1.publicKey
          })

          return createPublicKey({ key, format: 'der', type: 'spki' })
        }
        case 'rsa': {
          const RSAPublicKey = asn1.get('RSAPublicKey')
          const key = RSAPublicKey.encode(input._asn1)
          return createPublicKey({ key, format: 'der', type: 'pkcs1' })
        }
      }
    }

    if (typeof input === 'string' || Buffer.isBuffer(input)) {
      input = { key: input, format: 'pem' }
    }

    if (!isObject(input)) {
      throw new TypeError('input must be a string, Buffer or an object')
    }

    const { format, passphrase } = input
    let { key, type } = input

    if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
      throw new TypeError('key must be a string or Buffer')
    }

    if (format !== 'pem' && format !== 'der') {
      throw new TypeError('format must be one of "pem" or "der"')
    }

    let label
    if (format === 'pem') {
      key = key.toString()
      switch (key.split(/\r?\n/g)[0].toString()) {
        case '-----BEGIN PUBLIC KEY-----':
          type = 'spki'
          label = 'PUBLIC KEY'
          break
        case '-----BEGIN RSA PUBLIC KEY-----':
          type = 'pkcs1'
          label = 'RSA PUBLIC KEY'
          break
        case '-----BEGIN CERTIFICATE-----':
          throw new errors.JOSENotSupported('X.509 certificates are not supported in your Node.js runtime version')
        case '-----BEGIN PRIVATE KEY-----':
        case '-----BEGIN EC PRIVATE KEY-----':
        case '-----BEGIN RSA PRIVATE KEY-----':
          return createPublicKey(createPrivateKey(key))
        default:
          throw new TypeError('unknown/unsupported PEM type')
      }
    }

    switch (type) {
      case 'spki': {
        const PublicKeyInfo = asn1.get('PublicKeyInfo')
        const parsed = PublicKeyInfo.decode(key, format, { label })

        let type, keyObject
        switch (parsed.algorithm.algorithm) {
          case 'ecPublicKey': {
            keyObject = new KeyObject()
            keyObject._asn1 = parsed
            keyObject._asymmetricKeyType = 'ec'
            keyObject._type = 'public'
            keyObject._pem = PublicKeyInfo.encode(parsed, 'pem', { label: 'PUBLIC KEY' })

            break
          }
          case 'rsaEncryption': {
            type = 'pkcs1'
            keyObject = createPublicKey({ type, key: parsed.publicKey.data, format: 'der' })
            break
          }
          default:
            unsupported(parsed.algorithm.algorithm)
        }

        return keyObject
      }
      case 'pkcs1': {
        const RSAPublicKey = asn1.get('RSAPublicKey')
        const parsed = RSAPublicKey.decode(key, format, { label })

        // special case when private pkcs1 PEM / DER is used with createPublicKey
        if (parsed.n === BigInt(0)) {
          return createPublicKey(createPrivateKey({ key, format, type, passphrase }))
        }

        const keyObject = new KeyObject()
        keyObject._asn1 = parsed
        keyObject._asymmetricKeyType = 'rsa'
        keyObject._type = 'public'
        keyObject._pem = RSAPublicKey.encode(parsed, 'pem', { label: 'RSA PUBLIC KEY' })

        return keyObject
      }
      case 'pkcs8':
      case 'sec1':
        return createPublicKey(createPrivateKey({ format, key, type, passphrase }))
      default:
        throw new TypeError(`The value ${type} is invalid for option "type"`)
    }
  }

  createPrivateKey = (input, hints) => {
    if (typeof input === 'string' || Buffer.isBuffer(input)) {
      input = { key: input, format: 'pem' }
    }

    if (!isObject(input)) {
      throw new TypeError('input must be a string, Buffer or an object')
    }

    const { format, passphrase } = input
    let { key, type } = input

    if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
      throw new TypeError('key must be a string or Buffer')
    }

    if (passphrase !== undefined) {
      throw new errors.JOSENotSupported('encrypted private keys are not supported in your Node.js runtime version')
    }

    if (format !== 'pem' && format !== 'der') {
      throw new TypeError('format must be one of "pem" or "der"')
    }

    let label
    if (format === 'pem') {
      key = key.toString()
      switch (key.split(/\r?\n/g)[0].toString()) {
        case '-----BEGIN PRIVATE KEY-----':
          type = 'pkcs8'
          label = 'PRIVATE KEY'
          break
        case '-----BEGIN EC PRIVATE KEY-----':
          type = 'sec1'
          label = 'EC PRIVATE KEY'
          break
        case '-----BEGIN RSA PRIVATE KEY-----':
          type = 'pkcs1'
          label = 'RSA PRIVATE KEY'
          break
        default:
          throw new TypeError('unknown/unsupported PEM type')
      }
    }

    switch (type) {
      case 'pkcs8': {
        const PrivateKeyInfo = asn1.get('PrivateKeyInfo')
        const parsed = PrivateKeyInfo.decode(key, format, { label })

        let type, keyObject
        switch (parsed.algorithm.algorithm) {
          case 'ecPublicKey': {
            type = 'sec1'
            keyObject = createPrivateKey({ type, key: parsed.privateKey, format: 'der' }, { [namedCurve]: parsed.algorithm.parameters.value })
            break
          }
          case 'rsaEncryption': {
            type = 'pkcs1'
            keyObject = createPrivateKey({ type, key: parsed.privateKey, format: 'der' })
            break
          }
          default:
            unsupported(parsed.algorithm.algorithm)
        }

        keyObject._pkcs8 = key
        return keyObject
      }
      case 'pkcs1': {
        const RSAPrivateKey = asn1.get('RSAPrivateKey')
        const parsed = RSAPrivateKey.decode(key, format, { label })

        const keyObject = new KeyObject()
        keyObject._asn1 = parsed
        keyObject._asymmetricKeyType = 'rsa'
        keyObject._type = 'private'
        keyObject._pem = RSAPrivateKey.encode(parsed, 'pem', { label: 'RSA PRIVATE KEY' })

        return keyObject
      }
      case 'sec1': {
        const ECPrivateKey = asn1.get('ECPrivateKey')
        let parsed = ECPrivateKey.decode(key, format, { label })

        if (!('parameters' in parsed) && !hints[namedCurve]) {
          throw new Error('invalid sec1')
        } else if (!('parameters' in parsed)) {
          parsed = { ...parsed, parameters: { type: 'namedCurve', value: hints[namedCurve] } }
        }

        const keyObject = new KeyObject()
        keyObject._asn1 = parsed
        keyObject._asymmetricKeyType = 'ec'
        keyObject._type = 'private'
        keyObject._pem = ECPrivateKey.encode(parsed, 'pem', { label: 'EC PRIVATE KEY' })

        return keyObject
      }
      default:
        throw new TypeError(`The value ${type} is invalid for option "type"`)
    }
  }
}

module.exports = { createPublicKey, createPrivateKey, createSecretKey, KeyObject, asInput }


/***/ }),

/***/ "1Gj5":
/***/ (function(module, exports) {

// Helper
function reverse (map) {
  const res = {}

  Object.keys(map).forEach(function (key) {
    // Convert key to integer if it is stringified
    if ((key | 0) == key) { key = key | 0 } // eslint-disable-line eqeqeq

    const value = map[key]
    res[value] = key
  })

  return res
}

exports.tagClass = {
  0: 'universal',
  1: 'application',
  2: 'context',
  3: 'private'
}
exports.tagClassByName = reverse(exports.tagClass)

exports.tag = {
  0x00: 'end',
  0x01: 'bool',
  0x02: 'int',
  0x03: 'bitstr',
  0x04: 'octstr',
  0x05: 'null_',
  0x06: 'objid',
  0x07: 'objDesc',
  0x08: 'external',
  0x09: 'real',
  0x0a: 'enum',
  0x0b: 'embed',
  0x0c: 'utf8str',
  0x0d: 'relativeOid',
  0x10: 'seq',
  0x11: 'set',
  0x12: 'numstr',
  0x13: 'printstr',
  0x14: 't61str',
  0x15: 'videostr',
  0x16: 'ia5str',
  0x17: 'utctime',
  0x18: 'gentime',
  0x19: 'graphstr',
  0x1a: 'iso646str',
  0x1b: 'genstr',
  0x1c: 'unistr',
  0x1d: 'charstr',
  0x1e: 'bmpstr'
}
exports.tagByName = reverse(exports.tag)


/***/ }),

/***/ "1VP5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("vbc4");


const internals = {
    mismatched: null
};


module.exports = function (obj, ref, options) {

    options = Object.assign({ prototype: true }, options);

    return !!internals.isDeepEqual(obj, ref, options, []);
};


internals.isDeepEqual = function (obj, ref, options, seen) {

    if (obj === ref) {                                                      // Copied from Deep-eql, copyright(c) 2013 Jake Luer, jake@alogicalparadox.com, MIT Licensed, https://github.com/chaijs/deep-eql
        return obj !== 0 || 1 / obj === 1 / ref;
    }

    const type = typeof obj;

    if (type !== typeof ref) {
        return false;
    }

    if (obj === null ||
        ref === null) {

        return false;
    }

    if (type === 'function') {
        if (!options.deepFunction ||
            obj.toString() !== ref.toString()) {

            return false;
        }

        // Continue as object
    }
    else if (type !== 'object') {
        return obj !== obj && ref !== ref;                                  // NaN
    }

    const instanceType = internals.getSharedType(obj, ref, !!options.prototype);
    switch (instanceType) {
        case Types.buffer:
            return Buffer && Buffer.prototype.equals.call(obj, ref);        // $lab:coverage:ignore$
        case Types.promise:
            return obj === ref;
        case Types.regex:
            return obj.toString() === ref.toString();
        case internals.mismatched:
            return false;
    }

    for (let i = seen.length - 1; i >= 0; --i) {
        if (seen[i].isSame(obj, ref)) {
            return true;                                                    // If previous comparison failed, it would have stopped execution
        }
    }

    seen.push(new internals.SeenEntry(obj, ref));

    try {
        return !!internals.isDeepEqualObj(instanceType, obj, ref, options, seen);
    }
    finally {
        seen.pop();
    }
};


internals.getSharedType = function (obj, ref, checkPrototype) {

    if (checkPrototype) {
        if (Object.getPrototypeOf(obj) !== Object.getPrototypeOf(ref)) {
            return internals.mismatched;
        }

        return Types.getInternalProto(obj);
    }

    const type = Types.getInternalProto(obj);
    if (type !== Types.getInternalProto(ref)) {
        return internals.mismatched;
    }

    return type;
};


internals.valueOf = function (obj) {

    const objValueOf = obj.valueOf;
    if (objValueOf === undefined) {
        return obj;
    }

    try {
        return objValueOf.call(obj);
    }
    catch (err) {
        return err;
    }
};


internals.hasOwnEnumerableProperty = function (obj, key) {

    return Object.prototype.propertyIsEnumerable.call(obj, key);
};


internals.isSetSimpleEqual = function (obj, ref) {

    for (const entry of obj) {
        if (!ref.has(entry)) {
            return false;
        }
    }

    return true;
};


internals.isDeepEqualObj = function (instanceType, obj, ref, options, seen) {

    const { isDeepEqual, valueOf, hasOwnEnumerableProperty } = internals;
    const { keys, getOwnPropertySymbols } = Object;

    if (instanceType === Types.array) {
        if (options.part) {

            // Check if any index match any other index

            for (const objValue of obj) {
                for (const refValue of ref) {
                    if (isDeepEqual(objValue, refValue, options, seen)) {
                        return true;
                    }
                }
            }
        }
        else {
            if (obj.length !== ref.length) {
                return false;
            }

            for (let i = 0; i < obj.length; ++i) {
                if (!isDeepEqual(obj[i], ref[i], options, seen)) {
                    return false;
                }
            }

            return true;
        }
    }
    else if (instanceType === Types.set) {
        if (obj.size !== ref.size) {
            return false;
        }

        if (!internals.isSetSimpleEqual(obj, ref)) {

            // Check for deep equality

            const ref2 = new Set(ref);
            for (const objEntry of obj) {
                if (ref2.delete(objEntry)) {
                    continue;
                }

                let found = false;
                for (const refEntry of ref2) {
                    if (isDeepEqual(objEntry, refEntry, options, seen)) {
                        ref2.delete(refEntry);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    return false;
                }
            }
        }
    }
    else if (instanceType === Types.map) {
        if (obj.size !== ref.size) {
            return false;
        }

        for (const [key, value] of obj) {
            if (value === undefined && !ref.has(key)) {
                return false;
            }

            if (!isDeepEqual(value, ref.get(key), options, seen)) {
                return false;
            }
        }
    }
    else if (instanceType === Types.error) {

        // Always check name and message

        if (obj.name !== ref.name ||
            obj.message !== ref.message) {

            return false;
        }
    }

    // Check .valueOf()

    const valueOfObj = valueOf(obj);
    const valueOfRef = valueOf(ref);
    if ((obj !== valueOfObj || ref !== valueOfRef) &&
        !isDeepEqual(valueOfObj, valueOfRef, options, seen)) {

        return false;
    }

    // Check properties

    const objKeys = keys(obj);
    if (!options.part &&
        objKeys.length !== keys(ref).length &&
        !options.skip) {

        return false;
    }

    let skipped = 0;
    for (const key of objKeys) {
        if (options.skip &&
            options.skip.includes(key)) {

            if (ref[key] === undefined) {
                ++skipped;
            }

            continue;
        }

        if (!hasOwnEnumerableProperty(ref, key)) {
            return false;
        }

        if (!isDeepEqual(obj[key], ref[key], options, seen)) {
            return false;
        }
    }

    if (!options.part &&
        objKeys.length - skipped !== keys(ref).length) {

        return false;
    }

    // Check symbols

    if (options.symbols !== false) {                                // Defaults to true
        const objSymbols = getOwnPropertySymbols(obj);
        const refSymbols = new Set(getOwnPropertySymbols(ref));

        for (const key of objSymbols) {
            if (!options.skip ||
                !options.skip.includes(key)) {

                if (hasOwnEnumerableProperty(obj, key)) {
                    if (!hasOwnEnumerableProperty(ref, key)) {
                        return false;
                    }

                    if (!isDeepEqual(obj[key], ref[key], options, seen)) {
                        return false;
                    }
                }
                else if (hasOwnEnumerableProperty(ref, key)) {
                    return false;
                }
            }

            refSymbols.delete(key);
        }

        for (const key of refSymbols) {
            if (hasOwnEnumerableProperty(ref, key)) {
                return false;
            }
        }
    }

    return true;
};


internals.SeenEntry = class {

    constructor(obj, ref) {

        this.obj = obj;
        this.ref = ref;
    }

    isSame(obj, ref) {

        return this.obj === obj && this.ref === ref;
    }
};


/***/ }),

/***/ "1WHo":
/***/ (function(module, exports, __webpack_require__) {

const { inherits } = __webpack_require__("jK02")

function Reporter (options) {
  this._reporterState = {
    obj: null,
    path: [],
    options: options || {},
    errors: []
  }
}

Reporter.prototype.isError = function isError (obj) {
  return obj instanceof ReporterError
}

Reporter.prototype.save = function save () {
  const state = this._reporterState

  return { obj: state.obj, pathLen: state.path.length }
}

Reporter.prototype.restore = function restore (data) {
  const state = this._reporterState

  state.obj = data.obj
  state.path = state.path.slice(0, data.pathLen)
}

Reporter.prototype.enterKey = function enterKey (key) {
  return this._reporterState.path.push(key)
}

Reporter.prototype.exitKey = function exitKey (index) {
  const state = this._reporterState

  state.path = state.path.slice(0, index - 1)
}

Reporter.prototype.leaveKey = function leaveKey (index, key, value) {
  const state = this._reporterState

  this.exitKey(index)
  if (state.obj !== null) { state.obj[key] = value }
}

Reporter.prototype.path = function path () {
  return this._reporterState.path.join('/')
}

Reporter.prototype.enterObject = function enterObject () {
  const state = this._reporterState

  const prev = state.obj
  state.obj = {}
  return prev
}

Reporter.prototype.leaveObject = function leaveObject (prev) {
  const state = this._reporterState

  const now = state.obj
  state.obj = prev
  return now
}

Reporter.prototype.error = function error (msg) {
  let err
  const state = this._reporterState

  const inherited = msg instanceof ReporterError
  if (inherited) {
    err = msg
  } else {
    err = new ReporterError(state.path.map(function (elem) {
      return `[${JSON.stringify(elem)}]`
    }).join(''), msg.message || msg, msg.stack)
  }

  if (!state.options.partial) { throw err }

  if (!inherited) { state.errors.push(err) }

  return err
}

Reporter.prototype.wrapResult = function wrapResult (result) {
  const state = this._reporterState
  if (!state.options.partial) { return result }

  return {
    result: this.isError(result) ? null : result,
    errors: state.errors
  }
}

function ReporterError (path, msg) {
  this.path = path
  this.rethrow(msg)
}
inherits(ReporterError, Error)

ReporterError.prototype.rethrow = function rethrow (msg) {
  this.message = `${msg} at: ${this.path || '(shallow)'}`
  if (Error.captureStackTrace) { Error.captureStackTrace(this, ReporterError) }

  if (!this.stack) {
    try {
      // IE only adds stack when thrown
      throw new Error(this.message)
    } catch (e) {
      this.stack = e.stack
    }
  }
  return this
}

exports.Reporter = Reporter


/***/ }),

/***/ "1gXH":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const version_1 = tslib_1.__importDefault(__webpack_require__("Nndd"));
const url_helpers_1 = tslib_1.__importDefault(__webpack_require__("tuF3"));
const cookies_1 = __webpack_require__("gKi1");
const state_1 = __webpack_require__("ND7K");
function telemetry() {
    const bytes = Buffer.from(JSON.stringify({
        name: 'nextjs-auth0',
        version: version_1.default
    }));
    return bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function loginHandler(settings, clientProvider) {
    return (req, res, options) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        var _a;
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        if (req.query.redirectTo) {
            if (typeof req.query.redirectTo !== 'string') {
                throw new Error('Invalid value provided for redirectTo, must be a string');
            }
            if (!url_helpers_1.default(req.query.redirectTo)) {
                throw new Error('Invalid value provided for redirectTo, must be a relative url');
            }
        }
        const opt = options || {};
        const getLoginState = opt.getState ||
            function getLoginState() {
                return {};
            };
        const _b = (opt && opt.authParams) || {}, { 
        // Generate a state which contains a nonce, the redirectTo uri and potentially custom data
        state = state_1.createState(Object.assign({ redirectTo: ((_a = req.query) === null || _a === void 0 ? void 0 : _a.redirectTo) || (options === null || options === void 0 ? void 0 : options.redirectTo) }, getLoginState(req))) } = _b, authParams = tslib_1.__rest(_b, ["state"]);
        // Create the authorization url.
        const client = yield clientProvider();
        const authorizationUrl = client.authorizationUrl(Object.assign({ redirect_uri: settings.redirectUri, scope: settings.scope, response_type: 'code', audience: settings.audience, state, auth0Client: telemetry() }, authParams));
        // Set the necessary cookies
        cookies_1.setCookies(req, res, [
            {
                name: 'a0:state',
                value: state,
                maxAge: 60 * 60
            }
        ]);
        // Redirect to the authorize endpoint.
        res.writeHead(302, {
            Location: authorizationUrl
        });
        res.end();
    });
}
exports.default = loginHandler;
//# sourceMappingURL=login.js.map

/***/ }),

/***/ "1jOq":
/***/ (function(module, exports) {

// Returns a wrapper function that returns a wrapped callback
// The wrapper function should do some stuff, and return a
// presumably different callback function.
// This makes sure that own properties are retained, so that
// decorations and such are not lost along the way.
module.exports = wrappy
function wrappy (fn, cb) {
  if (fn && cb) return wrappy(fn)(cb)

  if (typeof fn !== 'function')
    throw new TypeError('need wrapper function')

  Object.keys(fn).forEach(function (k) {
    wrapper[k] = fn[k]
  })

  return wrapper

  function wrapper() {
    var args = new Array(arguments.length)
    for (var i = 0; i < args.length; i++) {
      args[i] = arguments[i]
    }
    var ret = fn.apply(this, args)
    var cb = args[args.length-1]
    if (typeof ret === 'function' && ret !== cb) {
      Object.keys(cb).forEach(function (k) {
        ret[k] = cb[k]
      })
    }
    return ret
  }
}


/***/ }),

/***/ "21rS":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const PassThrough = __webpack_require__("msIP").PassThrough;
const mimicResponse = __webpack_require__("qsvm");

const cloneResponse = response => {
	if (!(response && response.pipe)) {
		throw new TypeError('Parameter `response` must be a response stream.');
	}

	const clone = new PassThrough();
	mimicResponse(response, clone);

	return response.pipe(clone);
};

module.exports = cloneResponse;


/***/ }),

/***/ "2BAz":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const AssertError = __webpack_require__("p9XZ");

const internals = {};


module.exports = function (condition, ...args) {

    if (condition) {
        return;
    }

    if (args.length === 1 &&
        args[0] instanceof Error) {

        throw args[0];
    }

    throw new AssertError(args);
};


/***/ }),

/***/ "2IvE":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const net = __webpack_require__("Qs2e");

class TimeoutError extends Error {
	constructor(threshold, event) {
		super(`Timeout awaiting '${event}' for ${threshold}ms`);
		this.name = 'TimeoutError';
		this.code = 'ETIMEDOUT';
		this.event = event;
	}
}

const reentry = Symbol('reentry');

const noop = () => {};

module.exports = (request, delays, options) => {
	/* istanbul ignore next: this makes sure timed-out isn't called twice */
	if (request[reentry]) {
		return;
	}

	request[reentry] = true;

	let stopNewTimeouts = false;

	const addTimeout = (delay, callback, ...args) => {
		// An error had been thrown before. Going further would result in uncaught errors.
		// See https://github.com/sindresorhus/got/issues/631#issuecomment-435675051
		if (stopNewTimeouts) {
			return noop;
		}

		// Event loop order is timers, poll, immediates.
		// The timed event may emit during the current tick poll phase, so
		// defer calling the handler until the poll phase completes.
		let immediate;
		const timeout = setTimeout(() => {
			immediate = setImmediate(callback, delay, ...args);
			/* istanbul ignore next: added in node v9.7.0 */
			if (immediate.unref) {
				immediate.unref();
			}
		}, delay);

		/* istanbul ignore next: in order to support electron renderer */
		if (timeout.unref) {
			timeout.unref();
		}

		const cancel = () => {
			clearTimeout(timeout);
			clearImmediate(immediate);
		};

		cancelers.push(cancel);

		return cancel;
	};

	const {host, hostname} = options;
	const timeoutHandler = (delay, event) => {
		request.emit('error', new TimeoutError(delay, event));
		request.once('error', () => {}); // Ignore the `socket hung up` error made by request.abort()

		request.abort();
	};

	const cancelers = [];
	const cancelTimeouts = () => {
		stopNewTimeouts = true;
		cancelers.forEach(cancelTimeout => cancelTimeout());
	};

	request.once('error', cancelTimeouts);
	request.once('response', response => {
		response.once('end', cancelTimeouts);
	});

	if (delays.request !== undefined) {
		addTimeout(delays.request, timeoutHandler, 'request');
	}

	if (delays.socket !== undefined) {
		const socketTimeoutHandler = () => {
			timeoutHandler(delays.socket, 'socket');
		};

		request.setTimeout(delays.socket, socketTimeoutHandler);

		// `request.setTimeout(0)` causes a memory leak.
		// We can just remove the listener and forget about the timer - it's unreffed.
		// See https://github.com/sindresorhus/got/issues/690
		cancelers.push(() => request.removeListener('timeout', socketTimeoutHandler));
	}

	if (delays.lookup !== undefined && !request.socketPath && !net.isIP(hostname || host)) {
		request.once('socket', socket => {
			/* istanbul ignore next: hard to test */
			if (socket.connecting) {
				const cancelTimeout = addTimeout(delays.lookup, timeoutHandler, 'lookup');
				socket.once('lookup', cancelTimeout);
			}
		});
	}

	if (delays.connect !== undefined) {
		request.once('socket', socket => {
			/* istanbul ignore next: hard to test */
			if (socket.connecting) {
				const timeConnect = () => addTimeout(delays.connect, timeoutHandler, 'connect');

				if (request.socketPath || net.isIP(hostname || host)) {
					socket.once('connect', timeConnect());
				} else {
					socket.once('lookup', error => {
						if (error === null) {
							socket.once('connect', timeConnect());
						}
					});
				}
			}
		});
	}

	if (delays.secureConnect !== undefined && options.protocol === 'https:') {
		request.once('socket', socket => {
			/* istanbul ignore next: hard to test */
			if (socket.connecting) {
				socket.once('connect', () => {
					const cancelTimeout = addTimeout(delays.secureConnect, timeoutHandler, 'secureConnect');
					socket.once('secureConnect', cancelTimeout);
				});
			}
		});
	}

	if (delays.send !== undefined) {
		request.once('socket', socket => {
			const timeRequest = () => addTimeout(delays.send, timeoutHandler, 'send');
			/* istanbul ignore next: hard to test */
			if (socket.connecting) {
				socket.once('connect', () => {
					request.once('upload-complete', timeRequest());
				});
			} else {
				request.once('upload-complete', timeRequest());
			}
		});
	}

	if (delays.response !== undefined) {
		request.once('upload-complete', () => {
			const cancelTimeout = addTimeout(delays.response, timeoutHandler, 'response');
			request.once('response', cancelTimeout);
		});
	}
};

module.exports.TimeoutError = TimeoutError;


/***/ }),

/***/ "2KX+":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const token_cache_1 = tslib_1.__importDefault(__webpack_require__("0Kms"));
function profileHandler(sessionStore, clientProvider) {
    return (req, res, options) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        const session = yield sessionStore.read(req);
        if (!session || !session.user) {
            res.status(401).json({
                error: 'not_authenticated',
                description: 'The user does not have an active session or is not authenticated'
            });
            return;
        }
        if (options && options.refetch) {
            const tokenCache = token_cache_1.default(clientProvider, sessionStore)(req, res);
            const { accessToken } = yield tokenCache.getAccessToken();
            if (!accessToken) {
                throw new Error('No access token available to refetch the profile');
            }
            const client = yield clientProvider();
            const userInfo = yield client.userinfo(accessToken);
            const updatedUser = Object.assign(Object.assign({}, session.user), userInfo);
            yield sessionStore.save(req, res, Object.assign(Object.assign({}, session), { user: updatedUser }));
            res.json(updatedUser);
            return;
        }
        res.json(session.user);
    });
}
exports.default = profileHandler;
//# sourceMappingURL=profile.js.map

/***/ }),

/***/ "33Iv":
/***/ (function(module, exports, __webpack_require__) {

const { inflateRawSync } = __webpack_require__("FMKJ")

const base64url = __webpack_require__("Xab3")
const getKey = __webpack_require__("oGTz")
const { KeyStore } = __webpack_require__("WPgm")
const errors = __webpack_require__("yt7c")
const { check, decrypt, keyManagementDecrypt } = __webpack_require__("FUB/")
const JWK = __webpack_require__("lA9T")

const { createSecretKey } = __webpack_require__("1ALl")
const generateCEK = __webpack_require__("RGIU")
const validateHeaders = __webpack_require__("OHZa")
const { detect: resolveSerialization } = __webpack_require__("ARPQ")

const SINGLE_RECIPIENT = new Set(['compact', 'flattened'])

const combineHeader = (prot = {}, unprotected = {}, header = {}) => {
  if (typeof prot === 'string') {
    prot = base64url.JSON.decode(prot)
  }

  const p2s = prot.p2s || unprotected.p2s || header.p2s
  const apu = prot.apu || unprotected.apu || header.apu
  const apv = prot.apv || unprotected.apv || header.apv
  const iv = prot.iv || unprotected.iv || header.iv
  const tag = prot.tag || unprotected.tag || header.tag

  return {
    ...prot,
    ...unprotected,
    ...header,
    ...(typeof p2s === 'string' ? { p2s: base64url.decodeToBuffer(p2s) } : undefined),
    ...(typeof apu === 'string' ? { apu: base64url.decodeToBuffer(apu) } : undefined),
    ...(typeof apv === 'string' ? { apv: base64url.decodeToBuffer(apv) } : undefined),
    ...(typeof iv === 'string' ? { iv: base64url.decodeToBuffer(iv) } : undefined),
    ...(typeof tag === 'string' ? { tag: base64url.decodeToBuffer(tag) } : undefined)
  }
}

/*
 * @public
 */
const jweDecrypt = (skipValidateHeaders, serialization, jwe, key, { crit = [], complete = false, algorithms } = {}) => {
  key = getKey(key, true)

  if (algorithms !== undefined && (!Array.isArray(algorithms) || algorithms.some(s => typeof s !== 'string' || !s))) {
    throw new TypeError('"algorithms" option must be an array of non-empty strings')
  } else if (algorithms) {
    algorithms = new Set(algorithms)
  }

  if (!Array.isArray(crit) || crit.some(s => typeof s !== 'string' || !s)) {
    throw new TypeError('"crit" option must be an array of non-empty strings')
  }

  if (!serialization) {
    serialization = resolveSerialization(jwe)
  }

  let alg, ciphertext, enc, encryptedKey, iv, opts, prot, tag, unprotected, cek, aad, header

  // treat general format with one recipient as flattened
  // skips iteration and avoids multi errors in this case
  if (serialization === 'general' && jwe.recipients.length === 1) {
    serialization = 'flattened'
    const { recipients, ...root } = jwe
    jwe = { ...root, ...recipients[0] }
  }

  if (SINGLE_RECIPIENT.has(serialization)) {
    if (serialization === 'compact') { // compact serialization format
      ([prot, encryptedKey, iv, ciphertext, tag] = jwe.split('.'))
    } else { // flattened serialization format
      ({ protected: prot, encrypted_key: encryptedKey, iv, ciphertext, tag, unprotected, aad, header } = jwe)
    }

    if (!skipValidateHeaders) {
      validateHeaders(prot, unprotected, [{ header }], true, crit)
    }

    opts = combineHeader(prot, unprotected, header)

    ;({ alg, enc } = opts)

    if (algorithms && !algorithms.has(alg === 'dir' ? enc : alg)) {
      throw new errors.JOSEAlgNotWhitelisted('alg not whitelisted')
    }

    if (key instanceof KeyStore) {
      const keystore = key
      let keys
      if (opts.alg === 'dir') {
        keys = keystore.all({ kid: opts.kid, alg: opts.enc, key_ops: ['decrypt'] })
      } else {
        keys = keystore.all({ kid: opts.kid, alg: opts.alg, key_ops: ['unwrapKey'] })
      }
      switch (keys.length) {
        case 0:
          throw new errors.JWKSNoMatchingKey()
        case 1:
          // treat the call as if a Key instance was passed in
          // skips iteration and avoids multi errors in this case
          key = keys[0]
          break
        default: {
          const errs = []
          for (const key of keys) {
            try {
              return jweDecrypt(true, serialization, jwe, key, { crit, complete, algorithms: algorithms ? [...algorithms] : undefined })
            } catch (err) {
              errs.push(err)
              continue
            }
          }

          const multi = new errors.JOSEMultiError(errs)
          if ([...multi].some(e => e instanceof errors.JWEDecryptionFailed)) {
            throw new errors.JWEDecryptionFailed()
          }
          throw multi
        }
      }
    }

    check(key, ...(alg === 'dir' ? ['decrypt', enc] : ['keyManagementDecrypt', alg]))

    try {
      if (alg === 'dir') {
        cek = JWK.asKey(key, { alg: enc, use: 'enc' })
      } else if (alg === 'ECDH-ES') {
        const unwrapped = keyManagementDecrypt(alg, key, undefined, opts)
        cek = JWK.asKey(createSecretKey(unwrapped), { alg: enc, use: 'enc' })
      } else {
        const unwrapped = keyManagementDecrypt(alg, key, base64url.decodeToBuffer(encryptedKey), opts)
        cek = JWK.asKey(createSecretKey(unwrapped), { alg: enc, use: 'enc' })
      }
    } catch (err) {
      // To mitigate the attacks described in RFC 3218, the
      // recipient MUST NOT distinguish between format, padding, and length
      // errors of encrypted keys.  It is strongly recommended, in the event
      // of receiving an improperly formatted key, that the recipient
      // substitute a randomly generated CEK and proceed to the next step, to
      // mitigate timing attacks.
      cek = generateCEK(enc)
    }

    let adata
    if (aad) {
      adata = Buffer.concat([
        Buffer.from(prot || ''),
        Buffer.from('.'),
        Buffer.from(aad)
      ])
    } else {
      adata = Buffer.from(prot || '')
    }

    try {
      iv = base64url.decodeToBuffer(iv)
    } catch (err) {}
    try {
      tag = base64url.decodeToBuffer(tag)
    } catch (err) {}

    let cleartext = decrypt(enc, cek, base64url.decodeToBuffer(ciphertext), { iv, tag, aad: adata })

    if (opts.zip) {
      cleartext = inflateRawSync(cleartext)
    }

    if (complete) {
      const result = { cleartext, key, cek }
      if (aad) result.aad = aad
      if (header) result.header = header
      if (unprotected) result.unprotected = unprotected
      if (prot) result.protected = base64url.JSON.decode(prot)
      return result
    }

    return cleartext
  }

  validateHeaders(jwe.protected, jwe.unprotected, jwe.recipients.map(({ header }) => ({ header })), true, crit)

  // general serialization format
  const { recipients, ...root } = jwe
  const errs = []
  for (const recipient of recipients) {
    try {
      return jweDecrypt(true, 'flattened', { ...root, ...recipient }, key, { crit, complete, algorithms: algorithms ? [...algorithms] : undefined })
    } catch (err) {
      errs.push(err)
      continue
    }
  }

  const multi = new errors.JOSEMultiError(errs)
  if ([...multi].some(e => e instanceof errors.JWEDecryptionFailed)) {
    throw new errors.JWEDecryptionFailed()
  } else if ([...multi].every(e => e instanceof errors.JWKSNoMatchingKey)) {
    throw new errors.JWKSNoMatchingKey()
  }
  throw multi
}

module.exports = jweDecrypt.bind(undefined, false, undefined)


/***/ }),

/***/ "3AyT":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (string) {

    // Escape ^$.*+-?=!:|\/()[]{},

    return string.replace(/[\^\$\.\*\+\-\?\=\!\:\|\\\/\(\)\[\]\{\}\,]/g, '\\$&');
};


/***/ }),

/***/ "3HlQ":
/***/ (function(module, exports, __webpack_require__) {

const { generateKeyPairSync, generateKeyPair: async } = __webpack_require__("PJMN")
const { promisify } = __webpack_require__("jK02")

const {
  THUMBPRINT_MATERIAL, JWK_MEMBERS, PUBLIC_MEMBERS,
  PRIVATE_MEMBERS, KEY_MANAGEMENT_DECRYPT, KEY_MANAGEMENT_ENCRYPT
} = __webpack_require__("ehsS")
const { EC_CURVES } = __webpack_require__("N+nT")
const { keyObjectSupported } = __webpack_require__("pDDt")
const { createPublicKey, createPrivateKey } = __webpack_require__("1ALl")

const errors = __webpack_require__("yt7c")
const { name: secp256k1 } = __webpack_require__("F/JS")

const Key = __webpack_require__("//Cd")

const generateKeyPair = promisify(async)

const EC_PUBLIC = new Set(['crv', 'x', 'y'])
Object.freeze(EC_PUBLIC)
const EC_PRIVATE = new Set([...EC_PUBLIC, 'd'])
Object.freeze(EC_PRIVATE)

// Elliptic Curve Key Type
class ECKey extends Key {
  constructor (...args) {
    super(...args)
    this[JWK_MEMBERS]()
    Object.defineProperty(this, 'kty', { value: 'EC', enumerable: true })
    if (!EC_CURVES.has(this.crv)) {
      throw new errors.JOSENotSupported('unsupported EC key curve')
    }
  }

  static get [PUBLIC_MEMBERS] () {
    return EC_PUBLIC
  }

  static get [PRIVATE_MEMBERS] () {
    return EC_PRIVATE
  }

  // https://tc39.github.io/ecma262/#sec-ordinaryownpropertykeys no need for any special
  // JSON.stringify handling in V8
  [THUMBPRINT_MATERIAL] () {
    return { crv: this.crv, kty: 'EC', x: this.x, y: this.y }
  }

  [KEY_MANAGEMENT_ENCRYPT] () {
    return this.algorithms('deriveKey')
  }

  [KEY_MANAGEMENT_DECRYPT] () {
    if (this.public) {
      return new Set()
    }
    return this.algorithms('deriveKey')
  }

  static async generate (crv = 'P-256', privat = true) {
    if (!EC_CURVES.has(crv)) {
      throw new errors.JOSENotSupported(`unsupported EC key curve: ${crv}`)
    }

    if (crv === secp256k1 && crv !== 'secp256k1') {
      crv = 'secp256k1'
    }

    let privateKey, publicKey

    if (keyObjectSupported) {
      ({ privateKey, publicKey } = await generateKeyPair('ec', { namedCurve: crv }))
      return privat ? privateKey : publicKey
    }

    ({ privateKey, publicKey } = await generateKeyPair('ec', {
      namedCurve: crv,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }))

    if (privat) {
      return createPrivateKey(privateKey)
    } else {
      return createPublicKey(publicKey)
    }
  }

  static generateSync (crv = 'P-256', privat = true) {
    if (!EC_CURVES.has(crv)) {
      throw new errors.JOSENotSupported(`unsupported EC key curve: ${crv}`)
    }

    if (crv === secp256k1 && crv !== 'secp256k1') {
      crv = 'secp256k1'
    }

    let privateKey, publicKey

    if (keyObjectSupported) {
      ({ privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: crv }))
      return privat ? privateKey : publicKey
    }

    ({ privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: crv,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }))

    if (privat) {
      return createPrivateKey(privateKey)
    } else {
      return createPublicKey(publicKey)
    }
  }
}

module.exports = ECKey


/***/ }),

/***/ "3J/O":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("eq/D");


const internals = {};


exports.keys = function (obj, options = {}) {

    return options.symbols !== false ? Reflect.ownKeys(obj) : Object.getOwnPropertyNames(obj);  // Defaults to true
};


exports.store = function (source, keys) {

    const storage = new Map();
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        const value = Reach(source, key);
        if (typeof value === 'object' ||
            typeof value === 'function') {

            storage.set(key, value);
            internals.reachSet(source, key, undefined);
        }
    }

    return storage;
};


exports.restore = function (copy, source, storage) {

    for (const [key, value] of storage) {
        internals.reachSet(copy, key, value);
        internals.reachSet(source, key, value);
    }
};


internals.reachSet = function (obj, key, value) {

    const path = Array.isArray(key) ? key : key.split('.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        const segment = path[i];
        if (i + 1 === path.length) {
            ref[segment] = value;
        }

        ref = ref[segment];
    }
};


/***/ }),

/***/ "3WeD":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;
exports.searchParamsToUrlQuery = searchParamsToUrlQuery;
exports.urlQueryToSearchParams = urlQueryToSearchParams;
exports.assign = assign;

function searchParamsToUrlQuery(searchParams) {
  const query = {};
  searchParams.forEach((value, key) => {
    if (typeof query[key] === 'undefined') {
      query[key] = value;
    } else if (Array.isArray(query[key])) {
      ;
      query[key].push(value);
    } else {
      query[key] = [query[key], value];
    }
  });
  return query;
}

function stringifyUrlQueryParam(param) {
  if (typeof param === 'string' || typeof param === 'number' && !isNaN(param) || typeof param === 'boolean') {
    return String(param);
  } else {
    return '';
  }
}

function urlQueryToSearchParams(urlQuery) {
  const result = new URLSearchParams();
  Object.entries(urlQuery).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach(item => result.append(key, stringifyUrlQueryParam(item)));
    } else {
      result.set(key, stringifyUrlQueryParam(value));
    }
  });
  return result;
}

function assign(target, ...searchParamsList) {
  searchParamsList.forEach(searchParams => {
    Array.from(searchParams.keys()).forEach(key => target.delete(key));
    searchParams.forEach((value, key) => target.append(key, value));
  });
  return target;
}

/***/ }),

/***/ "4Hvf":
/***/ (function(module, exports) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,t){"use strict";var s={};function __webpack_require__(t){if(s[t]){return s[t].exports}var r=s[t]={i:t,l:false,exports:{}};e[t].call(r.exports,r,r.exports,__webpack_require__);r.l=true;return r.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(876)}return startup()}({16:function(e,t,s){const r=s(65);const n=(e,t,s)=>{const n=new r(e,s);const o=new r(t,s);return n.compare(o)||n.compareBuild(o)};e.exports=n},65:function(e,t,s){const r=s(548);const{MAX_LENGTH:n,MAX_SAFE_INTEGER:o}=s(181);const{re:i,t:c}=s(976);const{compareIdentifiers:a}=s(760);class SemVer{constructor(e,t){if(!t||typeof t!=="object"){t={loose:!!t,includePrerelease:false}}if(e instanceof SemVer){if(e.loose===!!t.loose&&e.includePrerelease===!!t.includePrerelease){return e}else{e=e.version}}else if(typeof e!=="string"){throw new TypeError(`Invalid Version: ${e}`)}if(e.length>n){throw new TypeError(`version is longer than ${n} characters`)}r("SemVer",e,t);this.options=t;this.loose=!!t.loose;this.includePrerelease=!!t.includePrerelease;const s=e.trim().match(t.loose?i[c.LOOSE]:i[c.FULL]);if(!s){throw new TypeError(`Invalid Version: ${e}`)}this.raw=e;this.major=+s[1];this.minor=+s[2];this.patch=+s[3];if(this.major>o||this.major<0){throw new TypeError("Invalid major version")}if(this.minor>o||this.minor<0){throw new TypeError("Invalid minor version")}if(this.patch>o||this.patch<0){throw new TypeError("Invalid patch version")}if(!s[4]){this.prerelease=[]}else{this.prerelease=s[4].split(".").map(e=>{if(/^[0-9]+$/.test(e)){const t=+e;if(t>=0&&t<o){return t}}return e})}this.build=s[5]?s[5].split("."):[];this.format()}format(){this.version=`${this.major}.${this.minor}.${this.patch}`;if(this.prerelease.length){this.version+=`-${this.prerelease.join(".")}`}return this.version}toString(){return this.version}compare(e){r("SemVer.compare",this.version,this.options,e);if(!(e instanceof SemVer)){if(typeof e==="string"&&e===this.version){return 0}e=new SemVer(e,this.options)}if(e.version===this.version){return 0}return this.compareMain(e)||this.comparePre(e)}compareMain(e){if(!(e instanceof SemVer)){e=new SemVer(e,this.options)}return a(this.major,e.major)||a(this.minor,e.minor)||a(this.patch,e.patch)}comparePre(e){if(!(e instanceof SemVer)){e=new SemVer(e,this.options)}if(this.prerelease.length&&!e.prerelease.length){return-1}else if(!this.prerelease.length&&e.prerelease.length){return 1}else if(!this.prerelease.length&&!e.prerelease.length){return 0}let t=0;do{const s=this.prerelease[t];const n=e.prerelease[t];r("prerelease compare",t,s,n);if(s===undefined&&n===undefined){return 0}else if(n===undefined){return 1}else if(s===undefined){return-1}else if(s===n){continue}else{return a(s,n)}}while(++t)}compareBuild(e){if(!(e instanceof SemVer)){e=new SemVer(e,this.options)}let t=0;do{const s=this.build[t];const n=e.build[t];r("prerelease compare",t,s,n);if(s===undefined&&n===undefined){return 0}else if(n===undefined){return 1}else if(s===undefined){return-1}else if(s===n){continue}else{return a(s,n)}}while(++t)}inc(e,t){switch(e){case"premajor":this.prerelease.length=0;this.patch=0;this.minor=0;this.major++;this.inc("pre",t);break;case"preminor":this.prerelease.length=0;this.patch=0;this.minor++;this.inc("pre",t);break;case"prepatch":this.prerelease.length=0;this.inc("patch",t);this.inc("pre",t);break;case"prerelease":if(this.prerelease.length===0){this.inc("patch",t)}this.inc("pre",t);break;case"major":if(this.minor!==0||this.patch!==0||this.prerelease.length===0){this.major++}this.minor=0;this.patch=0;this.prerelease=[];break;case"minor":if(this.patch!==0||this.prerelease.length===0){this.minor++}this.patch=0;this.prerelease=[];break;case"patch":if(this.prerelease.length===0){this.patch++}this.prerelease=[];break;case"pre":if(this.prerelease.length===0){this.prerelease=[0]}else{let e=this.prerelease.length;while(--e>=0){if(typeof this.prerelease[e]==="number"){this.prerelease[e]++;e=-2}}if(e===-1){this.prerelease.push(0)}}if(t){if(this.prerelease[0]===t){if(isNaN(this.prerelease[1])){this.prerelease=[t,0]}}else{this.prerelease=[t,0]}}break;default:throw new Error(`invalid increment argument: ${e}`)}this.format();this.raw=this.version;return this}}e.exports=SemVer},120:function(e,t,s){const r=s(16);const n=(e,t)=>e.sort((e,s)=>r(e,s,t));e.exports=n},124:function(e,t,s){class Range{constructor(e,t){if(!t||typeof t!=="object"){t={loose:!!t,includePrerelease:false}}if(e instanceof Range){if(e.loose===!!t.loose&&e.includePrerelease===!!t.includePrerelease){return e}else{return new Range(e.raw,t)}}if(e instanceof r){this.raw=e.value;this.set=[[e]];this.format();return this}this.options=t;this.loose=!!t.loose;this.includePrerelease=!!t.includePrerelease;this.raw=e;this.set=e.split(/\s*\|\|\s*/).map(e=>this.parseRange(e.trim())).filter(e=>e.length);if(!this.set.length){throw new TypeError(`Invalid SemVer Range: ${e}`)}this.format()}format(){this.range=this.set.map(e=>{return e.join(" ").trim()}).join("||").trim();return this.range}toString(){return this.range}parseRange(e){const t=this.options.loose;e=e.trim();const s=t?i[c.HYPHENRANGELOOSE]:i[c.HYPHENRANGE];e=e.replace(s,T(this.options.includePrerelease));n("hyphen replace",e);e=e.replace(i[c.COMPARATORTRIM],a);n("comparator trim",e,i[c.COMPARATORTRIM]);e=e.replace(i[c.TILDETRIM],l);e=e.replace(i[c.CARETTRIM],f);e=e.split(/\s+/).join(" ");const o=t?i[c.COMPARATORLOOSE]:i[c.COMPARATOR];return e.split(" ").map(e=>E(e,this.options)).join(" ").split(/\s+/).map(e=>A(e,this.options)).filter(this.options.loose?e=>!!e.match(o):()=>true).map(e=>new r(e,this.options))}intersects(e,t){if(!(e instanceof Range)){throw new TypeError("a Range is required")}return this.set.some(s=>{return u(s,t)&&e.set.some(e=>{return u(e,t)&&s.every(s=>{return e.every(e=>{return s.intersects(e,t)})})})})}test(e){if(!e){return false}if(typeof e==="string"){try{e=new o(e,this.options)}catch(e){return false}}for(let t=0;t<this.set.length;t++){if(S(this.set[t],e,this.options)){return true}}return false}}e.exports=Range;const r=s(174);const n=s(548);const o=s(65);const{re:i,t:c,comparatorTrimReplace:a,tildeTrimReplace:l,caretTrimReplace:f}=s(976);const u=(e,t)=>{let s=true;const r=e.slice();let n=r.pop();while(s&&r.length){s=r.every(e=>{return n.intersects(e,t)});n=r.pop()}return s};const E=(e,t)=>{n("comp",e,t);e=R(e,t);n("caret",e);e=$(e,t);n("tildes",e);e=N(e,t);n("xrange",e);e=L(e,t);n("stars",e);return e};const h=e=>!e||e.toLowerCase()==="x"||e==="*";const $=(e,t)=>e.trim().split(/\s+/).map(e=>{return I(e,t)}).join(" ");const I=(e,t)=>{const s=t.loose?i[c.TILDELOOSE]:i[c.TILDE];return e.replace(s,(t,s,r,o,i)=>{n("tilde",e,t,s,r,o,i);let c;if(h(s)){c=""}else if(h(r)){c=`>=${s}.0.0 <${+s+1}.0.0-0`}else if(h(o)){c=`>=${s}.${r}.0 <${s}.${+r+1}.0-0`}else if(i){n("replaceTilde pr",i);c=`>=${s}.${r}.${o}-${i} <${s}.${+r+1}.0-0`}else{c=`>=${s}.${r}.${o} <${s}.${+r+1}.0-0`}n("tilde return",c);return c})};const R=(e,t)=>e.trim().split(/\s+/).map(e=>{return p(e,t)}).join(" ");const p=(e,t)=>{n("caret",e,t);const s=t.loose?i[c.CARETLOOSE]:i[c.CARET];const r=t.includePrerelease?"-0":"";return e.replace(s,(t,s,o,i,c)=>{n("caret",e,t,s,o,i,c);let a;if(h(s)){a=""}else if(h(o)){a=`>=${s}.0.0${r} <${+s+1}.0.0-0`}else if(h(i)){if(s==="0"){a=`>=${s}.${o}.0${r} <${s}.${+o+1}.0-0`}else{a=`>=${s}.${o}.0${r} <${+s+1}.0.0-0`}}else if(c){n("replaceCaret pr",c);if(s==="0"){if(o==="0"){a=`>=${s}.${o}.${i}-${c} <${s}.${o}.${+i+1}-0`}else{a=`>=${s}.${o}.${i}-${c} <${s}.${+o+1}.0-0`}}else{a=`>=${s}.${o}.${i}-${c} <${+s+1}.0.0-0`}}else{n("no pr");if(s==="0"){if(o==="0"){a=`>=${s}.${o}.${i}${r} <${s}.${o}.${+i+1}-0`}else{a=`>=${s}.${o}.${i}${r} <${s}.${+o+1}.0-0`}}else{a=`>=${s}.${o}.${i} <${+s+1}.0.0-0`}}n("caret return",a);return a})};const N=(e,t)=>{n("replaceXRanges",e,t);return e.split(/\s+/).map(e=>{return O(e,t)}).join(" ")};const O=(e,t)=>{e=e.trim();const s=t.loose?i[c.XRANGELOOSE]:i[c.XRANGE];return e.replace(s,(s,r,o,i,c,a)=>{n("xRange",e,s,r,o,i,c,a);const l=h(o);const f=l||h(i);const u=f||h(c);const E=u;if(r==="="&&E){r=""}a=t.includePrerelease?"-0":"";if(l){if(r===">"||r==="<"){s="<0.0.0-0"}else{s="*"}}else if(r&&E){if(f){i=0}c=0;if(r===">"){r=">=";if(f){o=+o+1;i=0;c=0}else{i=+i+1;c=0}}else if(r==="<="){r="<";if(f){o=+o+1}else{i=+i+1}}if(r==="<")a="-0";s=`${r+o}.${i}.${c}${a}`}else if(f){s=`>=${o}.0.0${a} <${+o+1}.0.0-0`}else if(u){s=`>=${o}.${i}.0${a} <${o}.${+i+1}.0-0`}n("xRange return",s);return s})};const L=(e,t)=>{n("replaceStars",e,t);return e.trim().replace(i[c.STAR],"")};const A=(e,t)=>{n("replaceGTE0",e,t);return e.trim().replace(i[t.includePrerelease?c.GTE0PRE:c.GTE0],"")};const T=e=>(t,s,r,n,o,i,c,a,l,f,u,E,$)=>{if(h(r)){s=""}else if(h(n)){s=`>=${r}.0.0${e?"-0":""}`}else if(h(o)){s=`>=${r}.${n}.0${e?"-0":""}`}else if(i){s=`>=${s}`}else{s=`>=${s}${e?"-0":""}`}if(h(l)){a=""}else if(h(f)){a=`<${+l+1}.0.0-0`}else if(h(u)){a=`<${l}.${+f+1}.0-0`}else if(E){a=`<=${l}.${f}.${u}-${E}`}else if(e){a=`<${l}.${f}.${+u+1}-0`}else{a=`<=${a}`}return`${s} ${a}`.trim()};const S=(e,t,s)=>{for(let s=0;s<e.length;s++){if(!e[s].test(t)){return false}}if(t.prerelease.length&&!s.includePrerelease){for(let s=0;s<e.length;s++){n(e[s].semver);if(e[s].semver===r.ANY){continue}if(e[s].semver.prerelease.length>0){const r=e[s].semver;if(r.major===t.major&&r.minor===t.minor&&r.patch===t.patch){return true}}}return false}return true}},164:function(e,t,s){const r=s(65);const n=s(124);const o=s(486);const i=(e,t)=>{e=new n(e,t);let s=new r("0.0.0");if(e.test(s)){return s}s=new r("0.0.0-0");if(e.test(s)){return s}s=null;for(let t=0;t<e.set.length;++t){const n=e.set[t];n.forEach(e=>{const t=new r(e.semver.version);switch(e.operator){case">":if(t.prerelease.length===0){t.patch++}else{t.prerelease.push(0)}t.raw=t.format();case"":case">=":if(!s||o(s,t)){s=t}break;case"<":case"<=":break;default:throw new Error(`Unexpected operation: ${e.operator}`)}})}if(s&&e.test(s)){return s}return null};e.exports=i},167:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)>=0;e.exports=n},174:function(e,t,s){const r=Symbol("SemVer ANY");class Comparator{static get ANY(){return r}constructor(e,t){if(!t||typeof t!=="object"){t={loose:!!t,includePrerelease:false}}if(e instanceof Comparator){if(e.loose===!!t.loose){return e}else{e=e.value}}c("comparator",e,t);this.options=t;this.loose=!!t.loose;this.parse(e);if(this.semver===r){this.value=""}else{this.value=this.operator+this.semver.version}c("comp",this)}parse(e){const t=this.options.loose?n[o.COMPARATORLOOSE]:n[o.COMPARATOR];const s=e.match(t);if(!s){throw new TypeError(`Invalid comparator: ${e}`)}this.operator=s[1]!==undefined?s[1]:"";if(this.operator==="="){this.operator=""}if(!s[2]){this.semver=r}else{this.semver=new a(s[2],this.options.loose)}}toString(){return this.value}test(e){c("Comparator.test",e,this.options.loose);if(this.semver===r||e===r){return true}if(typeof e==="string"){try{e=new a(e,this.options)}catch(e){return false}}return i(e,this.operator,this.semver,this.options)}intersects(e,t){if(!(e instanceof Comparator)){throw new TypeError("a Comparator is required")}if(!t||typeof t!=="object"){t={loose:!!t,includePrerelease:false}}if(this.operator===""){if(this.value===""){return true}return new l(e.value,t).test(this.value)}else if(e.operator===""){if(e.value===""){return true}return new l(this.value,t).test(e.semver)}const s=(this.operator===">="||this.operator===">")&&(e.operator===">="||e.operator===">");const r=(this.operator==="<="||this.operator==="<")&&(e.operator==="<="||e.operator==="<");const n=this.semver.version===e.semver.version;const o=(this.operator===">="||this.operator==="<=")&&(e.operator===">="||e.operator==="<=");const c=i(this.semver,"<",e.semver,t)&&(this.operator===">="||this.operator===">")&&(e.operator==="<="||e.operator==="<");const a=i(this.semver,">",e.semver,t)&&(this.operator==="<="||this.operator==="<")&&(e.operator===">="||e.operator===">");return s||r||n&&o||c||a}}e.exports=Comparator;const{re:n,t:o}=s(976);const i=s(752);const c=s(548);const a=s(65);const l=s(124)},181:function(e){const t="2.0.0";const s=256;const r=Number.MAX_SAFE_INTEGER||9007199254740991;const n=16;e.exports={SEMVER_SPEC_VERSION:t,MAX_LENGTH:s,MAX_SAFE_INTEGER:r,MAX_SAFE_COMPONENT_LENGTH:n}},219:function(e,t,s){const r=s(124);const n=(e,t)=>new r(e,t).set.map(e=>e.map(e=>e.value).join(" ").trim().split(" "));e.exports=n},259:function(e,t,s){const r=s(124);const n=(e,t,s)=>{e=new r(e,s);t=new r(t,s);return e.intersects(t)};e.exports=n},283:function(e,t,s){const r=s(874);const n=(e,t)=>r(e,t,true);e.exports=n},298:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)===0;e.exports=n},310:function(e,t,s){const r=s(124);const n=(e,t,s)=>{try{t=new r(t,s)}catch(e){return false}return t.test(e)};e.exports=n},323:function(e,t,s){const r=s(462);const n=(e,t,s)=>r(e,t,"<",s);e.exports=n},431:function(e,t,s){const r=s(65);const n=(e,t,s,n)=>{if(typeof s==="string"){n=s;s=undefined}try{return new r(e,s).inc(t,n).version}catch(e){return null}};e.exports=n},462:function(e,t,s){const r=s(65);const n=s(174);const{ANY:o}=n;const i=s(124);const c=s(310);const a=s(486);const l=s(586);const f=s(898);const u=s(167);const E=(e,t,s,E)=>{e=new r(e,E);t=new i(t,E);let h,$,I,R,p;switch(s){case">":h=a;$=f;I=l;R=">";p=">=";break;case"<":h=l;$=u;I=a;R="<";p="<=";break;default:throw new TypeError('Must provide a hilo val of "<" or ">"')}if(c(e,t,E)){return false}for(let s=0;s<t.set.length;++s){const r=t.set[s];let i=null;let c=null;r.forEach(e=>{if(e.semver===o){e=new n(">=0.0.0")}i=i||e;c=c||e;if(h(e.semver,i.semver,E)){i=e}else if(I(e.semver,c.semver,E)){c=e}});if(i.operator===R||i.operator===p){return false}if((!c.operator||c.operator===R)&&$(e,c.semver)){return false}else if(c.operator===p&&I(e,c.semver)){return false}}return true};e.exports=E},480:function(e,t,s){const r=s(124);const n=(e,t)=>{try{return new r(e,t).range||"*"}catch(e){return null}};e.exports=n},486:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)>0;e.exports=n},489:function(e,t,s){const r=s(65);const n=(e,t)=>new r(e,t).patch;e.exports=n},499:function(e,t,s){const r=s(65);const n=s(830);const{re:o,t:i}=s(976);const c=(e,t)=>{if(e instanceof r){return e}if(typeof e==="number"){e=String(e)}if(typeof e!=="string"){return null}t=t||{};let s=null;if(!t.rtl){s=e.match(o[i.COERCE])}else{let t;while((t=o[i.COERCERTL].exec(e))&&(!s||s.index+s[0].length!==e.length)){if(!s||t.index+t[0].length!==s.index+s[0].length){s=t}o[i.COERCERTL].lastIndex=t.index+t[1].length+t[2].length}o[i.COERCERTL].lastIndex=-1}if(s===null)return null;return n(`${s[2]}.${s[3]||"0"}.${s[4]||"0"}`,t)};e.exports=c},503:function(e,t,s){const r=s(830);const n=(e,t)=>{const s=r(e.trim().replace(/^[=v]+/,""),t);return s?s.version:null};e.exports=n},531:function(e,t,s){const r=s(462);const n=(e,t,s)=>r(e,t,">",s);e.exports=n},548:function(e){const t=typeof process==="object"&&process.env&&process.env.NODE_DEBUG&&/\bsemver\b/i.test(process.env.NODE_DEBUG)?(...e)=>console.error("SEMVER",...e):()=>{};e.exports=t},586:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)<0;e.exports=n},593:function(e,t,s){const r=s(16);const n=(e,t)=>e.sort((e,s)=>r(s,e,t));e.exports=n},630:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(t,e,s);e.exports=n},714:function(e,t,s){const r=s(830);const n=(e,t)=>{const s=r(e,t);return s?s.version:null};e.exports=n},740:function(e,t,s){const r=s(65);const n=s(124);const o=(e,t,s)=>{let o=null;let i=null;let c=null;try{c=new n(t,s)}catch(e){return null}e.forEach(e=>{if(c.test(e)){if(!o||i.compare(e)===1){o=e;i=new r(o,s)}}});return o};e.exports=o},744:function(e,t,s){const r=s(65);const n=(e,t)=>new r(e,t).major;e.exports=n},752:function(e,t,s){const r=s(298);const n=s(873);const o=s(486);const i=s(167);const c=s(586);const a=s(898);const l=(e,t,s,l)=>{switch(t){case"===":if(typeof e==="object")e=e.version;if(typeof s==="object")s=s.version;return e===s;case"!==":if(typeof e==="object")e=e.version;if(typeof s==="object")s=s.version;return e!==s;case"":case"=":case"==":return r(e,s,l);case"!=":return n(e,s,l);case">":return o(e,s,l);case">=":return i(e,s,l);case"<":return c(e,s,l);case"<=":return a(e,s,l);default:throw new TypeError(`Invalid operator: ${t}`)}};e.exports=l},760:function(e){const t=/^[0-9]+$/;const s=(e,s)=>{const r=t.test(e);const n=t.test(s);if(r&&n){e=+e;s=+s}return e===s?0:r&&!n?-1:n&&!r?1:e<s?-1:1};const r=(e,t)=>s(t,e);e.exports={compareIdentifiers:s,rcompareIdentifiers:r}},803:function(e,t,s){const r=s(65);const n=(e,t)=>new r(e,t).minor;e.exports=n},811:function(e,t,s){const r=s(65);const n=s(124);const o=(e,t,s)=>{let o=null;let i=null;let c=null;try{c=new n(t,s)}catch(e){return null}e.forEach(e=>{if(c.test(e)){if(!o||i.compare(e)===-1){o=e;i=new r(o,s)}}});return o};e.exports=o},822:function(e,t,s){const r=s(830);const n=s(298);const o=(e,t)=>{if(n(e,t)){return null}else{const s=r(e);const n=r(t);const o=s.prerelease.length||n.prerelease.length;const i=o?"pre":"";const c=o?"prerelease":"";for(const e in s){if(e==="major"||e==="minor"||e==="patch"){if(s[e]!==n[e]){return i+e}}}return c}};e.exports=o},830:function(e,t,s){const{MAX_LENGTH:r}=s(181);const{re:n,t:o}=s(976);const i=s(65);const c=(e,t)=>{if(!t||typeof t!=="object"){t={loose:!!t,includePrerelease:false}}if(e instanceof i){return e}if(typeof e!=="string"){return null}if(e.length>r){return null}const s=t.loose?n[o.LOOSE]:n[o.FULL];if(!s.test(e)){return null}try{return new i(e,t)}catch(e){return null}};e.exports=c},873:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)!==0;e.exports=n},874:function(e,t,s){const r=s(65);const n=(e,t,s)=>new r(e,s).compare(new r(t,s));e.exports=n},876:function(e,t,s){const r=s(976);e.exports={re:r.re,src:r.src,tokens:r.t,SEMVER_SPEC_VERSION:s(181).SEMVER_SPEC_VERSION,SemVer:s(65),compareIdentifiers:s(760).compareIdentifiers,rcompareIdentifiers:s(760).rcompareIdentifiers,parse:s(830),valid:s(714),clean:s(503),inc:s(431),diff:s(822),major:s(744),minor:s(803),patch:s(489),prerelease:s(968),compare:s(874),rcompare:s(630),compareLoose:s(283),compareBuild:s(16),sort:s(120),rsort:s(593),gt:s(486),lt:s(586),eq:s(298),neq:s(873),gte:s(167),lte:s(898),cmp:s(752),coerce:s(499),Comparator:s(174),Range:s(124),satisfies:s(310),toComparators:s(219),maxSatisfying:s(811),minSatisfying:s(740),minVersion:s(164),validRange:s(480),outside:s(462),gtr:s(531),ltr:s(323),intersects:s(259),simplifyRange:s(877),subset:s(999)}},877:function(e,t,s){const r=s(310);const n=s(874);e.exports=((e,t,s)=>{const o=[];let i=null;let c=null;const a=e.sort((e,t)=>n(e,t,s));for(const e of a){const n=r(e,t,s);if(n){c=e;if(!i)i=e}else{if(c){o.push([i,c])}c=null;i=null}}if(i)o.push([i,null]);const l=[];for(const[e,t]of o){if(e===t)l.push(e);else if(!t&&e===a[0])l.push("*");else if(!t)l.push(`>=${e}`);else if(e===a[0])l.push(`<=${t}`);else l.push(`${e} - ${t}`)}const f=l.join(" || ");const u=typeof t.raw==="string"?t.raw:String(t);return f.length<u.length?f:t})},898:function(e,t,s){const r=s(874);const n=(e,t,s)=>r(e,t,s)<=0;e.exports=n},968:function(e,t,s){const r=s(830);const n=(e,t)=>{const s=r(e,t);return s&&s.prerelease.length?s.prerelease:null};e.exports=n},976:function(e,t,s){const{MAX_SAFE_COMPONENT_LENGTH:r}=s(181);const n=s(548);t=e.exports={};const o=t.re=[];const i=t.src=[];const c=t.t={};let a=0;const l=(e,t,s)=>{const r=a++;n(r,t);c[e]=r;i[r]=t;o[r]=new RegExp(t,s?"g":undefined)};l("NUMERICIDENTIFIER","0|[1-9]\\d*");l("NUMERICIDENTIFIERLOOSE","[0-9]+");l("NONNUMERICIDENTIFIER","\\d*[a-zA-Z-][a-zA-Z0-9-]*");l("MAINVERSION",`(${i[c.NUMERICIDENTIFIER]})\\.`+`(${i[c.NUMERICIDENTIFIER]})\\.`+`(${i[c.NUMERICIDENTIFIER]})`);l("MAINVERSIONLOOSE",`(${i[c.NUMERICIDENTIFIERLOOSE]})\\.`+`(${i[c.NUMERICIDENTIFIERLOOSE]})\\.`+`(${i[c.NUMERICIDENTIFIERLOOSE]})`);l("PRERELEASEIDENTIFIER",`(?:${i[c.NUMERICIDENTIFIER]}|${i[c.NONNUMERICIDENTIFIER]})`);l("PRERELEASEIDENTIFIERLOOSE",`(?:${i[c.NUMERICIDENTIFIERLOOSE]}|${i[c.NONNUMERICIDENTIFIER]})`);l("PRERELEASE",`(?:-(${i[c.PRERELEASEIDENTIFIER]}(?:\\.${i[c.PRERELEASEIDENTIFIER]})*))`);l("PRERELEASELOOSE",`(?:-?(${i[c.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${i[c.PRERELEASEIDENTIFIERLOOSE]})*))`);l("BUILDIDENTIFIER","[0-9A-Za-z-]+");l("BUILD",`(?:\\+(${i[c.BUILDIDENTIFIER]}(?:\\.${i[c.BUILDIDENTIFIER]})*))`);l("FULLPLAIN",`v?${i[c.MAINVERSION]}${i[c.PRERELEASE]}?${i[c.BUILD]}?`);l("FULL",`^${i[c.FULLPLAIN]}$`);l("LOOSEPLAIN",`[v=\\s]*${i[c.MAINVERSIONLOOSE]}${i[c.PRERELEASELOOSE]}?${i[c.BUILD]}?`);l("LOOSE",`^${i[c.LOOSEPLAIN]}$`);l("GTLT","((?:<|>)?=?)");l("XRANGEIDENTIFIERLOOSE",`${i[c.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);l("XRANGEIDENTIFIER",`${i[c.NUMERICIDENTIFIER]}|x|X|\\*`);l("XRANGEPLAIN",`[v=\\s]*(${i[c.XRANGEIDENTIFIER]})`+`(?:\\.(${i[c.XRANGEIDENTIFIER]})`+`(?:\\.(${i[c.XRANGEIDENTIFIER]})`+`(?:${i[c.PRERELEASE]})?${i[c.BUILD]}?`+`)?)?`);l("XRANGEPLAINLOOSE",`[v=\\s]*(${i[c.XRANGEIDENTIFIERLOOSE]})`+`(?:\\.(${i[c.XRANGEIDENTIFIERLOOSE]})`+`(?:\\.(${i[c.XRANGEIDENTIFIERLOOSE]})`+`(?:${i[c.PRERELEASELOOSE]})?${i[c.BUILD]}?`+`)?)?`);l("XRANGE",`^${i[c.GTLT]}\\s*${i[c.XRANGEPLAIN]}$`);l("XRANGELOOSE",`^${i[c.GTLT]}\\s*${i[c.XRANGEPLAINLOOSE]}$`);l("COERCE",`${"(^|[^\\d])"+"(\\d{1,"}${r}})`+`(?:\\.(\\d{1,${r}}))?`+`(?:\\.(\\d{1,${r}}))?`+`(?:$|[^\\d])`);l("COERCERTL",i[c.COERCE],true);l("LONETILDE","(?:~>?)");l("TILDETRIM",`(\\s*)${i[c.LONETILDE]}\\s+`,true);t.tildeTrimReplace="$1~";l("TILDE",`^${i[c.LONETILDE]}${i[c.XRANGEPLAIN]}$`);l("TILDELOOSE",`^${i[c.LONETILDE]}${i[c.XRANGEPLAINLOOSE]}$`);l("LONECARET","(?:\\^)");l("CARETTRIM",`(\\s*)${i[c.LONECARET]}\\s+`,true);t.caretTrimReplace="$1^";l("CARET",`^${i[c.LONECARET]}${i[c.XRANGEPLAIN]}$`);l("CARETLOOSE",`^${i[c.LONECARET]}${i[c.XRANGEPLAINLOOSE]}$`);l("COMPARATORLOOSE",`^${i[c.GTLT]}\\s*(${i[c.LOOSEPLAIN]})$|^$`);l("COMPARATOR",`^${i[c.GTLT]}\\s*(${i[c.FULLPLAIN]})$|^$`);l("COMPARATORTRIM",`(\\s*)${i[c.GTLT]}\\s*(${i[c.LOOSEPLAIN]}|${i[c.XRANGEPLAIN]})`,true);t.comparatorTrimReplace="$1$2$3";l("HYPHENRANGE",`^\\s*(${i[c.XRANGEPLAIN]})`+`\\s+-\\s+`+`(${i[c.XRANGEPLAIN]})`+`\\s*$`);l("HYPHENRANGELOOSE",`^\\s*(${i[c.XRANGEPLAINLOOSE]})`+`\\s+-\\s+`+`(${i[c.XRANGEPLAINLOOSE]})`+`\\s*$`);l("STAR","(<|>)?=?\\s*\\*");l("GTE0","^\\s*>=\\s*0.0.0\\s*$");l("GTE0PRE","^\\s*>=\\s*0.0.0-0\\s*$")},999:function(e,t,s){const r=s(124);const{ANY:n}=s(174);const o=s(310);const i=s(874);const c=(e,t,s)=>{e=new r(e,s);t=new r(t,s);let n=false;e:for(const r of e.set){for(const e of t.set){const t=a(r,e,s);n=n||t!==null;if(t)continue e}if(n)return false}return true};const a=(e,t,s)=>{if(e.length===1&&e[0].semver===n)return t.length===1&&t[0].semver===n;const r=new Set;let c,a;for(const t of e){if(t.operator===">"||t.operator===">=")c=l(c,t,s);else if(t.operator==="<"||t.operator==="<=")a=f(a,t,s);else r.add(t.semver)}if(r.size>1)return null;let u;if(c&&a){u=i(c.semver,a.semver,s);if(u>0)return null;else if(u===0&&(c.operator!==">="||a.operator!=="<="))return null}for(const e of r){if(c&&!o(e,String(c),s))return null;if(a&&!o(e,String(a),s))return null;for(const r of t){if(!o(e,String(r),s))return false}return true}let E,h;let $,I;for(const e of t){I=I||e.operator===">"||e.operator===">=";$=$||e.operator==="<"||e.operator==="<=";if(c){if(e.operator===">"||e.operator===">="){E=l(c,e,s);if(E===e)return false}else if(c.operator===">="&&!o(c.semver,String(e),s))return false}if(a){if(e.operator==="<"||e.operator==="<="){h=f(a,e,s);if(h===e)return false}else if(a.operator==="<="&&!o(a.semver,String(e),s))return false}if(!e.operator&&(a||c)&&u!==0)return false}if(c&&$&&!a&&u!==0)return false;if(a&&I&&!c&&u!==0)return false;return true};const l=(e,t,s)=>{if(!e)return t;const r=i(e.semver,t.semver,s);return r>0?e:r<0?t:t.operator===">"&&e.operator===">="?t:e};const f=(e,t,s)=>{if(!e)return t;const r=i(e.semver,t.semver,s);return r<0?e:r>0?t:t.operator==="<"&&e.operator==="<="?t:e};e.exports=c}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "4Njv":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    let escaped = '';

    for (let i = 0; i < input.length; ++i) {

        const charCode = input.charCodeAt(i);

        if (internals.isSafe(charCode)) {
            escaped += input[i];
        }
        else {
            escaped += internals.escapeHtmlChar(charCode);
        }
    }

    return escaped;
};


internals.escapeHtmlChar = function (charCode) {

    const namedEscape = internals.namedHtml[charCode];
    if (typeof namedEscape !== 'undefined') {
        return namedEscape;
    }

    if (charCode >= 256) {
        return '&#' + charCode + ';';
    }

    const hexValue = charCode.toString(16).padStart(2, '0');
    return `&#x${hexValue};`;
};


internals.isSafe = function (charCode) {

    return (typeof internals.safeCharCodes[charCode] !== 'undefined');
};


internals.namedHtml = {
    '38': '&amp;',
    '60': '&lt;',
    '62': '&gt;',
    '34': '&quot;',
    '160': '&nbsp;',
    '162': '&cent;',
    '163': '&pound;',
    '164': '&curren;',
    '169': '&copy;',
    '174': '&reg;'
};


internals.safeCharCodes = (function () {

    const safe = {};

    for (let i = 32; i < 123; ++i) {

        if ((i >= 97) ||                    // a-z
            (i >= 65 && i <= 90) ||         // A-Z
            (i >= 48 && i <= 57) ||         // 0-9
            i === 32 ||                     // space
            i === 46 ||                     // .
            i === 44 ||                     // ,
            i === 45 ||                     // -
            i === 58 ||                     // :
            i === 95) {                     // _

            safe[i] = null;
        }
    }

    return safe;
}());


/***/ }),

/***/ "4UWp":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const EventEmitter = __webpack_require__("/0p4");
const getStream = __webpack_require__("NFjz");
const is = __webpack_require__("6mOv");
const PCancelable = __webpack_require__("ijcl");
const requestAsEventEmitter = __webpack_require__("y/nk");
const {HTTPError, ParseError, ReadError} = __webpack_require__("9Fi5");
const {options: mergeOptions} = __webpack_require__("AW8e");
const {reNormalize} = __webpack_require__("whhB");

const asPromise = options => {
	const proxy = new EventEmitter();

	const promise = new PCancelable((resolve, reject, onCancel) => {
		const emitter = requestAsEventEmitter(options);

		onCancel(emitter.abort);

		emitter.on('response', async response => {
			proxy.emit('response', response);

			const stream = is.null(options.encoding) ? getStream.buffer(response) : getStream(response, options);

			let data;
			try {
				data = await stream;
			} catch (error) {
				reject(new ReadError(error, options));
				return;
			}

			const limitStatusCode = options.followRedirect ? 299 : 399;

			response.body = data;

			try {
				for (const [index, hook] of Object.entries(options.hooks.afterResponse)) {
					// eslint-disable-next-line no-await-in-loop
					response = await hook(response, updatedOptions => {
						updatedOptions = reNormalize(mergeOptions(options, {
							...updatedOptions,
							retry: 0,
							throwHttpErrors: false
						}));

						// Remove any further hooks for that request, because we we'll call them anyway.
						// The loop continues. We don't want duplicates (asPromise recursion).
						updatedOptions.hooks.afterResponse = options.hooks.afterResponse.slice(0, index);

						return asPromise(updatedOptions);
					});
				}
			} catch (error) {
				reject(error);
				return;
			}

			const {statusCode} = response;

			if (options.json && response.body) {
				try {
					response.body = JSON.parse(response.body);
				} catch (error) {
					if (statusCode >= 200 && statusCode < 300) {
						const parseError = new ParseError(error, statusCode, options, data);
						Object.defineProperty(parseError, 'response', {value: response});
						reject(parseError);
						return;
					}
				}
			}

			if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
				const error = new HTTPError(response, options);
				Object.defineProperty(error, 'response', {value: response});
				if (emitter.retry(error) === false) {
					if (options.throwHttpErrors) {
						reject(error);
						return;
					}

					resolve(response);
				}

				return;
			}

			resolve(response);
		});

		emitter.once('error', reject);
		[
			'request',
			'redirect',
			'uploadProgress',
			'downloadProgress'
		].forEach(event => emitter.on(event, (...args) => proxy.emit(event, ...args)));
	});

	promise.on = (name, fn) => {
		proxy.on(name, fn);
		return promise;
	};

	return promise;
};

module.exports = asPromise;


/***/ }),

/***/ "4mwe":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (array1, array2, options = {}) {

    if (!array1 ||
        !array2) {

        return (options.first ? null : []);
    }

    const common = [];
    const hash = (Array.isArray(array1) ? new Set(array1) : array1);
    const found = new Set();
    for (const value of array2) {
        if (internals.has(hash, value) &&
            !found.has(value)) {

            if (options.first) {
                return value;
            }

            common.push(value);
            found.add(value);
        }
    }

    return (options.first ? null : common);
};


internals.has = function (ref, key) {

    if (typeof ref.has === 'function') {
        return ref.has(key);
    }

    return ref[key] !== undefined;
};


/***/ }),

/***/ "5fWB":
/***/ (function(module, exports, __webpack_require__) {

const { createSign, createVerify } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const resolveNodeAlg = __webpack_require__("uGJc")
const { asInput } = __webpack_require__("1ALl")

const sign = (nodeAlg, { [KEYOBJECT]: keyObject }, payload) => {
  return createSign(nodeAlg).update(payload).sign(asInput(keyObject, false))
}

const verify = (nodeAlg, { [KEYOBJECT]: keyObject }, payload, signature) => {
  return createVerify(nodeAlg).update(payload).verify(asInput(keyObject, true), signature)
}

const LENGTHS = {
  RS256: 0,
  RS384: 624,
  RS512: 752
}

module.exports = (JWA, JWK) => {
  ['RS256', 'RS384', 'RS512'].forEach((jwaAlg) => {
    const nodeAlg = resolveNodeAlg(jwaAlg)
    JWA.sign.set(jwaAlg, sign.bind(undefined, nodeAlg))
    JWA.verify.set(jwaAlg, verify.bind(undefined, nodeAlg))
    JWK.RSA.sign[jwaAlg] = key => key.private && JWK.RSA.verify[jwaAlg](key)
    JWK.RSA.verify[jwaAlg] = key => (key.use === 'sig' || key.use === undefined) && key.length >= LENGTHS[jwaAlg]
  })
}


/***/ }),

/***/ "5j3D":
/***/ (function(module, exports) {

module.exports = (a) => !!a && a.constructor === Object;


/***/ }),

/***/ "5kZ8":
/***/ (function(module, exports, __webpack_require__) {

"use strict";



const internals = {
    suspectRx: /"(?:_|\\u005[Ff])(?:_|\\u005[Ff])(?:p|\\u0070)(?:r|\\u0072)(?:o|\\u006[Ff])(?:t|\\u0074)(?:o|\\u006[Ff])(?:_|\\u005[Ff])(?:_|\\u005[Ff])"\s*\:/
};


exports.parse = function (text, reviver, options) {

    // Normalize arguments

    if (!options) {
        if (reviver &&
            typeof reviver === 'object') {

            options = reviver;
            reviver = undefined;
        }
        else {
            options = {};
        }
    }

    // Parse normally, allowing exceptions

    const obj = JSON.parse(text, reviver);

    // options.protoAction: 'error' (default) / 'remove' / 'ignore'

    if (options.protoAction === 'ignore') {
        return obj;
    }

    // Ignore null and non-objects

    if (!obj ||
        typeof obj !== 'object') {

        return obj;
    }

    // Check original string for potential exploit

    if (!text.match(internals.suspectRx)) {
        return obj;
    }

    // Scan result for proto keys

    exports.scan(obj, options);

    return obj;
};


exports.scan = function (obj, options) {

    options = options || {};

    let next = [obj];

    while (next.length) {
        const nodes = next;
        next = [];

        for (const node of nodes) {
            if (Object.prototype.hasOwnProperty.call(node, '__proto__')) {      // Avoid calling node.hasOwnProperty directly
                if (options.protoAction !== 'remove') {
                    throw new SyntaxError('Object contains forbidden prototype property');
                }

                delete node.__proto__;
            }

            for (const key in node) {
                const value = node[key];
                if (value &&
                    typeof value === 'object') {

                    next.push(node[key]);
                }
            }
        }
    }
};


exports.safeParse = function (text, reviver) {

    try {
        return exports.parse(text, reviver);
    }
    catch (ignoreError) {
        return null;
    }
};


/***/ }),

/***/ "5sA0":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("2BAz");
const DeepEqual = __webpack_require__("bkX/");
const EscapeRegex = __webpack_require__("3AyT");
const Utils = __webpack_require__("3J/O");


const internals = {};


module.exports = function (ref, values, options = {}) {        // options: { deep, once, only, part, symbols }

    /*
        string -> string(s)
        array -> item(s)
        object -> key(s)
        object -> object (key:value)
    */

    if (typeof values !== 'object') {
        values = [values];
    }

    Assert(!Array.isArray(values) || values.length, 'Values array cannot be empty');

    // String

    if (typeof ref === 'string') {
        return internals.string(ref, values, options);
    }

    // Array

    if (Array.isArray(ref)) {
        return internals.array(ref, values, options);
    }

    // Object

    Assert(typeof ref === 'object', 'Reference must be string or an object');
    return internals.object(ref, values, options);
};


internals.array = function (ref, values, options) {

    if (!Array.isArray(values)) {
        values = [values];
    }

    if (!ref.length) {
        return false;
    }

    if (options.only &&
        options.once &&
        ref.length !== values.length) {

        return false;
    }

    let compare;

    // Map values

    const map = new Map();
    for (const value of values) {
        if (!options.deep ||
            !value ||
            typeof value !== 'object') {

            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
        else {
            compare = compare || internals.compare(options);

            let found = false;
            for (const [key, existing] of map.entries()) {
                if (compare(key, value)) {
                    ++existing.allowed;
                    found = true;
                    break;
                }
            }

            if (!found) {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
    }

    // Lookup values

    let hits = 0;
    for (const item of ref) {
        let match;
        if (!options.deep ||
            !item ||
            typeof item !== 'object') {

            match = map.get(item);
        }
        else {
            for (const [key, existing] of map.entries()) {
                if (compare(key, item)) {
                    match = existing;
                    break;
                }
            }
        }

        if (match) {
            ++match.hits;
            ++hits;

            if (options.once &&
                match.hits > match.allowed) {

                return false;
            }
        }
    }

    // Validate results

    if (options.only &&
        hits !== ref.length) {

        return false;
    }

    for (const match of map.values()) {
        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }
    }

    return !!hits;
};


internals.object = function (ref, values, options) {

    Assert(options.once === undefined, 'Cannot use option once with object');

    const keys = Utils.keys(ref, options);
    if (!keys.length) {
        return false;
    }

    // Keys list

    if (Array.isArray(values)) {
        return internals.array(keys, values, options);
    }

    // Key value pairs

    const symbols = Object.getOwnPropertySymbols(values).filter((sym) => values.propertyIsEnumerable(sym));
    const targets = [...Object.keys(values), ...symbols];

    const compare = internals.compare(options);
    const set = new Set(targets);

    for (const key of keys) {
        if (!set.has(key)) {
            if (options.only) {
                return false;
            }

            continue;
        }

        if (!compare(values[key], ref[key])) {
            return false;
        }

        set.delete(key);
    }

    if (set.size) {
        return options.part ? set.size < targets.length : false;
    }

    return true;
};


internals.string = function (ref, values, options) {

    // Empty string

    if (ref === '') {
        return values.length === 1 && values[0] === '' ||               // '' contains ''
            !options.once && !values.some((v) => v !== '');             // '' contains multiple '' if !once
    }

    // Map values

    const map = new Map();
    const patterns = [];

    for (const value of values) {
        Assert(typeof value === 'string', 'Cannot compare string reference to non-string value');

        if (value) {
            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
                patterns.push(EscapeRegex(value));
            }
        }
        else if (options.once ||
            options.only) {

            return false;
        }
    }

    if (!patterns.length) {                     // Non-empty string contains unlimited empty string
        return true;
    }

    // Match patterns

    const regex = new RegExp(`(${patterns.join('|')})`, 'g');
    const leftovers = ref.replace(regex, ($0, $1) => {

        ++map.get($1).hits;
        return '';                              // Remove from string
    });

    // Validate results

    if (options.only &&
        leftovers) {

        return false;
    }

    let any = false;
    for (const match of map.values()) {
        if (match.hits) {
            any = true;
        }

        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }

        // match.hits > match.allowed

        if (options.once) {
            return false;
        }
    }

    return !!any;
};


internals.compare = function (options) {

    if (!options.deep) {
        return internals.shallow;
    }

    const hasOnly = options.only !== undefined;
    const hasPart = options.part !== undefined;

    const flags = {
        prototype: hasOnly ? options.only : hasPart ? !options.part : false,
        part: hasOnly ? !options.only : hasPart ? options.part : false
    };

    return (a, b) => DeepEqual(a, b, flags);
};


internals.shallow = function (a, b) {

    return a === b;
};


/***/ }),

/***/ "5sMl":
/***/ (function(module, exports, __webpack_require__) {

const crypto = __webpack_require__("PJMN");

const [major, minor] = process.version.substr(1).split('.').map((x) => parseInt(x, 10));
const xofOutputLength = major > 12 || (major === 12 && minor >= 8);
const shake256 = xofOutputLength && crypto.getHashes().includes('shake256');

module.exports = shake256;


/***/ }),

/***/ "5sNo":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const state_1 = __webpack_require__("ND7K");
const cookies_1 = __webpack_require__("gKi1");
const session_1 = tslib_1.__importDefault(__webpack_require__("dKo8"));
function callbackHandler(settings, clientProvider, sessionStore) {
    return (req, res, options) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!res) {
            throw new Error('Response is not available');
        }
        if (!req) {
            throw new Error('Request is not available');
        }
        // Parse the cookies.
        const cookies = cookies_1.parseCookies(req);
        // Require that we have a state.
        const state = cookies['a0:state'];
        if (!state) {
            throw new Error('Invalid request, an initial state could not be found');
        }
        // Execute the code exchange
        const client = yield clientProvider();
        const params = client.callbackParams(req);
        const tokenSet = yield client.callback(settings.redirectUri, params, {
            state
        });
        const decodedState = state_1.decodeState(state);
        // Get the claims without any OIDC specific claim.
        let session = session_1.default(tokenSet);
        // Run the identity validated hook.
        if (options && options.onUserLoaded) {
            session = yield options.onUserLoaded(req, res, session, decodedState);
        }
        // Create the session.
        yield sessionStore.save(req, res, session);
        // Redirect to the homepage or custom url.
        const redirectTo = (options && options.redirectTo) || decodedState.redirectTo || '/';
        res.writeHead(302, {
            Location: redirectTo
        });
        res.end();
    });
}
exports.default = callbackHandler;
//# sourceMappingURL=callback.js.map

/***/ }),

/***/ "6D7l":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;
exports.formatUrl = formatUrl;

var querystring = _interopRequireWildcard(__webpack_require__("3WeD"));

function _getRequireWildcardCache() {
  if (typeof WeakMap !== "function") return null;
  var cache = new WeakMap();

  _getRequireWildcardCache = function () {
    return cache;
  };

  return cache;
}

function _interopRequireWildcard(obj) {
  if (obj && obj.__esModule) {
    return obj;
  }

  if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
    return {
      default: obj
    };
  }

  var cache = _getRequireWildcardCache();

  if (cache && cache.has(obj)) {
    return cache.get(obj);
  }

  var newObj = {};
  var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;

  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;

      if (desc && (desc.get || desc.set)) {
        Object.defineProperty(newObj, key, desc);
      } else {
        newObj[key] = obj[key];
      }
    }
  }

  newObj.default = obj;

  if (cache) {
    cache.set(obj, newObj);
  }

  return newObj;
} // Format function modified from nodejs
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.


const slashedProtocols = /https?|ftp|gopher|file/;

function formatUrl(urlObj) {
  let {
    auth,
    hostname
  } = urlObj;
  let protocol = urlObj.protocol || '';
  let pathname = urlObj.pathname || '';
  let hash = urlObj.hash || '';
  let query = urlObj.query || '';
  let host = false;
  auth = auth ? encodeURIComponent(auth).replace(/%3A/i, ':') + '@' : '';

  if (urlObj.host) {
    host = auth + urlObj.host;
  } else if (hostname) {
    host = auth + (~hostname.indexOf(':') ? `[${hostname}]` : hostname);

    if (urlObj.port) {
      host += ':' + urlObj.port;
    }
  }

  if (query && typeof query === 'object') {
    query = String(querystring.urlQueryToSearchParams(query));
  }

  let search = urlObj.search || query && `?${query}` || '';
  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  if (urlObj.slashes || (!protocol || slashedProtocols.test(protocol)) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname[0] !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash[0] !== '#') hash = '#' + hash;
  if (search && search[0] !== '?') search = '?' + search;
  pathname = pathname.replace(/[?#]/g, encodeURIComponent);
  search = search.replace('#', '%23');
  return `${protocol}${host}${pathname}${search}${hash}`;
}

/***/ }),

/***/ "6HRL":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("xG1e");
const Clone = __webpack_require__("E9YA");
const Utils = __webpack_require__("f/5Z");


const internals = {};


module.exports = internals.merge = function (target, source, options) {

    Assert(target && typeof target === 'object', 'Invalid target value: must be an object');
    Assert(source === null || source === undefined || typeof source === 'object', 'Invalid source value: must be null, undefined, or an object');

    if (!source) {
        return target;
    }

    options = Object.assign({ nullOverride: true, mergeArrays: true }, options);

    if (Array.isArray(source)) {
        Assert(Array.isArray(target), 'Cannot merge array onto an object');
        if (!options.mergeArrays) {
            target.length = 0;                                                          // Must not change target assignment
        }

        for (let i = 0; i < source.length; ++i) {
            target.push(Clone(source[i], { symbols: options.symbols }));
        }

        return target;
    }

    const keys = Utils.keys(source, options);
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (key === '__proto__' ||
            !Object.prototype.propertyIsEnumerable.call(source, key)) {

            continue;
        }

        const value = source[key];
        if (value &&
            typeof value === 'object') {

            if (!target[key] ||
                typeof target[key] !== 'object' ||
                (Array.isArray(target[key]) !== Array.isArray(value)) ||
                value instanceof Date ||
                (Buffer && Buffer.isBuffer(value)) ||               // $lab:coverage:ignore$
                value instanceof RegExp) {

                target[key] = Clone(value, { symbols: options.symbols });
            }
            else {
                internals.merge(target[key], value, options);
            }
        }
        else {
            if (value !== null &&
                value !== undefined) {                              // Explicit to preserve empty strings

                target[key] = value;
            }
            else if (options.nullOverride) {
                target[key] = value;
            }
        }
    }

    return target;
};


/***/ }),

/***/ "6I+L":
/***/ (function(module, exports, __webpack_require__) {

const isObject = __webpack_require__("kF1/")
const secs = __webpack_require__("o156")
const epoch = __webpack_require__("F4x3")
const getKey = __webpack_require__("oGTz")
const JWS = __webpack_require__("sR+5")

const isString = __webpack_require__("mRrf").isString.bind(undefined, TypeError)

const validateOptions = (options) => {
  if (typeof options.iat !== 'boolean') {
    throw new TypeError('options.iat must be a boolean')
  }

  if (typeof options.kid !== 'boolean') {
    throw new TypeError('options.kid must be a boolean')
  }

  isString(options.subject, 'options.subject')
  isString(options.issuer, 'options.issuer')

  if (
    options.audience !== undefined &&
    (
      (typeof options.audience !== 'string' || !options.audience) &&
      (!Array.isArray(options.audience) || options.audience.length === 0 || options.audience.some(a => !a || typeof a !== 'string'))
    )
  ) {
    throw new TypeError('options.audience must be a string or an array of strings')
  }

  if (!isObject(options.header)) {
    throw new TypeError('options.header must be an object')
  }

  isString(options.algorithm, 'options.algorithm')
  isString(options.expiresIn, 'options.expiresIn')
  isString(options.notBefore, 'options.notBefore')
  isString(options.jti, 'options.jti')
  isString(options.nonce, 'options.nonce')

  if (options.now !== undefined && (!(options.now instanceof Date) || !options.now.getTime())) {
    throw new TypeError('options.now must be a valid Date object')
  }
}

module.exports = (payload, key, options = {}) => {
  if (!isObject(options)) {
    throw new TypeError('options must be an object')
  }

  const {
    algorithm, audience, expiresIn, header = {}, iat = true,
    issuer, jti, kid = true, nonce, notBefore, subject, now
  } = options

  validateOptions({
    algorithm, audience, expiresIn, header, iat, issuer, jti, kid, nonce, notBefore, now, subject
  })

  if (!isObject(payload)) {
    throw new TypeError('payload must be an object')
  }

  let unix
  if (expiresIn || notBefore || iat) {
    unix = epoch(now || new Date())
  }

  payload = {
    ...payload,
    sub: subject || payload.sub,
    aud: audience || payload.aud,
    iss: issuer || payload.iss,
    jti: jti || payload.jti,
    iat: iat ? unix : payload.iat,
    nonce: nonce || payload.nonce,
    exp: expiresIn ? unix + secs(expiresIn) : payload.exp,
    nbf: notBefore ? unix + secs(notBefore) : payload.nbf
  }

  key = getKey(key)

  let includeKid

  if (typeof options.kid === 'boolean') {
    includeKid = kid
  } else {
    includeKid = !key.secret
  }

  return JWS.sign(JSON.stringify(payload), key, {
    ...header,
    alg: algorithm || header.alg,
    kid: includeKid ? key.kid : header.kid
  })
}


/***/ }),

/***/ "6gLP":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function createDummyBrowserInstance() {
    return {
        isBrowser: true,
        handleLogin: () => {
            throw new Error('The handleLogin method can only be used from the server side');
        },
        handleLogout: () => {
            throw new Error('The handleLogout method can only be used from the server side');
        },
        handleCallback: () => {
            throw new Error('The handleCallback method can only be used from the server side');
        },
        handleProfile: () => {
            throw new Error('The handleProfile method can only be used from the server side');
        },
        getSession: () => {
            throw new Error('The getSession method can only be used from the server side');
        },
        requireAuthentication: () => () => {
            throw new Error('The requireAuthentication method can only be used from the server side');
        },
        tokenCache: () => {
            throw new Error('The tokenCache method can only be used from the server side');
        }
    };
}
exports.default = createDummyBrowserInstance;
//# sourceMappingURL=instance.browser.js.map

/***/ }),

/***/ "6mOv":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/// <reference lib="es2016"/>
/// <reference lib="es2017.sharedmemory"/>
/// <reference lib="esnext.asynciterable"/>
/// <reference lib="dom"/>
Object.defineProperty(exports, "__esModule", { value: true });
// TODO: Use the `URL` global when targeting Node.js 10
// tslint:disable-next-line
const URLGlobal = typeof URL === 'undefined' ? __webpack_require__("bzos").URL : URL;
const toString = Object.prototype.toString;
const isOfType = (type) => (value) => typeof value === type;
const isBuffer = (input) => !is.nullOrUndefined(input) && !is.nullOrUndefined(input.constructor) && is.function_(input.constructor.isBuffer) && input.constructor.isBuffer(input);
const getObjectType = (value) => {
    const objectName = toString.call(value).slice(8, -1);
    if (objectName) {
        return objectName;
    }
    return null;
};
const isObjectOfType = (type) => (value) => getObjectType(value) === type;
function is(value) {
    switch (value) {
        case null:
            return "null" /* null */;
        case true:
        case false:
            return "boolean" /* boolean */;
        default:
    }
    switch (typeof value) {
        case 'undefined':
            return "undefined" /* undefined */;
        case 'string':
            return "string" /* string */;
        case 'number':
            return "number" /* number */;
        case 'symbol':
            return "symbol" /* symbol */;
        default:
    }
    if (is.function_(value)) {
        return "Function" /* Function */;
    }
    if (is.observable(value)) {
        return "Observable" /* Observable */;
    }
    if (Array.isArray(value)) {
        return "Array" /* Array */;
    }
    if (isBuffer(value)) {
        return "Buffer" /* Buffer */;
    }
    const tagType = getObjectType(value);
    if (tagType) {
        return tagType;
    }
    if (value instanceof String || value instanceof Boolean || value instanceof Number) {
        throw new TypeError('Please don\'t use object wrappers for primitive types');
    }
    return "Object" /* Object */;
}
(function (is) {
    // tslint:disable-next-line:strict-type-predicates
    const isObject = (value) => typeof value === 'object';
    // tslint:disable:variable-name
    is.undefined = isOfType('undefined');
    is.string = isOfType('string');
    is.number = isOfType('number');
    is.function_ = isOfType('function');
    // tslint:disable-next-line:strict-type-predicates
    is.null_ = (value) => value === null;
    is.class_ = (value) => is.function_(value) && value.toString().startsWith('class ');
    is.boolean = (value) => value === true || value === false;
    is.symbol = isOfType('symbol');
    // tslint:enable:variable-name
    is.numericString = (value) => is.string(value) && value.length > 0 && !Number.isNaN(Number(value));
    is.array = Array.isArray;
    is.buffer = isBuffer;
    is.nullOrUndefined = (value) => is.null_(value) || is.undefined(value);
    is.object = (value) => !is.nullOrUndefined(value) && (is.function_(value) || isObject(value));
    is.iterable = (value) => !is.nullOrUndefined(value) && is.function_(value[Symbol.iterator]);
    is.asyncIterable = (value) => !is.nullOrUndefined(value) && is.function_(value[Symbol.asyncIterator]);
    is.generator = (value) => is.iterable(value) && is.function_(value.next) && is.function_(value.throw);
    is.nativePromise = (value) => isObjectOfType("Promise" /* Promise */)(value);
    const hasPromiseAPI = (value) => !is.null_(value) &&
        isObject(value) &&
        is.function_(value.then) &&
        is.function_(value.catch);
    is.promise = (value) => is.nativePromise(value) || hasPromiseAPI(value);
    is.generatorFunction = isObjectOfType("GeneratorFunction" /* GeneratorFunction */);
    is.asyncFunction = isObjectOfType("AsyncFunction" /* AsyncFunction */);
    is.boundFunction = (value) => is.function_(value) && !value.hasOwnProperty('prototype');
    is.regExp = isObjectOfType("RegExp" /* RegExp */);
    is.date = isObjectOfType("Date" /* Date */);
    is.error = isObjectOfType("Error" /* Error */);
    is.map = (value) => isObjectOfType("Map" /* Map */)(value);
    is.set = (value) => isObjectOfType("Set" /* Set */)(value);
    is.weakMap = (value) => isObjectOfType("WeakMap" /* WeakMap */)(value);
    is.weakSet = (value) => isObjectOfType("WeakSet" /* WeakSet */)(value);
    is.int8Array = isObjectOfType("Int8Array" /* Int8Array */);
    is.uint8Array = isObjectOfType("Uint8Array" /* Uint8Array */);
    is.uint8ClampedArray = isObjectOfType("Uint8ClampedArray" /* Uint8ClampedArray */);
    is.int16Array = isObjectOfType("Int16Array" /* Int16Array */);
    is.uint16Array = isObjectOfType("Uint16Array" /* Uint16Array */);
    is.int32Array = isObjectOfType("Int32Array" /* Int32Array */);
    is.uint32Array = isObjectOfType("Uint32Array" /* Uint32Array */);
    is.float32Array = isObjectOfType("Float32Array" /* Float32Array */);
    is.float64Array = isObjectOfType("Float64Array" /* Float64Array */);
    is.arrayBuffer = isObjectOfType("ArrayBuffer" /* ArrayBuffer */);
    is.sharedArrayBuffer = isObjectOfType("SharedArrayBuffer" /* SharedArrayBuffer */);
    is.dataView = isObjectOfType("DataView" /* DataView */);
    is.directInstanceOf = (instance, klass) => Object.getPrototypeOf(instance) === klass.prototype;
    is.urlInstance = (value) => isObjectOfType("URL" /* URL */)(value);
    is.urlString = (value) => {
        if (!is.string(value)) {
            return false;
        }
        try {
            new URLGlobal(value); // tslint:disable-line no-unused-expression
            return true;
        }
        catch (_a) {
            return false;
        }
    };
    is.truthy = (value) => Boolean(value);
    is.falsy = (value) => !value;
    is.nan = (value) => Number.isNaN(value);
    const primitiveTypes = new Set([
        'undefined',
        'string',
        'number',
        'boolean',
        'symbol'
    ]);
    is.primitive = (value) => is.null_(value) || primitiveTypes.has(typeof value);
    is.integer = (value) => Number.isInteger(value);
    is.safeInteger = (value) => Number.isSafeInteger(value);
    is.plainObject = (value) => {
        // From: https://github.com/sindresorhus/is-plain-obj/blob/master/index.js
        let prototype;
        return getObjectType(value) === "Object" /* Object */ &&
            (prototype = Object.getPrototypeOf(value), prototype === null || // tslint:disable-line:ban-comma-operator
                prototype === Object.getPrototypeOf({}));
    };
    const typedArrayTypes = new Set([
        "Int8Array" /* Int8Array */,
        "Uint8Array" /* Uint8Array */,
        "Uint8ClampedArray" /* Uint8ClampedArray */,
        "Int16Array" /* Int16Array */,
        "Uint16Array" /* Uint16Array */,
        "Int32Array" /* Int32Array */,
        "Uint32Array" /* Uint32Array */,
        "Float32Array" /* Float32Array */,
        "Float64Array" /* Float64Array */
    ]);
    is.typedArray = (value) => {
        const objectType = getObjectType(value);
        if (objectType === null) {
            return false;
        }
        return typedArrayTypes.has(objectType);
    };
    const isValidLength = (value) => is.safeInteger(value) && value > -1;
    is.arrayLike = (value) => !is.nullOrUndefined(value) && !is.function_(value) && isValidLength(value.length);
    is.inRange = (value, range) => {
        if (is.number(range)) {
            return value >= Math.min(0, range) && value <= Math.max(range, 0);
        }
        if (is.array(range) && range.length === 2) {
            return value >= Math.min(...range) && value <= Math.max(...range);
        }
        throw new TypeError(`Invalid range: ${JSON.stringify(range)}`);
    };
    const NODE_TYPE_ELEMENT = 1;
    const DOM_PROPERTIES_TO_CHECK = [
        'innerHTML',
        'ownerDocument',
        'style',
        'attributes',
        'nodeValue'
    ];
    is.domElement = (value) => is.object(value) && value.nodeType === NODE_TYPE_ELEMENT && is.string(value.nodeName) &&
        !is.plainObject(value) && DOM_PROPERTIES_TO_CHECK.every(property => property in value);
    is.observable = (value) => {
        if (!value) {
            return false;
        }
        if (value[Symbol.observable] && value === value[Symbol.observable]()) {
            return true;
        }
        if (value['@@observable'] && value === value['@@observable']()) {
            return true;
        }
        return false;
    };
    is.nodeStream = (value) => !is.nullOrUndefined(value) && isObject(value) && is.function_(value.pipe) && !is.observable(value);
    is.infinite = (value) => value === Infinity || value === -Infinity;
    const isAbsoluteMod2 = (rem) => (value) => is.integer(value) && Math.abs(value % 2) === rem;
    is.even = isAbsoluteMod2(0);
    is.odd = isAbsoluteMod2(1);
    const isWhiteSpaceString = (value) => is.string(value) && /\S/.test(value) === false;
    is.emptyArray = (value) => is.array(value) && value.length === 0;
    is.nonEmptyArray = (value) => is.array(value) && value.length > 0;
    is.emptyString = (value) => is.string(value) && value.length === 0;
    is.nonEmptyString = (value) => is.string(value) && value.length > 0;
    is.emptyStringOrWhitespace = (value) => is.emptyString(value) || isWhiteSpaceString(value);
    is.emptyObject = (value) => is.object(value) && !is.map(value) && !is.set(value) && Object.keys(value).length === 0;
    is.nonEmptyObject = (value) => is.object(value) && !is.map(value) && !is.set(value) && Object.keys(value).length > 0;
    is.emptySet = (value) => is.set(value) && value.size === 0;
    is.nonEmptySet = (value) => is.set(value) && value.size > 0;
    is.emptyMap = (value) => is.map(value) && value.size === 0;
    is.nonEmptyMap = (value) => is.map(value) && value.size > 0;
    const predicateOnArray = (method, predicate, values) => {
        if (is.function_(predicate) === false) {
            throw new TypeError(`Invalid predicate: ${JSON.stringify(predicate)}`);
        }
        if (values.length === 0) {
            throw new TypeError('Invalid number of values');
        }
        return method.call(values, predicate);
    };
    // tslint:disable variable-name
    is.any = (predicate, ...values) => predicateOnArray(Array.prototype.some, predicate, values);
    is.all = (predicate, ...values) => predicateOnArray(Array.prototype.every, predicate, values);
    // tslint:enable variable-name
})(is || (is = {}));
// Some few keywords are reserved, but we'll populate them for Node.js users
// See https://github.com/Microsoft/TypeScript/issues/2536
Object.defineProperties(is, {
    class: {
        value: is.class_
    },
    function: {
        value: is.function_
    },
    null: {
        value: is.null_
    }
});
exports.default = is;
// For CommonJS default export support
module.exports = is;
module.exports.default = is;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "6mnf":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

exports.__esModule = true;
exports.default = prepareDestination;

var _querystring = __webpack_require__("3WeD");

var _parseRelativeUrl = __webpack_require__("hS4m");

var pathToRegexp = _interopRequireWildcard(__webpack_require__("zOyy"));

function _getRequireWildcardCache() {
  if (typeof WeakMap !== "function") return null;
  var cache = new WeakMap();

  _getRequireWildcardCache = function () {
    return cache;
  };

  return cache;
}

function _interopRequireWildcard(obj) {
  if (obj && obj.__esModule) {
    return obj;
  }

  if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
    return {
      default: obj
    };
  }

  var cache = _getRequireWildcardCache();

  if (cache && cache.has(obj)) {
    return cache.get(obj);
  }

  var newObj = {};
  var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;

  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;

      if (desc && (desc.get || desc.set)) {
        Object.defineProperty(newObj, key, desc);
      } else {
        newObj[key] = obj[key];
      }
    }
  }

  newObj.default = obj;

  if (cache) {
    cache.set(obj, newObj);
  }

  return newObj;
}

function prepareDestination(destination, params, query, appendParamsToQuery, basePath) {
  let parsedDestination = {};

  if (destination.startsWith('/')) {
    parsedDestination = (0, _parseRelativeUrl.parseRelativeUrl)(destination);
  } else {
    const {
      pathname,
      searchParams,
      hash,
      hostname,
      port,
      protocol,
      search,
      href
    } = new URL(destination);
    parsedDestination = {
      pathname,
      query: (0, _querystring.searchParamsToUrlQuery)(searchParams),
      hash,
      protocol,
      hostname,
      port,
      search,
      href
    };
  }

  const destQuery = parsedDestination.query;
  const destPath = `${parsedDestination.pathname}${parsedDestination.hash || ''}`;
  const destPathParamKeys = [];
  pathToRegexp.pathToRegexp(destPath, destPathParamKeys);
  const destPathParams = destPathParamKeys.map(key => key.name);
  let destinationCompiler = pathToRegexp.compile(destPath, // we don't validate while compiling the destination since we should
  // have already validated before we got to this point and validating
  // breaks compiling destinations with named pattern params from the source
  // e.g. /something:hello(.*) -> /another/:hello is broken with validation
  // since compile validation is meant for reversing and not for inserting
  // params from a separate path-regex into another
  {
    validate: false
  });
  let newUrl; // update any params in query values

  for (const [key, strOrArray] of Object.entries(destQuery)) {
    let value = Array.isArray(strOrArray) ? strOrArray[0] : strOrArray;

    if (value) {
      // the value needs to start with a forward-slash to be compiled
      // correctly
      value = `/${value}`;
      const queryCompiler = pathToRegexp.compile(value, {
        validate: false
      });
      value = queryCompiler(params).substr(1);
    }

    destQuery[key] = value;
  } // add path params to query if it's not a redirect and not
  // already defined in destination query or path


  const paramKeys = Object.keys(params);

  if (appendParamsToQuery && !paramKeys.some(key => destPathParams.includes(key))) {
    for (const key of paramKeys) {
      if (!(key in destQuery)) {
        destQuery[key] = params[key];
      }
    }
  }

  const shouldAddBasePath = destination.startsWith('/') && basePath;

  try {
    newUrl = `${shouldAddBasePath ? basePath : ''}${destinationCompiler(params)}`;
    const [pathname, hash] = newUrl.split('#');
    parsedDestination.pathname = pathname;
    parsedDestination.hash = `${hash ? '#' : ''}${hash || ''}`;
    delete parsedDestination.search;
  } catch (err) {
    if (err.message.match(/Expected .*? to not repeat, but got an array/)) {
      throw new Error(`To use a multi-match in the destination you must add \`*\` at the end of the param name to signify it should repeat. https://err.sh/vercel/next.js/invalid-multi-match`);
    }

    throw err;
  } // Query merge order lowest priority to highest
  // 1. initial URL query values
  // 2. path segment values
  // 3. destination specified query values


  parsedDestination.query = _objectSpread(_objectSpread({}, query), parsedDestination.query);
  return {
    newUrl,
    parsedDestination
  };
}

/***/ }),

/***/ "6nrT":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Ignore = __webpack_require__("NqRk");


const internals = {};


module.exports = function () {

    return new Promise(Ignore);         // $lab:coverage:ignore$
};


/***/ }),

/***/ "7WL4":
/***/ (function(module, exports) {

module.exports = require("https");

/***/ }),

/***/ "7kea":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (promise) {

    return !!promise && typeof promise.then === 'function';
};


/***/ }),

/***/ "7o4N":
/***/ (function(module, exports, __webpack_require__) {

const base64url = __webpack_require__("Xab3")
const errors = __webpack_require__("yt7c")

module.exports = (token, { complete = false } = {}) => {
  if (typeof token !== 'string' || !token) {
    throw new TypeError('JWT must be a string')
  }

  const { 0: header, 1: payload, 2: signature, length } = token.split('.')

  if (length === 5) {
    throw new TypeError('JWTs must be decrypted first')
  }

  if (length !== 3) {
    throw new errors.JWTMalformed('JWTs must have three components')
  }

  try {
    const result = {
      header: base64url.JSON.decode(header),
      payload: base64url.JSON.decode(payload),
      signature
    }

    return complete ? result : result.payload
  } catch (err) {
    throw new errors.JWTMalformed('JWT is malformed')
  }
}


/***/ }),

/***/ "8AeH":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("2BAz");
const Clone = __webpack_require__("JT7C");
const Utils = __webpack_require__("3J/O");


const internals = {};


module.exports = internals.merge = function (target, source, options) {

    Assert(target && typeof target === 'object', 'Invalid target value: must be an object');
    Assert(source === null || source === undefined || typeof source === 'object', 'Invalid source value: must be null, undefined, or an object');

    if (!source) {
        return target;
    }

    options = Object.assign({ nullOverride: true, mergeArrays: true }, options);

    if (Array.isArray(source)) {
        Assert(Array.isArray(target), 'Cannot merge array onto an object');
        if (!options.mergeArrays) {
            target.length = 0;                                                          // Must not change target assignment
        }

        for (let i = 0; i < source.length; ++i) {
            target.push(Clone(source[i], { symbols: options.symbols }));
        }

        return target;
    }

    const keys = Utils.keys(source, options);
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (key === '__proto__' ||
            !Object.prototype.propertyIsEnumerable.call(source, key)) {

            continue;
        }

        const value = source[key];
        if (value &&
            typeof value === 'object') {

            if (!target[key] ||
                typeof target[key] !== 'object' ||
                (Array.isArray(target[key]) !== Array.isArray(value)) ||
                value instanceof Date ||
                (Buffer && Buffer.isBuffer(value)) ||               // $lab:coverage:ignore$
                value instanceof RegExp) {

                target[key] = Clone(value, { symbols: options.symbols });
            }
            else {
                internals.merge(target[key], value, options);
            }
        }
        else {
            if (value !== null &&
                value !== undefined) {                              // Explicit to preserve empty strings

                target[key] = value;
            }
            else if (options.nullOverride) {
                target[key] = value;
            }
        }
    }

    return target;
};


/***/ }),

/***/ "8g7u":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


exports = module.exports = {
    array: Array.prototype,
    buffer: Buffer && Buffer.prototype,             // $lab:coverage:ignore$
    date: Date.prototype,
    error: Error.prototype,
    generic: Object.prototype,
    map: Map.prototype,
    promise: Promise.prototype,
    regex: RegExp.prototype,
    set: Set.prototype,
    weakMap: WeakMap.prototype,
    weakSet: WeakSet.prototype
};


internals.typeMap = new Map([
    ['[object Error]', exports.error],
    ['[object Map]', exports.map],
    ['[object Promise]', exports.promise],
    ['[object Set]', exports.set],
    ['[object WeakMap]', exports.weakMap],
    ['[object WeakSet]', exports.weakSet]
]);


exports.getInternalProto = function (obj) {

    if (Array.isArray(obj)) {
        return exports.array;
    }

    if (Buffer && obj instanceof Buffer) {          // $lab:coverage:ignore$
        return exports.buffer;
    }

    if (obj instanceof Date) {
        return exports.date;
    }

    if (obj instanceof RegExp) {
        return exports.regex;
    }

    if (obj instanceof Error) {
        return exports.error;
    }

    const objName = Object.prototype.toString.call(obj);
    return internals.typeMap.get(objName) || exports.generic;
};


/***/ }),

/***/ "8qAF":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (promise) {

    return !!promise && typeof promise.then === 'function';
};


/***/ }),

/***/ "8xkj":
/***/ (function(module, exports) {

module.exports = require("querystring");

/***/ }),

/***/ "9AeD":
/***/ (function(module, exports, __webpack_require__) {

const Encrypt = __webpack_require__("/hdj")
const decrypt = __webpack_require__("33Iv")

// TODO: in v2.x swap unprotectedHeader and aad
const single = (serialization, cleartext, key, protectedHeader, unprotectedHeader, aad) => {
  return new Encrypt(cleartext, protectedHeader, unprotectedHeader, aad)
    .recipient(key)
    .encrypt(serialization)
}

module.exports.Encrypt = Encrypt
module.exports.encrypt = single.bind(undefined, 'compact')
module.exports.encrypt.flattened = single.bind(undefined, 'flattened')
module.exports.encrypt.general = single.bind(undefined, 'general')

module.exports.decrypt = decrypt


/***/ }),

/***/ "9Fi5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const urlLib = __webpack_require__("bzos");
const http = __webpack_require__("KEll");
const PCancelable = __webpack_require__("ijcl");
const is = __webpack_require__("6mOv");

class GotError extends Error {
	constructor(message, error, options) {
		super(message);
		Error.captureStackTrace(this, this.constructor);
		this.name = 'GotError';

		if (!is.undefined(error.code)) {
			this.code = error.code;
		}

		Object.assign(this, {
			host: options.host,
			hostname: options.hostname,
			method: options.method,
			path: options.path,
			socketPath: options.socketPath,
			protocol: options.protocol,
			url: options.href,
			gotOptions: options
		});
	}
}

module.exports.GotError = GotError;

module.exports.CacheError = class extends GotError {
	constructor(error, options) {
		super(error.message, error, options);
		this.name = 'CacheError';
	}
};

module.exports.RequestError = class extends GotError {
	constructor(error, options) {
		super(error.message, error, options);
		this.name = 'RequestError';
	}
};

module.exports.ReadError = class extends GotError {
	constructor(error, options) {
		super(error.message, error, options);
		this.name = 'ReadError';
	}
};

module.exports.ParseError = class extends GotError {
	constructor(error, statusCode, options, data) {
		super(`${error.message} in "${urlLib.format(options)}": \n${data.slice(0, 77)}...`, error, options);
		this.name = 'ParseError';
		this.statusCode = statusCode;
		this.statusMessage = http.STATUS_CODES[this.statusCode];
	}
};

module.exports.HTTPError = class extends GotError {
	constructor(response, options) {
		const {statusCode} = response;
		let {statusMessage} = response;

		if (statusMessage) {
			statusMessage = statusMessage.replace(/\r?\n/g, ' ').trim();
		} else {
			statusMessage = http.STATUS_CODES[statusCode];
		}

		super(`Response code ${statusCode} (${statusMessage})`, {}, options);
		this.name = 'HTTPError';
		this.statusCode = statusCode;
		this.statusMessage = statusMessage;
		this.headers = response.headers;
		this.body = response.body;
	}
};

module.exports.MaxRedirectsError = class extends GotError {
	constructor(statusCode, redirectUrls, options) {
		super('Redirected 10 times. Aborting.', {}, options);
		this.name = 'MaxRedirectsError';
		this.statusCode = statusCode;
		this.statusMessage = http.STATUS_CODES[this.statusCode];
		this.redirectUrls = redirectUrls;
	}
};

module.exports.UnsupportedProtocolError = class extends GotError {
	constructor(options) {
		super(`Unsupported protocol "${options.protocol}"`, {}, options);
		this.name = 'UnsupportedProtocolError';
	}
};

module.exports.TimeoutError = class extends GotError {
	constructor(error, options) {
		super(error.message, {code: 'ETIMEDOUT'}, options);
		this.name = 'TimeoutError';
		this.event = error.event;
	}
};

module.exports.CancelError = PCancelable.CancelError;


/***/ }),

/***/ "9YuQ":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
function requireAuthentication(sessionStore) {
    return (apiRoute) => (req, res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        const session = yield sessionStore.read(req);
        if (!session || !session.user) {
            res.status(401).json({
                error: 'not_authenticated',
                description: 'The user does not have an active session or is not authenticated'
            });
            return;
        }
        yield apiRoute(req, res);
    });
}
exports.default = requireAuthentication;
//# sourceMappingURL=require-authentication.js.map

/***/ }),

/***/ "9l6Z":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const url = __webpack_require__("bzos");
const prependHttp = __webpack_require__("mXTs");

module.exports = (input, options) => {
	if (typeof input !== 'string') {
		throw new TypeError(`Expected \`url\` to be of type \`string\`, got \`${typeof input}\` instead.`);
	}

	const finalUrl = prependHttp(input, Object.assign({https: true}, options));
	return url.parse(finalUrl);
};


/***/ }),

/***/ "9ny7":
/***/ (function(module, exports, __webpack_require__) {

const { define } = __webpack_require__("jUDV")
const base = __webpack_require__("VZIC")
const constants = __webpack_require__("h+i2")
const decoders = __webpack_require__("zspo")
const encoders = __webpack_require__("E8LI")

module.exports = {
  base,
  constants,
  decoders,
  define,
  encoders
}


/***/ }),

/***/ "9qEa":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    let escaped = '';

    for (let i = 0; i < input.length; ++i) {

        const charCode = input.charCodeAt(i);

        if (internals.isSafe(charCode)) {
            escaped += input[i];
        }
        else {
            escaped += internals.escapeHtmlChar(charCode);
        }
    }

    return escaped;
};


internals.escapeHtmlChar = function (charCode) {

    const namedEscape = internals.namedHtml[charCode];
    if (typeof namedEscape !== 'undefined') {
        return namedEscape;
    }

    if (charCode >= 256) {
        return '&#' + charCode + ';';
    }

    const hexValue = charCode.toString(16).padStart(2, '0');
    return `&#x${hexValue};`;
};


internals.isSafe = function (charCode) {

    return (typeof internals.safeCharCodes[charCode] !== 'undefined');
};


internals.namedHtml = {
    '38': '&amp;',
    '60': '&lt;',
    '62': '&gt;',
    '34': '&quot;',
    '160': '&nbsp;',
    '162': '&cent;',
    '163': '&pound;',
    '164': '&curren;',
    '169': '&copy;',
    '174': '&reg;'
};


internals.safeCharCodes = (function () {

    const safe = {};

    for (let i = 32; i < 123; ++i) {

        if ((i >= 97) ||                    // a-z
            (i >= 65 && i <= 90) ||         // A-Z
            (i >= 48 && i <= 57) ||         // 0-9
            i === 32 ||                     // space
            i === 46 ||                     // .
            i === 44 ||                     // ,
            i === 45 ||                     // -
            i === 58 ||                     // :
            i === 95) {                     // _

            safe[i] = null;
        }
    }

    return safe;
}());


/***/ }),

/***/ "9rVn":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const os = __webpack_require__("jle/");

const extractPathRegex = /\s+at.*(?:\(|\s)(.*)\)?/;
const pathRegex = /^(?:(?:(?:node|(?:internal\/[\w/]*|.*node_modules\/(?:babel-polyfill|pirates)\/.*)?\w+)\.js:\d+:\d+)|native)/;
const homeDir = typeof os.homedir === 'undefined' ? '' : os.homedir();

module.exports = (stack, options) => {
	options = Object.assign({pretty: false}, options);

	return stack.replace(/\\/g, '/')
		.split('\n')
		.filter(line => {
			const pathMatches = line.match(extractPathRegex);
			if (pathMatches === null || !pathMatches[1]) {
				return true;
			}

			const match = pathMatches[1];

			// Electron
			if (
				match.includes('.app/Contents/Resources/electron.asar') ||
				match.includes('.app/Contents/Resources/default_app.asar')
			) {
				return false;
			}

			return !pathRegex.test(match);
		})
		.filter(line => line.trim() !== '')
		.map(line => {
			if (options.pretty) {
				return line.replace(extractPathRegex, (m, p1) => m.replace(p1, p1.replace(homeDir, '~')));
			}

			return line;
		})
		.join('\n');
};


/***/ }),

/***/ "A4T3":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function() { return login; });
/* harmony import */ var _config_auth0__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("XUic");

async function login(req, res) {
  try {
    await _config_auth0__WEBPACK_IMPORTED_MODULE_0__[/* default */ "a"].handleLogin(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 400).end(error.message);
  }
}

/***/ }),

/***/ "A93I":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable max-classes-per-file */

const { inspect, deprecate } = __webpack_require__("jK02");
const url = __webpack_require__("bzos");

const jose = __webpack_require__("xZSz");
const pAny = __webpack_require__("lN8I");
const LRU = __webpack_require__("HyWp");
const objectHash = __webpack_require__("RIp3");

const { RPError } = __webpack_require__("L71r");
const getClient = __webpack_require__("HrFp");
const registry = __webpack_require__("0Aai");
const processResponse = __webpack_require__("WeJA");
const webfingerNormalize = __webpack_require__("HpSD");
const instance = __webpack_require__("0pkK");
const request = __webpack_require__("UwMm");
const { assertIssuerConfiguration } = __webpack_require__("N+si");
const {
  ISSUER_DEFAULTS, OIDC_DISCOVERY, OAUTH2_DISCOVERY, WEBFINGER, REL, AAD_MULTITENANT_DISCOVERY,
} = __webpack_require__("TJm8");

const AAD_MULTITENANT = Symbol('AAD_MULTITENANT');

class Issuer {
  /**
   * @name constructor
   * @api public
   */
  constructor(meta = {}) {
    const aadIssValidation = meta[AAD_MULTITENANT];
    delete meta[AAD_MULTITENANT];

    ['introspection', 'revocation'].forEach((endpoint) => {
      // if intro/revocation endpoint auth specific meta is missing use the token ones if they
      // are defined
      if (
        meta[`${endpoint}_endpoint`]
        && meta[`${endpoint}_endpoint_auth_methods_supported`] === undefined
        && meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] === undefined
      ) {
        if (meta.token_endpoint_auth_methods_supported) {
          meta[`${endpoint}_endpoint_auth_methods_supported`] = meta.token_endpoint_auth_methods_supported;
        }
        if (meta.token_endpoint_auth_signing_alg_values_supported) {
          meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] = meta.token_endpoint_auth_signing_alg_values_supported;
        }
      }
    });

    Object.entries(meta).forEach(([key, value]) => {
      instance(this).get('metadata').set(key, value);
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() { return instance(this).get('metadata').get(key); },
          enumerable: true,
        });
      }
    });

    instance(this).set('cache', new LRU({ max: 100 }));

    registry.set(this.issuer, this);

    Object.defineProperty(this, 'Client', {
      value: getClient(this, aadIssValidation),
    });

    Object.defineProperty(this, 'FAPIClient', {
      value: class FAPIClient extends this.Client {},
    });
  }

  /**
   * @name keystore
   * @api public
   */
  async keystore(reload = false) {
    assertIssuerConfiguration(this, 'jwks_uri');

    const keystore = instance(this).get('keystore');
    const cache = instance(this).get('cache');

    if (reload || !keystore) {
      cache.reset();
      const response = await request.call(this, {
        method: 'GET',
        json: true,
        url: this.jwks_uri,
      });
      const jwks = processResponse(response);

      const joseKeyStore = jose.JWKS.asKeyStore(jwks, { ignoreErrors: true });
      cache.set('throttle', true, 60 * 1000);
      instance(this).set('keystore', joseKeyStore);
      return joseKeyStore;
    }

    return keystore;
  }

  /**
   * @name queryKeyStore
   * @api private
   */
  async queryKeyStore({
    kid, kty, alg, use, key_ops: ops,
  }, { allowMulti = false } = {}) {
    const cache = instance(this).get('cache');

    const def = {
      kid, kty, alg, use, key_ops: ops,
    };

    const defHash = objectHash(def, {
      algorithm: 'sha256',
      ignoreUnknown: true,
      unorderedArrays: true,
      unorderedSets: true,
    });

    // refresh keystore on every unknown key but also only upto once every minute
    const freshJwksUri = cache.get(defHash) || cache.get('throttle');

    const keystore = await this.keystore(!freshJwksUri);
    const keys = keystore.all(def);

    if (keys.length === 0) {
      throw new RPError({
        printf: ["no valid key found in issuer's jwks_uri for key parameters %j", def],
        jwks: keystore,
      });
    }

    if (!allowMulti && keys.length > 1 && !kid) {
      throw new RPError({
        printf: ["multiple matching keys found in issuer's jwks_uri for key parameters %j, kid must be provided in this case", def],
        jwks: keystore,
      });
    }

    cache.set(defHash, true);

    return new jose.JWKS.KeyStore(keys);
  }

  /**
   * @name metadata
   * @api public
   */
  get metadata() {
    const copy = {};
    instance(this).get('metadata').forEach((value, key) => {
      copy[key] = value;
    });
    return copy;
  }

  /**
   * @name webfinger
   * @api public
   */
  static async webfinger(input) {
    const resource = webfingerNormalize(input);
    const { host } = url.parse(resource);
    const webfingerUrl = `https://${host}${WEBFINGER}`;

    const response = await request.call(this, {
      method: 'GET',
      url: webfingerUrl,
      json: true,
      query: { resource, rel: REL },
      followRedirect: true,
    });
    const body = processResponse(response);

    const location = Array.isArray(body.links) && body.links.find((link) => typeof link === 'object' && link.rel === REL && link.href);

    if (!location) {
      throw new RPError({
        message: 'no issuer found in webfinger response',
        body,
      });
    }

    if (typeof location.href !== 'string' || !location.href.startsWith('https://')) {
      throw new RPError({
        printf: ['invalid issuer location %s', location.href],
        body,
      });
    }

    const expectedIssuer = location.href;
    if (registry.has(expectedIssuer)) {
      return registry.get(expectedIssuer);
    }

    const issuer = await this.discover(expectedIssuer);

    if (issuer.issuer !== expectedIssuer) {
      registry.delete(issuer.issuer);
      throw new RPError('discovered issuer mismatch, expected %s, got: %s', expectedIssuer, issuer.issuer);
    }
    return issuer;
  }

  /**
   * @name discover
   * @api public
   */
  static async discover(uri) {
    const parsed = url.parse(uri);

    if (parsed.pathname.includes('/.well-known/')) {
      const response = await request.call(this, {
        method: 'GET',
        json: true,
        url: uri,
      });
      const body = processResponse(response);
      return new Issuer({
        ...ISSUER_DEFAULTS,
        ...body,
        [AAD_MULTITENANT]: !!AAD_MULTITENANT_DISCOVERY.find(
          (discoveryURL) => uri.startsWith(discoveryURL),
        ),
      });
    }

    const uris = [];
    if (parsed.pathname === '/') {
      uris.push(`${OAUTH2_DISCOVERY}`);
    } else {
      uris.push(`${OAUTH2_DISCOVERY}${parsed.pathname}`);
    }
    if (parsed.pathname.endsWith('/')) {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY.substring(1)}`);
    } else {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY}`);
    }

    return pAny(uris.map(async (pathname) => {
      const wellKnownUri = url.format({ ...parsed, pathname });
      const response = await request.call(this, {
        method: 'GET',
        json: true,
        url: wellKnownUri,
      });
      const body = processResponse(response);
      return new Issuer({
        ...ISSUER_DEFAULTS,
        ...body,
        [AAD_MULTITENANT]: !!AAD_MULTITENANT_DISCOVERY.find(
          (discoveryURL) => wellKnownUri.startsWith(discoveryURL),
        ),
      });
    }));
  }

  /* istanbul ignore next */
  [inspect.custom]() {
    return `${this.constructor.name} ${inspect(this.metadata, {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true,
    })}`;
  }
}

/**
 * @name key
 * @api private
 */
Issuer.prototype.key = deprecate(async function key({
  kid, kty, alg, use, key_ops: ops,
}, allowMulti = false) {
  const cache = instance(this).get('cache');

  const def = {
    kid, kty, alg, use, key_ops: ops,
  };

  const defHash = objectHash(def, {
    algorithm: 'sha256',
    ignoreUnknown: true,
    unorderedArrays: true,
    unorderedSets: true,
  });

  // refresh keystore on every unknown key but also only upto once every minute
  const freshJwksUri = cache.get(defHash) || cache.get('throttle');

  const keystore = await this.keystore(!freshJwksUri);
  const keys = keystore.all(def);

  if (keys.length === 0) {
    throw new RPError({
      printf: ["no valid key found in issuer's jwks_uri for key parameters %j", def],
      jwks: keystore,
    });
  }
  if (!allowMulti) {
    if (keys.length !== 1) {
      throw new RPError({
        printf: ["multiple matching keys found in issuer's jwks_uri for key parameters %j, kid must be provided in this case", def],
        jwks: keystore,
      });
    }
    cache.set(defHash, true);
  }
  return keys[0];
}, 'issuer.key is not only a private API, it is also deprecated');

module.exports = Issuer;


/***/ }),

/***/ "ARPQ":
/***/ (function(module, exports, __webpack_require__) {

const isObject = __webpack_require__("kF1/")
let validateCrit = __webpack_require__("urXW")

const { JWEInvalid } = __webpack_require__("yt7c")

validateCrit = validateCrit.bind(undefined, JWEInvalid)

const compactSerializer = (final, [recipient]) => {
  return `${final.protected}.${recipient.encrypted_key}.${final.iv}.${final.ciphertext}.${final.tag}`
}
compactSerializer.validate = (protectedHeader, unprotectedHeader, aad, { 0: { header }, length }) => {
  if (length !== 1 || aad || unprotectedHeader || header) {
    throw new JWEInvalid('JWE Compact Serialization doesn\'t support multiple recipients, JWE unprotected headers or AAD')
  }
  validateCrit(protectedHeader, unprotectedHeader, protectedHeader ? protectedHeader.crit : undefined)
}

const flattenedSerializer = (final, [recipient]) => {
  const { header, encrypted_key: encryptedKey } = recipient

  return {
    ...(final.protected ? { protected: final.protected } : undefined),
    ...(final.unprotected ? { unprotected: final.unprotected } : undefined),
    ...(header ? { header } : undefined),
    ...(encryptedKey ? { encrypted_key: encryptedKey } : undefined),
    ...(final.aad ? { aad: final.aad } : undefined),
    iv: final.iv,
    ciphertext: final.ciphertext,
    tag: final.tag
  }
}
flattenedSerializer.validate = (protectedHeader, unprotectedHeader, aad, { 0: { header }, length }) => {
  if (length !== 1) {
    throw new JWEInvalid('Flattened JWE JSON Serialization doesn\'t support multiple recipients')
  }
  validateCrit(protectedHeader, { ...unprotectedHeader, ...header }, protectedHeader ? protectedHeader.crit : undefined)
}

const generalSerializer = (final, recipients) => {
  const result = {
    ...(final.protected ? { protected: final.protected } : undefined),
    ...(final.unprotected ? { unprotected: final.unprotected } : undefined),
    recipients: recipients.map(({ header, encrypted_key: encryptedKey, generatedHeader }) => {
      if (!header && !encryptedKey && !generatedHeader) {
        return false
      }

      return {
        ...(header || generatedHeader ? { header: { ...header, ...generatedHeader } } : undefined),
        ...(encryptedKey ? { encrypted_key: encryptedKey } : undefined)
      }
    }).filter(Boolean),
    ...(final.aad ? { aad: final.aad } : undefined),
    iv: final.iv,
    ciphertext: final.ciphertext,
    tag: final.tag
  }

  if (!result.recipients.length) {
    delete result.recipients
  }

  return result
}
generalSerializer.validate = (protectedHeader, unprotectedHeader, aad, recipients) => {
  recipients.forEach(({ header }) => {
    validateCrit(protectedHeader, { ...header, ...unprotectedHeader }, protectedHeader ? protectedHeader.crit : undefined)
  })
}

const isJSON = (input) => {
  return isObject(input) &&
    typeof input.ciphertext === 'string' &&
    typeof input.iv === 'string' &&
    typeof input.tag === 'string' &&
    (input.unprotected === undefined || isObject(input.unprotected)) &&
    (input.protected === undefined || typeof input.protected === 'string') &&
    (input.aad === undefined || typeof input.aad === 'string')
}

const isSingleRecipient = (input) => {
  return (input.encrypted_key === undefined || typeof input.encrypted_key === 'string') &&
    (input.header === undefined || isObject(input.header))
}

const isValidRecipient = (recipient) => {
  return isObject(recipient) && typeof recipient.encrypted_key === 'string' && (recipient.header === undefined || isObject(recipient.header))
}

const isMultiRecipient = (input) => {
  if (Array.isArray(input.recipients) && input.recipients.every(isValidRecipient)) {
    return true
  }

  return false
}

const detect = (input) => {
  if (typeof input === 'string' && input.split('.').length === 5) {
    return 'compact'
  }

  if (isJSON(input)) {
    if (isMultiRecipient(input)) {
      return 'general'
    }

    if (isSingleRecipient(input)) {
      return 'flattened'
    }
  }

  throw new JWEInvalid('JWE malformed or invalid serialization')
}

module.exports = {
  compact: compactSerializer,
  flattened: flattenedSerializer,
  general: generalSerializer,
  detect
}


/***/ }),

/***/ "AW8e":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {URL} = __webpack_require__("bzos");
const is = __webpack_require__("6mOv");
const knownHookEvents = __webpack_require__("JlL/");

const merge = (target, ...sources) => {
	for (const source of sources) {
		for (const [key, sourceValue] of Object.entries(source)) {
			if (is.undefined(sourceValue)) {
				continue;
			}

			const targetValue = target[key];
			if (is.urlInstance(targetValue) && (is.urlInstance(sourceValue) || is.string(sourceValue))) {
				target[key] = new URL(sourceValue, targetValue);
			} else if (is.plainObject(sourceValue)) {
				if (is.plainObject(targetValue)) {
					target[key] = merge({}, targetValue, sourceValue);
				} else {
					target[key] = merge({}, sourceValue);
				}
			} else if (is.array(sourceValue)) {
				target[key] = merge([], sourceValue);
			} else {
				target[key] = sourceValue;
			}
		}
	}

	return target;
};

const mergeOptions = (...sources) => {
	sources = sources.map(source => source || {});
	const merged = merge({}, ...sources);

	const hooks = {};
	for (const hook of knownHookEvents) {
		hooks[hook] = [];
	}

	for (const source of sources) {
		if (source.hooks) {
			for (const hook of knownHookEvents) {
				hooks[hook] = hooks[hook].concat(source.hooks[hook]);
			}
		}
	}

	merged.hooks = hooks;

	return merged;
};

const mergeInstances = (instances, methods) => {
	const handlers = instances.map(instance => instance.defaults.handler);
	const size = instances.length - 1;

	return {
		methods,
		options: mergeOptions(...instances.map(instance => instance.defaults.options)),
		handler: (options, next) => {
			let iteration = -1;
			const iterate = options => handlers[++iteration](options, iteration === size ? next : iterate);

			return iterate(options);
		}
	};
};

module.exports = merge;
module.exports.options = mergeOptions;
module.exports.instances = mergeInstances;


/***/ }),

/***/ "AWHq":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.interopDefault=interopDefault;exports.loadComponents=loadComponents;var _constants=__webpack_require__("w7wo");var _path=__webpack_require__("oyvS");var _require=__webpack_require__("vv4h");function interopDefault(mod){return mod.default||mod;}async function loadComponents(distDir,pathname,serverless){if(serverless){const Component=await(0,_require.requirePage)(pathname,distDir,serverless);const{getStaticProps,getStaticPaths,getServerSideProps}=Component;return{Component,pageConfig:Component.config||{},getStaticProps,getStaticPaths,getServerSideProps};}const DocumentMod=(0,_require.requirePage)('/_document',distDir,serverless);const AppMod=(0,_require.requirePage)('/_app',distDir,serverless);const ComponentMod=(0,_require.requirePage)(pathname,distDir,serverless);const[buildManifest,reactLoadableManifest,Component,Document,App]=await Promise.all([__webpack_require__("PJv+")((0,_path.join)(distDir,_constants.BUILD_MANIFEST)),__webpack_require__("PJv+")((0,_path.join)(distDir,_constants.REACT_LOADABLE_MANIFEST)),interopDefault(ComponentMod),interopDefault(DocumentMod),interopDefault(AppMod)]);const{getServerSideProps,getStaticProps,getStaticPaths}=ComponentMod;return{App,Document,Component,buildManifest,reactLoadableManifest,pageConfig:ComponentMod.config||{},getServerSideProps,getStaticProps,getStaticPaths};}
//# sourceMappingURL=load-components.js.map

/***/ }),

/***/ "AfMj":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const pkg = __webpack_require__("tCGZ");
const create = __webpack_require__("canG");

const defaults = {
	options: {
		retry: {
			retries: 2,
			methods: [
				'GET',
				'PUT',
				'HEAD',
				'DELETE',
				'OPTIONS',
				'TRACE'
			],
			statusCodes: [
				408,
				413,
				429,
				500,
				502,
				503,
				504
			],
			errorCodes: [
				'ETIMEDOUT',
				'ECONNRESET',
				'EADDRINUSE',
				'ECONNREFUSED',
				'EPIPE',
				'ENOTFOUND',
				'ENETUNREACH',
				'EAI_AGAIN'
			]
		},
		headers: {
			'user-agent': `${pkg.name}/${pkg.version} (https://github.com/sindresorhus/got)`
		},
		hooks: {
			beforeRequest: [],
			beforeRedirect: [],
			beforeRetry: [],
			afterResponse: []
		},
		decompress: true,
		throwHttpErrors: true,
		followRedirect: true,
		stream: false,
		form: false,
		json: false,
		cache: false,
		useElectronNet: false
	},
	mutableDefaults: false
};

const got = create(defaults);

module.exports = got;


/***/ }),

/***/ "Alr0":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


class CancelError extends Error {
	constructor(reason) {
		super(reason || 'Promise was canceled');
		this.name = 'CancelError';
	}

	get isCanceled() {
		return true;
	}
}

class PCancelable {
	static fn(userFn) {
		return (...arguments_) => {
			return new PCancelable((resolve, reject, onCancel) => {
				arguments_.push(onCancel);
				// eslint-disable-next-line promise/prefer-await-to-then
				userFn(...arguments_).then(resolve, reject);
			});
		};
	}

	constructor(executor) {
		this._cancelHandlers = [];
		this._isPending = true;
		this._isCanceled = false;
		this._rejectOnCancel = true;

		this._promise = new Promise((resolve, reject) => {
			this._reject = reject;

			const onResolve = value => {
				this._isPending = false;
				resolve(value);
			};

			const onReject = error => {
				this._isPending = false;
				reject(error);
			};

			const onCancel = handler => {
				if (!this._isPending) {
					throw new Error('The `onCancel` handler was attached after the promise settled.');
				}

				this._cancelHandlers.push(handler);
			};

			Object.defineProperties(onCancel, {
				shouldReject: {
					get: () => this._rejectOnCancel,
					set: boolean => {
						this._rejectOnCancel = boolean;
					}
				}
			});

			return executor(onResolve, onReject, onCancel);
		});
	}

	then(onFulfilled, onRejected) {
		// eslint-disable-next-line promise/prefer-await-to-then
		return this._promise.then(onFulfilled, onRejected);
	}

	catch(onRejected) {
		return this._promise.catch(onRejected);
	}

	finally(onFinally) {
		return this._promise.finally(onFinally);
	}

	cancel(reason) {
		if (!this._isPending || this._isCanceled) {
			return;
		}

		if (this._cancelHandlers.length > 0) {
			try {
				for (const handler of this._cancelHandlers) {
					handler();
				}
			} catch (error) {
				this._reject(error);
			}
		}

		this._isCanceled = true;
		if (this._rejectOnCancel) {
			this._reject(new CancelError(reason));
		}
	}

	get isCanceled() {
		return this._isCanceled;
	}
}

Object.setPrototypeOf(PCancelable.prototype, Promise.prototype);

module.exports = PCancelable;
module.exports.CancelError = CancelError;


/***/ }),

/***/ "AlvL":
/***/ (function(module, exports) {

const curves = new Set(['Ed25519'])

if (!('electron' in process.versions)) {
  curves.add('Ed448')
  curves.add('X25519')
  curves.add('X448')
}

module.exports = curves


/***/ }),

/***/ "B2tm":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("eq/D");


const internals = {};


module.exports = function (obj, template, options) {

    return template.replace(/{([^}]+)}/g, ($0, chain) => {

        const value = Reach(obj, chain, options);
        return (value === undefined || value === null ? '' : value);
    });
};


/***/ }),

/***/ "BBt9":
/***/ (function(module, exports, __webpack_require__) {

const { randomBytes } = __webpack_require__("PJMN")

const { createSecretKey } = __webpack_require__("1ALl")
const base64url = __webpack_require__("Xab3")
const {
  THUMBPRINT_MATERIAL, PUBLIC_MEMBERS, PRIVATE_MEMBERS,
  KEY_MANAGEMENT_DECRYPT, KEY_MANAGEMENT_ENCRYPT, KEYOBJECT
} = __webpack_require__("ehsS")

const Key = __webpack_require__("//Cd")

const OCT_PUBLIC = new Set()
Object.freeze(OCT_PUBLIC)
const OCT_PRIVATE = new Set(['k'])
Object.freeze(OCT_PRIVATE)

// Octet sequence Key Type
class OctKey extends Key {
  constructor (...args) {
    super(...args)
    Object.defineProperties(this, {
      kty: {
        value: 'oct',
        enumerable: true
      },
      length: {
        value: this[KEYOBJECT] ? this[KEYOBJECT].symmetricKeySize * 8 : undefined
      },
      k: {
        enumerable: false,
        get () {
          if (this[KEYOBJECT]) {
            Object.defineProperty(this, 'k', {
              value: base64url.encodeBuffer(this[KEYOBJECT].export()),
              configurable: false
            })
          } else {
            Object.defineProperty(this, 'k', {
              value: undefined,
              configurable: false
            })
          }

          return this.k
        },
        configurable: true
      }
    })
  }

  static get [PUBLIC_MEMBERS] () {
    return OCT_PUBLIC
  }

  static get [PRIVATE_MEMBERS] () {
    return OCT_PRIVATE
  }

  // https://tc39.github.io/ecma262/#sec-ordinaryownpropertykeys no need for any special
  // JSON.stringify handling in V8
  [THUMBPRINT_MATERIAL] () {
    if (!this[KEYOBJECT]) {
      throw new TypeError('reference "oct" keys without "k" cannot have their thumbprint calculated')
    }
    return { k: this.k, kty: 'oct' }
  }

  [KEY_MANAGEMENT_ENCRYPT] () {
    return new Set([
      ...this.algorithms('wrapKey'),
      ...this.algorithms('deriveKey')
    ])
  }

  [KEY_MANAGEMENT_DECRYPT] () {
    return this[KEY_MANAGEMENT_ENCRYPT]()
  }

  algorithms (...args) {
    if (!this[KEYOBJECT]) {
      return new Set()
    }

    return Key.prototype.algorithms.call(this, ...args)
  }

  static async generate (...args) {
    return this.generateSync(...args)
  }

  static generateSync (len = 256, privat = true) {
    if (!privat) {
      throw new TypeError('"oct" keys cannot be generated as public')
    }
    if (!Number.isSafeInteger(len) || !len || len % 8 !== 0) {
      throw new TypeError('invalid bit length')
    }

    return createSecretKey(randomBytes(len / 8))
  }
}

module.exports = OctKey


/***/ }),

/***/ "BJV5":
/***/ (function(module, exports, __webpack_require__) {

const { createCipheriv, createDecipheriv, getCiphers } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const { JWEInvalid, JWEDecryptionFailed } = __webpack_require__("yt7c")
const { asInput } = __webpack_require__("1ALl")

const checkInput = function (size, iv, tag) {
  if (iv.length !== 12) {
    throw new JWEInvalid('invalid iv')
  }
  if (arguments.length === 3) {
    if (tag.length !== 16) {
      throw new JWEInvalid('invalid tag')
    }
  }
}

const encrypt = (size, { [KEYOBJECT]: keyObject }, cleartext, { iv, aad = Buffer.alloc(0) }) => {
  const key = asInput(keyObject, false)
  checkInput(size, iv)

  const cipher = createCipheriv(`aes-${size}-gcm`, key, iv, { authTagLength: 16 })
  cipher.setAAD(aad)

  const ciphertext = Buffer.concat([cipher.update(cleartext), cipher.final()])
  const tag = cipher.getAuthTag()

  return { ciphertext, tag }
}

const decrypt = (size, { [KEYOBJECT]: keyObject }, ciphertext, { iv, tag = Buffer.alloc(0), aad = Buffer.alloc(0) }) => {
  const key = asInput(keyObject, false)
  checkInput(size, iv, tag)

  try {
    const cipher = createDecipheriv(`aes-${size}-gcm`, key, iv, { authTagLength: 16 })
    cipher.setAuthTag(tag)
    cipher.setAAD(aad)

    return Buffer.concat([cipher.update(ciphertext), cipher.final()])
  } catch (err) {
    throw new JWEDecryptionFailed()
  }
}

module.exports = (JWA, JWK) => {
  ['A128GCM', 'A192GCM', 'A256GCM'].forEach((jwaAlg) => {
    const size = parseInt(jwaAlg.substr(1, 3), 10)
    if (getCiphers().includes(`aes-${size}-gcm`)) {
      JWA.encrypt.set(jwaAlg, encrypt.bind(undefined, size))
      JWA.decrypt.set(jwaAlg, decrypt.bind(undefined, size))
      JWK.oct.encrypt[jwaAlg] = JWK.oct.decrypt[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.length === size
    }
  })
}


/***/ }),

/***/ "BOd6":
/***/ (function(module, exports, __webpack_require__) {

const isObject = __webpack_require__("kF1/")
const epoch = __webpack_require__("F4x3")
const secs = __webpack_require__("o156")
const getKey = __webpack_require__("oGTz")
const { bare: verify } = __webpack_require__("ZXG7")
const { JWTClaimInvalid, JWTExpired } = __webpack_require__("yt7c")

const { isString, isNotString } = __webpack_require__("mRrf")
const decode = __webpack_require__("7o4N")

const isPayloadString = isString.bind(undefined, JWTClaimInvalid)
const isOptionString = isString.bind(undefined, TypeError)

const IDTOKEN = 'id_token'
const LOGOUTTOKEN = 'logout_token'
const ATJWT = 'at+JWT'

const isTimestamp = (value, label, required = false) => {
  if (required && value === undefined) {
    throw new JWTClaimInvalid(`"${label}" claim is missing`, label, 'missing')
  }

  if (value !== undefined && (typeof value !== 'number')) {
    throw new JWTClaimInvalid(`"${label}" claim must be a JSON numeric value`, label, 'invalid')
  }
}

const isStringOrArrayOfStrings = (value, label, required = false) => {
  if (required && value === undefined) {
    throw new JWTClaimInvalid(`"${label}" claim is missing`, label, 'missing')
  }

  if (value !== undefined && (isNotString(value) && isNotArrayOfStrings(value))) {
    throw new JWTClaimInvalid(`"${label}" claim must be a string or array of strings`, label, 'invalid')
  }
}

const isNotArrayOfStrings = val => !Array.isArray(val) || val.length === 0 || val.some(isNotString)
const normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, '')

const validateOptions = ({
  algorithms, audience, clockTolerance, complete = false, crit, ignoreExp = false,
  ignoreIat = false, ignoreNbf = false, issuer, jti, maxAuthAge, maxTokenAge, nonce, now = new Date(),
  profile, subject, typ
}) => {
  isOptionString(profile, 'options.profile')

  if (typeof complete !== 'boolean') {
    throw new TypeError('options.complete must be a boolean')
  }

  if (typeof ignoreExp !== 'boolean') {
    throw new TypeError('options.ignoreExp must be a boolean')
  }

  if (typeof ignoreNbf !== 'boolean') {
    throw new TypeError('options.ignoreNbf must be a boolean')
  }

  if (typeof ignoreIat !== 'boolean') {
    throw new TypeError('options.ignoreIat must be a boolean')
  }

  isOptionString(maxTokenAge, 'options.maxTokenAge')
  isOptionString(subject, 'options.subject')
  isOptionString(maxAuthAge, 'options.maxAuthAge')
  isOptionString(jti, 'options.jti')
  isOptionString(clockTolerance, 'options.clockTolerance')
  isOptionString(typ, 'options.typ')

  if (issuer !== undefined && (isNotString(issuer) && isNotArrayOfStrings(issuer))) {
    throw new TypeError('options.issuer must be a string or an array of strings')
  }

  if (audience !== undefined && (isNotString(audience) && isNotArrayOfStrings(audience))) {
    throw new TypeError('options.audience must be a string or an array of strings')
  }

  if (algorithms !== undefined && isNotArrayOfStrings(algorithms)) {
    throw new TypeError('options.algorithms must be an array of strings')
  }

  isOptionString(nonce, 'options.nonce')

  if (!(now instanceof Date) || !now.getTime()) {
    throw new TypeError('options.now must be a valid Date object')
  }

  if (ignoreIat && maxTokenAge !== undefined) {
    throw new TypeError('options.ignoreIat and options.maxTokenAge cannot used together')
  }

  if (crit !== undefined && isNotArrayOfStrings(crit)) {
    throw new TypeError('options.crit must be an array of strings')
  }

  switch (profile) {
    case IDTOKEN:
      if (!issuer) {
        throw new TypeError('"issuer" option is required to validate an ID Token')
      }

      if (!audience) {
        throw new TypeError('"audience" option is required to validate an ID Token')
      }

      break
    case ATJWT:
      if (!issuer) {
        throw new TypeError('"issuer" option is required to validate a JWT Access Token')
      }

      if (!audience) {
        throw new TypeError('"audience" option is required to validate a JWT Access Token')
      }

      typ = ATJWT

      break
    case LOGOUTTOKEN:
      if (!issuer) {
        throw new TypeError('"issuer" option is required to validate a Logout Token')
      }

      if (!audience) {
        throw new TypeError('"audience" option is required to validate a Logout Token')
      }

      break
    case undefined:
      break
    default:
      throw new TypeError(`unsupported options.profile value "${profile}"`)
  }

  return {
    algorithms,
    audience,
    clockTolerance,
    complete,
    crit,
    ignoreExp,
    ignoreIat,
    ignoreNbf,
    issuer,
    jti,
    maxAuthAge,
    maxTokenAge,
    nonce,
    now,
    profile,
    subject,
    typ
  }
}

const validateTypes = ({ header, payload }, profile, options) => {
  isPayloadString(header.alg, '"alg" header parameter', 'alg', true)

  isTimestamp(payload.iat, 'iat', profile === IDTOKEN || profile === LOGOUTTOKEN || profile === ATJWT || !!options.maxTokenAge)
  isTimestamp(payload.exp, 'exp', profile === IDTOKEN || profile === ATJWT)
  isTimestamp(payload.auth_time, 'auth_time', !!options.maxAuthAge)
  isTimestamp(payload.nbf, 'nbf')
  isPayloadString(payload.jti, '"jti" claim', 'jti', profile === LOGOUTTOKEN || profile === ATJWT || !!options.jti)
  isPayloadString(payload.acr, '"acr" claim', 'acr')
  isPayloadString(payload.nonce, '"nonce" claim', 'nonce', !!options.nonce)
  isStringOrArrayOfStrings(payload.iss, 'iss', !!options.issuer)
  isPayloadString(payload.sub, '"sub" claim', 'sub', profile === IDTOKEN || profile === ATJWT || !!options.subject)
  isStringOrArrayOfStrings(payload.aud, 'aud', !!options.audience)
  isPayloadString(payload.azp, '"azp" claim', 'azp', profile === IDTOKEN && Array.isArray(payload.aud) && payload.aud.length > 1)
  isStringOrArrayOfStrings(payload.amr, 'amr')
  isPayloadString(header.typ, '"typ" header parameter', 'typ', !!options.typ)

  if (profile === ATJWT) {
    isPayloadString(payload.client_id, '"client_id" claim', 'client_id', true)
  }

  if (profile === LOGOUTTOKEN) {
    isPayloadString(payload.sid, '"sid" claim', 'sid')

    if (!('sid' in payload) && !('sub' in payload)) {
      throw new JWTClaimInvalid('either "sid" or "sub" (or both) claims must be present')
    }

    if ('nonce' in payload) {
      throw new JWTClaimInvalid('"nonce" claim is prohibited', 'nonce', 'prohibited')
    }

    if (!('events' in payload)) {
      throw new JWTClaimInvalid('"events" claim is missing', 'events', 'missing')
    }

    if (!isObject(payload.events)) {
      throw new JWTClaimInvalid('"events" claim must be an object', 'events', 'invalid')
    }

    if (!('http://schemas.openid.net/event/backchannel-logout' in payload.events)) {
      throw new JWTClaimInvalid('"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim', 'events', 'invalid')
    }

    if (!isObject(payload.events['http://schemas.openid.net/event/backchannel-logout'])) {
      throw new JWTClaimInvalid('"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object', 'events', 'invalid')
    }
  }
}

const checkAudiencePresence = (audPayload, audOption, profile) => {
  if (typeof audPayload === 'string') {
    return audOption.includes(audPayload)
  }

  // Each principal intended to process the JWT MUST
  // identify itself with a value in the audience claim
  audPayload = new Set(audPayload)
  return audOption.some(Set.prototype.has.bind(audPayload))
}

module.exports = (token, key, options = {}) => {
  if (!isObject(options)) {
    throw new TypeError('options must be an object')
  }

  const {
    algorithms, audience, clockTolerance, complete, crit, ignoreExp, ignoreIat, ignoreNbf, issuer,
    jti, maxAuthAge, maxTokenAge, nonce, now, profile, subject, typ
  } = options = validateOptions(options)

  const decoded = decode(token, { complete: true })
  key = getKey(key, true)

  if (complete) {
    ({ key } = verify(true, 'preparsed', { decoded, token }, key, { crit, algorithms, complete: true }))
    decoded.key = key
  } else {
    verify(true, 'preparsed', { decoded, token }, key, { crit, algorithms })
  }

  const unix = epoch(now)
  validateTypes(decoded, profile, options)

  if (issuer && (typeof decoded.payload.iss !== 'string' || !(typeof issuer === 'string' ? [issuer] : issuer).includes(decoded.payload.iss))) {
    throw new JWTClaimInvalid('unexpected "iss" claim value', 'iss', 'check_failed')
  }

  if (nonce && decoded.payload.nonce !== nonce) {
    throw new JWTClaimInvalid('unexpected "nonce" claim value', 'nonce', 'check_failed')
  }

  if (subject && decoded.payload.sub !== subject) {
    throw new JWTClaimInvalid('unexpected "sub" claim value', 'sub', 'check_failed')
  }

  if (jti && decoded.payload.jti !== jti) {
    throw new JWTClaimInvalid('unexpected "jti" claim value', 'jti', 'check_failed')
  }

  if (audience && !checkAudiencePresence(decoded.payload.aud, typeof audience === 'string' ? [audience] : audience, profile)) {
    throw new JWTClaimInvalid('unexpected "aud" claim value', 'aud', 'check_failed')
  }

  if (typ && normalizeTyp(decoded.header.typ) !== normalizeTyp(typ)) {
    throw new JWTClaimInvalid('unexpected "typ" JWT header value', 'typ', 'check_failed')
  }

  const tolerance = clockTolerance ? secs(clockTolerance) : 0

  if (maxAuthAge) {
    const maxAuthAgeSeconds = secs(maxAuthAge)
    if (decoded.payload.auth_time + maxAuthAgeSeconds < unix - tolerance) {
      throw new JWTClaimInvalid('"auth_time" claim timestamp check failed (too much time has elapsed since the last End-User authentication)', 'auth_time', 'check_failed')
    }
  }

  if (!ignoreIat && !('exp' in decoded.payload) && 'iat' in decoded.payload && decoded.payload.iat > unix + tolerance) {
    throw new JWTClaimInvalid('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed')
  }

  if (!ignoreNbf && 'nbf' in decoded.payload && decoded.payload.nbf > unix + tolerance) {
    throw new JWTClaimInvalid('"nbf" claim timestamp check failed', 'nbf', 'check_failed')
  }

  if (!ignoreExp && 'exp' in decoded.payload && decoded.payload.exp <= unix - tolerance) {
    throw new JWTExpired('"exp" claim timestamp check failed', 'exp', 'check_failed')
  }

  if (maxTokenAge) {
    const age = unix - decoded.payload.iat
    const max = secs(maxTokenAge)

    if (age - tolerance > max) {
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', 'iat', 'check_failed')
    }

    if (age < 0 - tolerance) {
      throw new JWTClaimInvalid('"iat" claim timestamp check failed (it should be in the past)', 'iat', 'check_failed')
    }
  }

  if (profile === IDTOKEN && Array.isArray(decoded.payload.aud) && decoded.payload.aud.length > 1 && decoded.payload.azp !== audience) {
    throw new JWTClaimInvalid('unexpected "azp" claim value', 'azp', 'check_failed')
  }

  return complete ? decoded : decoded.payload
}


/***/ }),

/***/ "BS6f":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.flatten = function (array, target) {

    const result = target || [];

    for (let i = 0; i < array.length; ++i) {
        if (Array.isArray(array[i])) {
            internals.flatten(array[i], result);
        }
        else {
            result.push(array[i]);
        }
    }

    return result;
};


/***/ }),

/***/ "BzZA":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/*
    Encode functions adapted from:
    Version 1.0 12/25/99 Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>
    http://www.onicos.com/staff/iz/amuse/javascript/expert/base64.txt
*/

const Stream = __webpack_require__("msIP");


const internals = {};


exports.encode = function (buffer) {

    return Buffer.from(buffer.toString('base64'));
};


exports.Encoder = class Encoder extends Stream.Transform {
    constructor() {

        super();
        this._reminder = null;
    }

    _transform(chunk, encoding, callback) {

        let part = this._reminder ? Buffer.concat([this._reminder, chunk]) : chunk;
        const remaining = part.length % 3;
        if (remaining) {
            this._reminder = part.slice(part.length - remaining);
            part = part.slice(0, part.length - remaining);
        }
        else {
            this._reminder = null;
        }

        this.push(exports.encode(part));
        return callback();
    }

    _flush(callback) {

        if (this._reminder) {
            this.push(exports.encode(this._reminder));
        }

        return callback();
    }
};


/***/ }),

/***/ "C/Kw":
/***/ (function(module, exports, __webpack_require__) {

const { improvedDH } = __webpack_require__("pDDt")
const { KEYLENGTHS } = __webpack_require__("N+nT")
const { generateSync } = __webpack_require__("LDEB")
const { name: secp256k1 } = __webpack_require__("F/JS")

const derive = __webpack_require__("kZLX")

const wrapKey = (key, payload, { enc }) => {
  const epk = generateSync(key.kty, key.crv)

  const derivedKey = derive(enc, KEYLENGTHS.get(enc), epk, key)

  return {
    wrapped: derivedKey,
    header: { epk: { kty: key.kty, crv: key.crv, x: epk.x, y: epk.y } }
  }
}

const unwrapKey = (key, payload, header) => {
  const { enc, epk } = header
  return derive(enc, KEYLENGTHS.get(enc), key, epk, header)
}

module.exports = (JWA, JWK) => {
  JWA.keyManagementEncrypt.set('ECDH-ES', wrapKey)
  JWA.keyManagementDecrypt.set('ECDH-ES', unwrapKey)
  JWK.EC.deriveKey['ECDH-ES'] = key => (key.use === 'enc' || key.use === undefined) && key.crv !== secp256k1

  if (improvedDH) {
    JWK.OKP.deriveKey['ECDH-ES'] = key => (key.use === 'enc' || key.use === undefined) && key.keyObject.asymmetricKeyType.startsWith('x')
  }
}


/***/ }),

/***/ "CMUe":
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,t){"use strict";var r={};function __webpack_require__(t){if(r[t]){return r[t].exports}var i=r[t]={i:t,l:false,exports:{}};e[t].call(i.exports,i,i.exports,__webpack_require__);i.l=true;return i.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(828)}return startup()}({42:function(e){e.exports=[["0","\0",127],["8ea1","｡",62],["a1a1","　、。，．・：；？！゛゜´｀¨＾￣＿ヽヾゝゞ〃仝々〆〇ー―‐／＼～∥｜…‥‘’“”（）〔〕［］｛｝〈",9,"＋－±×÷＝≠＜＞≦≧∞∴♂♀°′″℃￥＄￠￡％＃＆＊＠§☆★○●◎◇"],["a2a1","◆□■△▲▽▼※〒→←↑↓〓"],["a2ba","∈∋⊆⊇⊂⊃∪∩"],["a2ca","∧∨￢⇒⇔∀∃"],["a2dc","∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬"],["a2f2","Å‰♯♭♪†‡¶"],["a2fe","◯"],["a3b0","０",9],["a3c1","Ａ",25],["a3e1","ａ",25],["a4a1","ぁ",82],["a5a1","ァ",85],["a6a1","Α",16,"Σ",6],["a6c1","α",16,"σ",6],["a7a1","А",5,"ЁЖ",25],["a7d1","а",5,"ёж",25],["a8a1","─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂"],["ada1","①",19,"Ⅰ",9],["adc0","㍉㌔㌢㍍㌘㌧㌃㌶㍑㍗㌍㌦㌣㌫㍊㌻㎜㎝㎞㎎㎏㏄㎡"],["addf","㍻〝〟№㏍℡㊤",4,"㈱㈲㈹㍾㍽㍼≒≡∫∮∑√⊥∠∟⊿∵∩∪"],["b0a1","亜唖娃阿哀愛挨姶逢葵茜穐悪握渥旭葦芦鯵梓圧斡扱宛姐虻飴絢綾鮎或粟袷安庵按暗案闇鞍杏以伊位依偉囲夷委威尉惟意慰易椅為畏異移維緯胃萎衣謂違遺医井亥域育郁磯一壱溢逸稲茨芋鰯允印咽員因姻引飲淫胤蔭"],["b1a1","院陰隠韻吋右宇烏羽迂雨卯鵜窺丑碓臼渦嘘唄欝蔚鰻姥厩浦瓜閏噂云運雲荏餌叡営嬰影映曳栄永泳洩瑛盈穎頴英衛詠鋭液疫益駅悦謁越閲榎厭円園堰奄宴延怨掩援沿演炎焔煙燕猿縁艶苑薗遠鉛鴛塩於汚甥凹央奥往応"],["b2a1","押旺横欧殴王翁襖鴬鴎黄岡沖荻億屋憶臆桶牡乙俺卸恩温穏音下化仮何伽価佳加可嘉夏嫁家寡科暇果架歌河火珂禍禾稼箇花苛茄荷華菓蝦課嘩貨迦過霞蚊俄峨我牙画臥芽蛾賀雅餓駕介会解回塊壊廻快怪悔恢懐戒拐改"],["b3a1","魁晦械海灰界皆絵芥蟹開階貝凱劾外咳害崖慨概涯碍蓋街該鎧骸浬馨蛙垣柿蛎鈎劃嚇各廓拡撹格核殻獲確穫覚角赫較郭閣隔革学岳楽額顎掛笠樫橿梶鰍潟割喝恰括活渇滑葛褐轄且鰹叶椛樺鞄株兜竃蒲釜鎌噛鴨栢茅萱"],["b4a1","粥刈苅瓦乾侃冠寒刊勘勧巻喚堪姦完官寛干幹患感慣憾換敢柑桓棺款歓汗漢澗潅環甘監看竿管簡緩缶翰肝艦莞観諌貫還鑑間閑関陥韓館舘丸含岸巌玩癌眼岩翫贋雁頑顔願企伎危喜器基奇嬉寄岐希幾忌揮机旗既期棋棄"],["b5a1","機帰毅気汽畿祈季稀紀徽規記貴起軌輝飢騎鬼亀偽儀妓宜戯技擬欺犠疑祇義蟻誼議掬菊鞠吉吃喫桔橘詰砧杵黍却客脚虐逆丘久仇休及吸宮弓急救朽求汲泣灸球究窮笈級糾給旧牛去居巨拒拠挙渠虚許距鋸漁禦魚亨享京"],["b6a1","供侠僑兇競共凶協匡卿叫喬境峡強彊怯恐恭挟教橋況狂狭矯胸脅興蕎郷鏡響饗驚仰凝尭暁業局曲極玉桐粁僅勤均巾錦斤欣欽琴禁禽筋緊芹菌衿襟謹近金吟銀九倶句区狗玖矩苦躯駆駈駒具愚虞喰空偶寓遇隅串櫛釧屑屈"],["b7a1","掘窟沓靴轡窪熊隈粂栗繰桑鍬勲君薫訓群軍郡卦袈祁係傾刑兄啓圭珪型契形径恵慶慧憩掲携敬景桂渓畦稽系経継繋罫茎荊蛍計詣警軽頚鶏芸迎鯨劇戟撃激隙桁傑欠決潔穴結血訣月件倹倦健兼券剣喧圏堅嫌建憲懸拳捲"],["b8a1","検権牽犬献研硯絹県肩見謙賢軒遣鍵険顕験鹸元原厳幻弦減源玄現絃舷言諺限乎個古呼固姑孤己庫弧戸故枯湖狐糊袴股胡菰虎誇跨鈷雇顧鼓五互伍午呉吾娯後御悟梧檎瑚碁語誤護醐乞鯉交佼侯候倖光公功効勾厚口向"],["b9a1","后喉坑垢好孔孝宏工巧巷幸広庚康弘恒慌抗拘控攻昂晃更杭校梗構江洪浩港溝甲皇硬稿糠紅紘絞綱耕考肯肱腔膏航荒行衡講貢購郊酵鉱砿鋼閤降項香高鴻剛劫号合壕拷濠豪轟麹克刻告国穀酷鵠黒獄漉腰甑忽惚骨狛込"],["baa1","此頃今困坤墾婚恨懇昏昆根梱混痕紺艮魂些佐叉唆嵯左差査沙瑳砂詐鎖裟坐座挫債催再最哉塞妻宰彩才採栽歳済災采犀砕砦祭斎細菜裁載際剤在材罪財冴坂阪堺榊肴咲崎埼碕鷺作削咋搾昨朔柵窄策索錯桜鮭笹匙冊刷"],["bba1","察拶撮擦札殺薩雑皐鯖捌錆鮫皿晒三傘参山惨撒散桟燦珊産算纂蚕讃賛酸餐斬暫残仕仔伺使刺司史嗣四士始姉姿子屍市師志思指支孜斯施旨枝止死氏獅祉私糸紙紫肢脂至視詞詩試誌諮資賜雌飼歯事似侍児字寺慈持時"],["bca1","次滋治爾璽痔磁示而耳自蒔辞汐鹿式識鴫竺軸宍雫七叱執失嫉室悉湿漆疾質実蔀篠偲柴芝屡蕊縞舎写射捨赦斜煮社紗者謝車遮蛇邪借勺尺杓灼爵酌釈錫若寂弱惹主取守手朱殊狩珠種腫趣酒首儒受呪寿授樹綬需囚収周"],["bda1","宗就州修愁拾洲秀秋終繍習臭舟蒐衆襲讐蹴輯週酋酬集醜什住充十従戎柔汁渋獣縦重銃叔夙宿淑祝縮粛塾熟出術述俊峻春瞬竣舜駿准循旬楯殉淳準潤盾純巡遵醇順処初所暑曙渚庶緒署書薯藷諸助叙女序徐恕鋤除傷償"],["bea1","勝匠升召哨商唱嘗奨妾娼宵将小少尚庄床廠彰承抄招掌捷昇昌昭晶松梢樟樵沼消渉湘焼焦照症省硝礁祥称章笑粧紹肖菖蒋蕉衝裳訟証詔詳象賞醤鉦鍾鐘障鞘上丈丞乗冗剰城場壌嬢常情擾条杖浄状畳穣蒸譲醸錠嘱埴飾"],["bfa1","拭植殖燭織職色触食蝕辱尻伸信侵唇娠寝審心慎振新晋森榛浸深申疹真神秦紳臣芯薪親診身辛進針震人仁刃塵壬尋甚尽腎訊迅陣靭笥諏須酢図厨逗吹垂帥推水炊睡粋翠衰遂酔錐錘随瑞髄崇嵩数枢趨雛据杉椙菅頗雀裾"],["c0a1","澄摺寸世瀬畝是凄制勢姓征性成政整星晴棲栖正清牲生盛精聖声製西誠誓請逝醒青静斉税脆隻席惜戚斥昔析石積籍績脊責赤跡蹟碩切拙接摂折設窃節説雪絶舌蝉仙先千占宣専尖川戦扇撰栓栴泉浅洗染潜煎煽旋穿箭線"],["c1a1","繊羨腺舛船薦詮賎践選遷銭銑閃鮮前善漸然全禅繕膳糎噌塑岨措曾曽楚狙疏疎礎祖租粗素組蘇訴阻遡鼠僧創双叢倉喪壮奏爽宋層匝惣想捜掃挿掻操早曹巣槍槽漕燥争痩相窓糟総綜聡草荘葬蒼藻装走送遭鎗霜騒像増憎"],["c2a1","臓蔵贈造促側則即息捉束測足速俗属賊族続卒袖其揃存孫尊損村遜他多太汰詑唾堕妥惰打柁舵楕陀駄騨体堆対耐岱帯待怠態戴替泰滞胎腿苔袋貸退逮隊黛鯛代台大第醍題鷹滝瀧卓啄宅托択拓沢濯琢託鐸濁諾茸凧蛸只"],["c3a1","叩但達辰奪脱巽竪辿棚谷狸鱈樽誰丹単嘆坦担探旦歎淡湛炭短端箪綻耽胆蛋誕鍛団壇弾断暖檀段男談値知地弛恥智池痴稚置致蜘遅馳築畜竹筑蓄逐秩窒茶嫡着中仲宙忠抽昼柱注虫衷註酎鋳駐樗瀦猪苧著貯丁兆凋喋寵"],["c4a1","帖帳庁弔張彫徴懲挑暢朝潮牒町眺聴脹腸蝶調諜超跳銚長頂鳥勅捗直朕沈珍賃鎮陳津墜椎槌追鎚痛通塚栂掴槻佃漬柘辻蔦綴鍔椿潰坪壷嬬紬爪吊釣鶴亭低停偵剃貞呈堤定帝底庭廷弟悌抵挺提梯汀碇禎程締艇訂諦蹄逓"],["c5a1","邸鄭釘鼎泥摘擢敵滴的笛適鏑溺哲徹撤轍迭鉄典填天展店添纏甜貼転顛点伝殿澱田電兎吐堵塗妬屠徒斗杜渡登菟賭途都鍍砥砺努度土奴怒倒党冬凍刀唐塔塘套宕島嶋悼投搭東桃梼棟盗淘湯涛灯燈当痘祷等答筒糖統到"],["c6a1","董蕩藤討謄豆踏逃透鐙陶頭騰闘働動同堂導憧撞洞瞳童胴萄道銅峠鴇匿得徳涜特督禿篤毒独読栃橡凸突椴届鳶苫寅酉瀞噸屯惇敦沌豚遁頓呑曇鈍奈那内乍凪薙謎灘捺鍋楢馴縄畷南楠軟難汝二尼弐迩匂賑肉虹廿日乳入"],["c7a1","如尿韮任妊忍認濡禰祢寧葱猫熱年念捻撚燃粘乃廼之埜嚢悩濃納能脳膿農覗蚤巴把播覇杷波派琶破婆罵芭馬俳廃拝排敗杯盃牌背肺輩配倍培媒梅楳煤狽買売賠陪這蝿秤矧萩伯剥博拍柏泊白箔粕舶薄迫曝漠爆縛莫駁麦"],["c8a1","函箱硲箸肇筈櫨幡肌畑畠八鉢溌発醗髪伐罰抜筏閥鳩噺塙蛤隼伴判半反叛帆搬斑板氾汎版犯班畔繁般藩販範釆煩頒飯挽晩番盤磐蕃蛮匪卑否妃庇彼悲扉批披斐比泌疲皮碑秘緋罷肥被誹費避非飛樋簸備尾微枇毘琵眉美"],["c9a1","鼻柊稗匹疋髭彦膝菱肘弼必畢筆逼桧姫媛紐百謬俵彪標氷漂瓢票表評豹廟描病秒苗錨鋲蒜蛭鰭品彬斌浜瀕貧賓頻敏瓶不付埠夫婦富冨布府怖扶敷斧普浮父符腐膚芙譜負賦赴阜附侮撫武舞葡蕪部封楓風葺蕗伏副復幅服"],["caa1","福腹複覆淵弗払沸仏物鮒分吻噴墳憤扮焚奮粉糞紛雰文聞丙併兵塀幣平弊柄並蔽閉陛米頁僻壁癖碧別瞥蔑箆偏変片篇編辺返遍便勉娩弁鞭保舗鋪圃捕歩甫補輔穂募墓慕戊暮母簿菩倣俸包呆報奉宝峰峯崩庖抱捧放方朋"],["cba1","法泡烹砲縫胞芳萌蓬蜂褒訪豊邦鋒飽鳳鵬乏亡傍剖坊妨帽忘忙房暴望某棒冒紡肪膨謀貌貿鉾防吠頬北僕卜墨撲朴牧睦穆釦勃没殆堀幌奔本翻凡盆摩磨魔麻埋妹昧枚毎哩槙幕膜枕鮪柾鱒桝亦俣又抹末沫迄侭繭麿万慢満"],["cca1","漫蔓味未魅巳箕岬密蜜湊蓑稔脈妙粍民眠務夢無牟矛霧鵡椋婿娘冥名命明盟迷銘鳴姪牝滅免棉綿緬面麺摸模茂妄孟毛猛盲網耗蒙儲木黙目杢勿餅尤戻籾貰問悶紋門匁也冶夜爺耶野弥矢厄役約薬訳躍靖柳薮鑓愉愈油癒"],["cda1","諭輸唯佑優勇友宥幽悠憂揖有柚湧涌猶猷由祐裕誘遊邑郵雄融夕予余与誉輿預傭幼妖容庸揚揺擁曜楊様洋溶熔用窯羊耀葉蓉要謡踊遥陽養慾抑欲沃浴翌翼淀羅螺裸来莱頼雷洛絡落酪乱卵嵐欄濫藍蘭覧利吏履李梨理璃"],["cea1","痢裏裡里離陸律率立葎掠略劉流溜琉留硫粒隆竜龍侶慮旅虜了亮僚両凌寮料梁涼猟療瞭稜糧良諒遼量陵領力緑倫厘林淋燐琳臨輪隣鱗麟瑠塁涙累類令伶例冷励嶺怜玲礼苓鈴隷零霊麗齢暦歴列劣烈裂廉恋憐漣煉簾練聯"],["cfa1","蓮連錬呂魯櫓炉賂路露労婁廊弄朗楼榔浪漏牢狼篭老聾蝋郎六麓禄肋録論倭和話歪賄脇惑枠鷲亙亘鰐詫藁蕨椀湾碗腕"],["d0a1","弌丐丕个丱丶丼丿乂乖乘亂亅豫亊舒弍于亞亟亠亢亰亳亶从仍仄仆仂仗仞仭仟价伉佚估佛佝佗佇佶侈侏侘佻佩佰侑佯來侖儘俔俟俎俘俛俑俚俐俤俥倚倨倔倪倥倅伜俶倡倩倬俾俯們倆偃假會偕偐偈做偖偬偸傀傚傅傴傲"],["d1a1","僉僊傳僂僖僞僥僭僣僮價僵儉儁儂儖儕儔儚儡儺儷儼儻儿兀兒兌兔兢竸兩兪兮冀冂囘册冉冏冑冓冕冖冤冦冢冩冪冫决冱冲冰况冽凅凉凛几處凩凭凰凵凾刄刋刔刎刧刪刮刳刹剏剄剋剌剞剔剪剴剩剳剿剽劍劔劒剱劈劑辨"],["d2a1","辧劬劭劼劵勁勍勗勞勣勦飭勠勳勵勸勹匆匈甸匍匐匏匕匚匣匯匱匳匸區卆卅丗卉卍凖卞卩卮夘卻卷厂厖厠厦厥厮厰厶參簒雙叟曼燮叮叨叭叺吁吽呀听吭吼吮吶吩吝呎咏呵咎呟呱呷呰咒呻咀呶咄咐咆哇咢咸咥咬哄哈咨"],["d3a1","咫哂咤咾咼哘哥哦唏唔哽哮哭哺哢唹啀啣啌售啜啅啖啗唸唳啝喙喀咯喊喟啻啾喘喞單啼喃喩喇喨嗚嗅嗟嗄嗜嗤嗔嘔嗷嘖嗾嗽嘛嗹噎噐營嘴嘶嘲嘸噫噤嘯噬噪嚆嚀嚊嚠嚔嚏嚥嚮嚶嚴囂嚼囁囃囀囈囎囑囓囗囮囹圀囿圄圉"],["d4a1","圈國圍圓團圖嗇圜圦圷圸坎圻址坏坩埀垈坡坿垉垓垠垳垤垪垰埃埆埔埒埓堊埖埣堋堙堝塲堡塢塋塰毀塒堽塹墅墹墟墫墺壞墻墸墮壅壓壑壗壙壘壥壜壤壟壯壺壹壻壼壽夂夊夐夛梦夥夬夭夲夸夾竒奕奐奎奚奘奢奠奧奬奩"],["d5a1","奸妁妝佞侫妣妲姆姨姜妍姙姚娥娟娑娜娉娚婀婬婉娵娶婢婪媚媼媾嫋嫂媽嫣嫗嫦嫩嫖嫺嫻嬌嬋嬖嬲嫐嬪嬶嬾孃孅孀孑孕孚孛孥孩孰孳孵學斈孺宀它宦宸寃寇寉寔寐寤實寢寞寥寫寰寶寳尅將專對尓尠尢尨尸尹屁屆屎屓"],["d6a1","屐屏孱屬屮乢屶屹岌岑岔妛岫岻岶岼岷峅岾峇峙峩峽峺峭嶌峪崋崕崗嵜崟崛崑崔崢崚崙崘嵌嵒嵎嵋嵬嵳嵶嶇嶄嶂嶢嶝嶬嶮嶽嶐嶷嶼巉巍巓巒巖巛巫已巵帋帚帙帑帛帶帷幄幃幀幎幗幔幟幢幤幇幵并幺麼广庠廁廂廈廐廏"],["d7a1","廖廣廝廚廛廢廡廨廩廬廱廳廰廴廸廾弃弉彝彜弋弑弖弩弭弸彁彈彌彎弯彑彖彗彙彡彭彳彷徃徂彿徊很徑徇從徙徘徠徨徭徼忖忻忤忸忱忝悳忿怡恠怙怐怩怎怱怛怕怫怦怏怺恚恁恪恷恟恊恆恍恣恃恤恂恬恫恙悁悍惧悃悚"],["d8a1","悄悛悖悗悒悧悋惡悸惠惓悴忰悽惆悵惘慍愕愆惶惷愀惴惺愃愡惻惱愍愎慇愾愨愧慊愿愼愬愴愽慂慄慳慷慘慙慚慫慴慯慥慱慟慝慓慵憙憖憇憬憔憚憊憑憫憮懌懊應懷懈懃懆憺懋罹懍懦懣懶懺懴懿懽懼懾戀戈戉戍戌戔戛"],["d9a1","戞戡截戮戰戲戳扁扎扞扣扛扠扨扼抂抉找抒抓抖拔抃抔拗拑抻拏拿拆擔拈拜拌拊拂拇抛拉挌拮拱挧挂挈拯拵捐挾捍搜捏掖掎掀掫捶掣掏掉掟掵捫捩掾揩揀揆揣揉插揶揄搖搴搆搓搦搶攝搗搨搏摧摯摶摎攪撕撓撥撩撈撼"],["daa1","據擒擅擇撻擘擂擱擧舉擠擡抬擣擯攬擶擴擲擺攀擽攘攜攅攤攣攫攴攵攷收攸畋效敖敕敍敘敞敝敲數斂斃變斛斟斫斷旃旆旁旄旌旒旛旙无旡旱杲昊昃旻杳昵昶昴昜晏晄晉晁晞晝晤晧晨晟晢晰暃暈暎暉暄暘暝曁暹曉暾暼"],["dba1","曄暸曖曚曠昿曦曩曰曵曷朏朖朞朦朧霸朮朿朶杁朸朷杆杞杠杙杣杤枉杰枩杼杪枌枋枦枡枅枷柯枴柬枳柩枸柤柞柝柢柮枹柎柆柧檜栞框栩桀桍栲桎梳栫桙档桷桿梟梏梭梔條梛梃檮梹桴梵梠梺椏梍桾椁棊椈棘椢椦棡椌棍"],["dca1","棔棧棕椶椒椄棗棣椥棹棠棯椨椪椚椣椡棆楹楷楜楸楫楔楾楮椹楴椽楙椰楡楞楝榁楪榲榮槐榿槁槓榾槎寨槊槝榻槃榧樮榑榠榜榕榴槞槨樂樛槿權槹槲槧樅榱樞槭樔槫樊樒櫁樣樓橄樌橲樶橸橇橢橙橦橈樸樢檐檍檠檄檢檣"],["dda1","檗蘗檻櫃櫂檸檳檬櫞櫑櫟檪櫚櫪櫻欅蘖櫺欒欖鬱欟欸欷盜欹飮歇歃歉歐歙歔歛歟歡歸歹歿殀殄殃殍殘殕殞殤殪殫殯殲殱殳殷殼毆毋毓毟毬毫毳毯麾氈氓气氛氤氣汞汕汢汪沂沍沚沁沛汾汨汳沒沐泄泱泓沽泗泅泝沮沱沾"],["dea1","沺泛泯泙泪洟衍洶洫洽洸洙洵洳洒洌浣涓浤浚浹浙涎涕濤涅淹渕渊涵淇淦涸淆淬淞淌淨淒淅淺淙淤淕淪淮渭湮渮渙湲湟渾渣湫渫湶湍渟湃渺湎渤滿渝游溂溪溘滉溷滓溽溯滄溲滔滕溏溥滂溟潁漑灌滬滸滾漿滲漱滯漲滌"],["dfa1","漾漓滷澆潺潸澁澀潯潛濳潭澂潼潘澎澑濂潦澳澣澡澤澹濆澪濟濕濬濔濘濱濮濛瀉瀋濺瀑瀁瀏濾瀛瀚潴瀝瀘瀟瀰瀾瀲灑灣炙炒炯烱炬炸炳炮烟烋烝烙焉烽焜焙煥煕熈煦煢煌煖煬熏燻熄熕熨熬燗熹熾燒燉燔燎燠燬燧燵燼"],["e0a1","燹燿爍爐爛爨爭爬爰爲爻爼爿牀牆牋牘牴牾犂犁犇犒犖犢犧犹犲狃狆狄狎狒狢狠狡狹狷倏猗猊猜猖猝猴猯猩猥猾獎獏默獗獪獨獰獸獵獻獺珈玳珎玻珀珥珮珞璢琅瑯琥珸琲琺瑕琿瑟瑙瑁瑜瑩瑰瑣瑪瑶瑾璋璞璧瓊瓏瓔珱"],["e1a1","瓠瓣瓧瓩瓮瓲瓰瓱瓸瓷甄甃甅甌甎甍甕甓甞甦甬甼畄畍畊畉畛畆畚畩畤畧畫畭畸當疆疇畴疊疉疂疔疚疝疥疣痂疳痃疵疽疸疼疱痍痊痒痙痣痞痾痿痼瘁痰痺痲痳瘋瘍瘉瘟瘧瘠瘡瘢瘤瘴瘰瘻癇癈癆癜癘癡癢癨癩癪癧癬癰"],["e2a1","癲癶癸發皀皃皈皋皎皖皓皙皚皰皴皸皹皺盂盍盖盒盞盡盥盧盪蘯盻眈眇眄眩眤眞眥眦眛眷眸睇睚睨睫睛睥睿睾睹瞎瞋瞑瞠瞞瞰瞶瞹瞿瞼瞽瞻矇矍矗矚矜矣矮矼砌砒礦砠礪硅碎硴碆硼碚碌碣碵碪碯磑磆磋磔碾碼磅磊磬"],["e3a1","磧磚磽磴礇礒礑礙礬礫祀祠祗祟祚祕祓祺祿禊禝禧齋禪禮禳禹禺秉秕秧秬秡秣稈稍稘稙稠稟禀稱稻稾稷穃穗穉穡穢穩龝穰穹穽窈窗窕窘窖窩竈窰窶竅竄窿邃竇竊竍竏竕竓站竚竝竡竢竦竭竰笂笏笊笆笳笘笙笞笵笨笶筐"],["e4a1","筺笄筍笋筌筅筵筥筴筧筰筱筬筮箝箘箟箍箜箚箋箒箏筝箙篋篁篌篏箴篆篝篩簑簔篦篥籠簀簇簓篳篷簗簍篶簣簧簪簟簷簫簽籌籃籔籏籀籐籘籟籤籖籥籬籵粃粐粤粭粢粫粡粨粳粲粱粮粹粽糀糅糂糘糒糜糢鬻糯糲糴糶糺紆"],["e5a1","紂紜紕紊絅絋紮紲紿紵絆絳絖絎絲絨絮絏絣經綉絛綏絽綛綺綮綣綵緇綽綫總綢綯緜綸綟綰緘緝緤緞緻緲緡縅縊縣縡縒縱縟縉縋縢繆繦縻縵縹繃縷縲縺繧繝繖繞繙繚繹繪繩繼繻纃緕繽辮繿纈纉續纒纐纓纔纖纎纛纜缸缺"],["e6a1","罅罌罍罎罐网罕罔罘罟罠罨罩罧罸羂羆羃羈羇羌羔羞羝羚羣羯羲羹羮羶羸譱翅翆翊翕翔翡翦翩翳翹飜耆耄耋耒耘耙耜耡耨耿耻聊聆聒聘聚聟聢聨聳聲聰聶聹聽聿肄肆肅肛肓肚肭冐肬胛胥胙胝胄胚胖脉胯胱脛脩脣脯腋"],["e7a1","隋腆脾腓腑胼腱腮腥腦腴膃膈膊膀膂膠膕膤膣腟膓膩膰膵膾膸膽臀臂膺臉臍臑臙臘臈臚臟臠臧臺臻臾舁舂舅與舊舍舐舖舩舫舸舳艀艙艘艝艚艟艤艢艨艪艫舮艱艷艸艾芍芒芫芟芻芬苡苣苟苒苴苳苺莓范苻苹苞茆苜茉苙"],["e8a1","茵茴茖茲茱荀茹荐荅茯茫茗茘莅莚莪莟莢莖茣莎莇莊荼莵荳荵莠莉莨菴萓菫菎菽萃菘萋菁菷萇菠菲萍萢萠莽萸蔆菻葭萪萼蕚蒄葷葫蒭葮蒂葩葆萬葯葹萵蓊葢蒹蒿蒟蓙蓍蒻蓚蓐蓁蓆蓖蒡蔡蓿蓴蔗蔘蔬蔟蔕蔔蓼蕀蕣蕘蕈"],["e9a1","蕁蘂蕋蕕薀薤薈薑薊薨蕭薔薛藪薇薜蕷蕾薐藉薺藏薹藐藕藝藥藜藹蘊蘓蘋藾藺蘆蘢蘚蘰蘿虍乕虔號虧虱蚓蚣蚩蚪蚋蚌蚶蚯蛄蛆蚰蛉蠣蚫蛔蛞蛩蛬蛟蛛蛯蜒蜆蜈蜀蜃蛻蜑蜉蜍蛹蜊蜴蜿蜷蜻蜥蜩蜚蝠蝟蝸蝌蝎蝴蝗蝨蝮蝙"],["eaa1","蝓蝣蝪蠅螢螟螂螯蟋螽蟀蟐雖螫蟄螳蟇蟆螻蟯蟲蟠蠏蠍蟾蟶蟷蠎蟒蠑蠖蠕蠢蠡蠱蠶蠹蠧蠻衄衂衒衙衞衢衫袁衾袞衵衽袵衲袂袗袒袮袙袢袍袤袰袿袱裃裄裔裘裙裝裹褂裼裴裨裲褄褌褊褓襃褞褥褪褫襁襄褻褶褸襌褝襠襞"],["eba1","襦襤襭襪襯襴襷襾覃覈覊覓覘覡覩覦覬覯覲覺覽覿觀觚觜觝觧觴觸訃訖訐訌訛訝訥訶詁詛詒詆詈詼詭詬詢誅誂誄誨誡誑誥誦誚誣諄諍諂諚諫諳諧諤諱謔諠諢諷諞諛謌謇謚諡謖謐謗謠謳鞫謦謫謾謨譁譌譏譎證譖譛譚譫"],["eca1","譟譬譯譴譽讀讌讎讒讓讖讙讚谺豁谿豈豌豎豐豕豢豬豸豺貂貉貅貊貍貎貔豼貘戝貭貪貽貲貳貮貶賈賁賤賣賚賽賺賻贄贅贊贇贏贍贐齎贓賍贔贖赧赭赱赳趁趙跂趾趺跏跚跖跌跛跋跪跫跟跣跼踈踉跿踝踞踐踟蹂踵踰踴蹊"],["eda1","蹇蹉蹌蹐蹈蹙蹤蹠踪蹣蹕蹶蹲蹼躁躇躅躄躋躊躓躑躔躙躪躡躬躰軆躱躾軅軈軋軛軣軼軻軫軾輊輅輕輒輙輓輜輟輛輌輦輳輻輹轅轂輾轌轉轆轎轗轜轢轣轤辜辟辣辭辯辷迚迥迢迪迯邇迴逅迹迺逑逕逡逍逞逖逋逧逶逵逹迸"],["eea1","遏遐遑遒逎遉逾遖遘遞遨遯遶隨遲邂遽邁邀邊邉邏邨邯邱邵郢郤扈郛鄂鄒鄙鄲鄰酊酖酘酣酥酩酳酲醋醉醂醢醫醯醪醵醴醺釀釁釉釋釐釖釟釡釛釼釵釶鈞釿鈔鈬鈕鈑鉞鉗鉅鉉鉤鉈銕鈿鉋鉐銜銖銓銛鉚鋏銹銷鋩錏鋺鍄錮"],["efa1","錙錢錚錣錺錵錻鍜鍠鍼鍮鍖鎰鎬鎭鎔鎹鏖鏗鏨鏥鏘鏃鏝鏐鏈鏤鐚鐔鐓鐃鐇鐐鐶鐫鐵鐡鐺鑁鑒鑄鑛鑠鑢鑞鑪鈩鑰鑵鑷鑽鑚鑼鑾钁鑿閂閇閊閔閖閘閙閠閨閧閭閼閻閹閾闊濶闃闍闌闕闔闖關闡闥闢阡阨阮阯陂陌陏陋陷陜陞"],["f0a1","陝陟陦陲陬隍隘隕隗險隧隱隲隰隴隶隸隹雎雋雉雍襍雜霍雕雹霄霆霈霓霎霑霏霖霙霤霪霰霹霽霾靄靆靈靂靉靜靠靤靦靨勒靫靱靹鞅靼鞁靺鞆鞋鞏鞐鞜鞨鞦鞣鞳鞴韃韆韈韋韜韭齏韲竟韶韵頏頌頸頤頡頷頽顆顏顋顫顯顰"],["f1a1","顱顴顳颪颯颱颶飄飃飆飩飫餃餉餒餔餘餡餝餞餤餠餬餮餽餾饂饉饅饐饋饑饒饌饕馗馘馥馭馮馼駟駛駝駘駑駭駮駱駲駻駸騁騏騅駢騙騫騷驅驂驀驃騾驕驍驛驗驟驢驥驤驩驫驪骭骰骼髀髏髑髓體髞髟髢髣髦髯髫髮髴髱髷"],["f2a1","髻鬆鬘鬚鬟鬢鬣鬥鬧鬨鬩鬪鬮鬯鬲魄魃魏魍魎魑魘魴鮓鮃鮑鮖鮗鮟鮠鮨鮴鯀鯊鮹鯆鯏鯑鯒鯣鯢鯤鯔鯡鰺鯲鯱鯰鰕鰔鰉鰓鰌鰆鰈鰒鰊鰄鰮鰛鰥鰤鰡鰰鱇鰲鱆鰾鱚鱠鱧鱶鱸鳧鳬鳰鴉鴈鳫鴃鴆鴪鴦鶯鴣鴟鵄鴕鴒鵁鴿鴾鵆鵈"],["f3a1","鵝鵞鵤鵑鵐鵙鵲鶉鶇鶫鵯鵺鶚鶤鶩鶲鷄鷁鶻鶸鶺鷆鷏鷂鷙鷓鷸鷦鷭鷯鷽鸚鸛鸞鹵鹹鹽麁麈麋麌麒麕麑麝麥麩麸麪麭靡黌黎黏黐黔黜點黝黠黥黨黯黴黶黷黹黻黼黽鼇鼈皷鼕鼡鼬鼾齊齒齔齣齟齠齡齦齧齬齪齷齲齶龕龜龠"],["f4a1","堯槇遙瑤凜熙"],["f9a1","纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德"],["faa1","忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱"],["fba1","犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚"],["fca1","釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"],["fcf1","ⅰ",9,"￢￤＇＂"],["8fa2af","˘ˇ¸˙˝¯˛˚～΄΅"],["8fa2c2","¡¦¿"],["8fa2eb","ºª©®™¤№"],["8fa6e1","ΆΈΉΊΪ"],["8fa6e7","Ό"],["8fa6e9","ΎΫ"],["8fa6ec","Ώ"],["8fa6f1","άέήίϊΐόςύϋΰώ"],["8fa7c2","Ђ",10,"ЎЏ"],["8fa7f2","ђ",10,"ўџ"],["8fa9a1","ÆĐ"],["8fa9a4","Ħ"],["8fa9a6","Ĳ"],["8fa9a8","ŁĿ"],["8fa9ab","ŊØŒ"],["8fa9af","ŦÞ"],["8fa9c1","æđðħıĳĸłŀŉŋøœßŧþ"],["8faaa1","ÁÀÄÂĂǍĀĄÅÃĆĈČÇĊĎÉÈËÊĚĖĒĘ"],["8faaba","ĜĞĢĠĤÍÌÏÎǏİĪĮĨĴĶĹĽĻŃŇŅÑÓÒÖÔǑŐŌÕŔŘŖŚŜŠŞŤŢÚÙÜÛŬǓŰŪŲŮŨǗǛǙǕŴÝŸŶŹŽŻ"],["8faba1","áàäâăǎāąåãćĉčçċďéèëêěėēęǵĝğ"],["8fabbd","ġĥíìïîǐ"],["8fabc5","īįĩĵķĺľļńňņñóòöôǒőōõŕřŗśŝšşťţúùüûŭǔűūųůũǘǜǚǖŵýÿŷźžż"],["8fb0a1","丂丄丅丌丒丟丣两丨丫丮丯丰丵乀乁乄乇乑乚乜乣乨乩乴乵乹乿亍亖亗亝亯亹仃仐仚仛仠仡仢仨仯仱仳仵份仾仿伀伂伃伈伋伌伒伕伖众伙伮伱你伳伵伷伹伻伾佀佂佈佉佋佌佒佔佖佘佟佣佪佬佮佱佷佸佹佺佽佾侁侂侄"],["8fb1a1","侅侉侊侌侎侐侒侓侔侗侙侚侞侟侲侷侹侻侼侽侾俀俁俅俆俈俉俋俌俍俏俒俜俠俢俰俲俼俽俿倀倁倄倇倊倌倎倐倓倗倘倛倜倝倞倢倧倮倰倲倳倵偀偁偂偅偆偊偌偎偑偒偓偗偙偟偠偢偣偦偧偪偭偰偱倻傁傃傄傆傊傎傏傐"],["8fb2a1","傒傓傔傖傛傜傞",4,"傪傯傰傹傺傽僀僃僄僇僌僎僐僓僔僘僜僝僟僢僤僦僨僩僯僱僶僺僾儃儆儇儈儋儌儍儎僲儐儗儙儛儜儝儞儣儧儨儬儭儯儱儳儴儵儸儹兂兊兏兓兕兗兘兟兤兦兾冃冄冋冎冘冝冡冣冭冸冺冼冾冿凂"],["8fb3a1","凈减凑凒凓凕凘凞凢凥凮凲凳凴凷刁刂刅划刓刕刖刘刢刨刱刲刵刼剅剉剕剗剘剚剜剟剠剡剦剮剷剸剹劀劂劅劊劌劓劕劖劗劘劚劜劤劥劦劧劯劰劶劷劸劺劻劽勀勄勆勈勌勏勑勔勖勛勜勡勥勨勩勪勬勰勱勴勶勷匀匃匊匋"],["8fb4a1","匌匑匓匘匛匜匞匟匥匧匨匩匫匬匭匰匲匵匼匽匾卂卌卋卙卛卡卣卥卬卭卲卹卾厃厇厈厎厓厔厙厝厡厤厪厫厯厲厴厵厷厸厺厽叀叅叏叒叓叕叚叝叞叠另叧叵吂吓吚吡吧吨吪启吱吴吵呃呄呇呍呏呞呢呤呦呧呩呫呭呮呴呿"],["8fb5a1","咁咃咅咈咉咍咑咕咖咜咟咡咦咧咩咪咭咮咱咷咹咺咻咿哆哊响哎哠哪哬哯哶哼哾哿唀唁唅唈唉唌唍唎唕唪唫唲唵唶唻唼唽啁啇啉啊啍啐啑啘啚啛啞啠啡啤啦啿喁喂喆喈喎喏喑喒喓喔喗喣喤喭喲喿嗁嗃嗆嗉嗋嗌嗎嗑嗒"],["8fb6a1","嗓嗗嗘嗛嗞嗢嗩嗶嗿嘅嘈嘊嘍",5,"嘙嘬嘰嘳嘵嘷嘹嘻嘼嘽嘿噀噁噃噄噆噉噋噍噏噔噞噠噡噢噣噦噩噭噯噱噲噵嚄嚅嚈嚋嚌嚕嚙嚚嚝嚞嚟嚦嚧嚨嚩嚫嚬嚭嚱嚳嚷嚾囅囉囊囋囏囐囌囍囙囜囝囟囡囤",4,"囱囫园"],["8fb7a1","囶囷圁圂圇圊圌圑圕圚圛圝圠圢圣圤圥圩圪圬圮圯圳圴圽圾圿坅坆坌坍坒坢坥坧坨坫坭",4,"坳坴坵坷坹坺坻坼坾垁垃垌垔垗垙垚垜垝垞垟垡垕垧垨垩垬垸垽埇埈埌埏埕埝埞埤埦埧埩埭埰埵埶埸埽埾埿堃堄堈堉埡"],["8fb8a1","堌堍堛堞堟堠堦堧堭堲堹堿塉塌塍塏塐塕塟塡塤塧塨塸塼塿墀墁墇墈墉墊墌墍墏墐墔墖墝墠墡墢墦墩墱墲壄墼壂壈壍壎壐壒壔壖壚壝壡壢壩壳夅夆夋夌夒夓夔虁夝夡夣夤夨夯夰夳夵夶夿奃奆奒奓奙奛奝奞奟奡奣奫奭"],["8fb9a1","奯奲奵奶她奻奼妋妌妎妒妕妗妟妤妧妭妮妯妰妳妷妺妼姁姃姄姈姊姍姒姝姞姟姣姤姧姮姯姱姲姴姷娀娄娌娍娎娒娓娞娣娤娧娨娪娭娰婄婅婇婈婌婐婕婞婣婥婧婭婷婺婻婾媋媐媓媖媙媜媞媟媠媢媧媬媱媲媳媵媸媺媻媿"],["8fbaa1","嫄嫆嫈嫏嫚嫜嫠嫥嫪嫮嫵嫶嫽嬀嬁嬈嬗嬴嬙嬛嬝嬡嬥嬭嬸孁孋孌孒孖孞孨孮孯孼孽孾孿宁宄宆宊宎宐宑宓宔宖宨宩宬宭宯宱宲宷宺宼寀寁寍寏寖",4,"寠寯寱寴寽尌尗尞尟尣尦尩尫尬尮尰尲尵尶屙屚屜屢屣屧屨屩"],["8fbba1","屭屰屴屵屺屻屼屽岇岈岊岏岒岝岟岠岢岣岦岪岲岴岵岺峉峋峒峝峗峮峱峲峴崁崆崍崒崫崣崤崦崧崱崴崹崽崿嵂嵃嵆嵈嵕嵑嵙嵊嵟嵠嵡嵢嵤嵪嵭嵰嵹嵺嵾嵿嶁嶃嶈嶊嶒嶓嶔嶕嶙嶛嶟嶠嶧嶫嶰嶴嶸嶹巃巇巋巐巎巘巙巠巤"],["8fbca1","巩巸巹帀帇帍帒帔帕帘帟帠帮帨帲帵帾幋幐幉幑幖幘幛幜幞幨幪",4,"幰庀庋庎庢庤庥庨庪庬庱庳庽庾庿廆廌廋廎廑廒廔廕廜廞廥廫异弆弇弈弎弙弜弝弡弢弣弤弨弫弬弮弰弴弶弻弽弿彀彄彅彇彍彐彔彘彛彠彣彤彧"],["8fbda1","彯彲彴彵彸彺彽彾徉徍徏徖徜徝徢徧徫徤徬徯徰徱徸忄忇忈忉忋忐",4,"忞忡忢忨忩忪忬忭忮忯忲忳忶忺忼怇怊怍怓怔怗怘怚怟怤怭怳怵恀恇恈恉恌恑恔恖恗恝恡恧恱恾恿悂悆悈悊悎悑悓悕悘悝悞悢悤悥您悰悱悷"],["8fbea1","悻悾惂惄惈惉惊惋惎惏惔惕惙惛惝惞惢惥惲惵惸惼惽愂愇愊愌愐",4,"愖愗愙愜愞愢愪愫愰愱愵愶愷愹慁慅慆慉慞慠慬慲慸慻慼慿憀憁憃憄憋憍憒憓憗憘憜憝憟憠憥憨憪憭憸憹憼懀懁懂懎懏懕懜懝懞懟懡懢懧懩懥"],["8fbfa1","懬懭懯戁戃戄戇戓戕戜戠戢戣戧戩戫戹戽扂扃扄扆扌扐扑扒扔扖扚扜扤扭扯扳扺扽抍抎抏抐抦抨抳抶抷抺抾抿拄拎拕拖拚拪拲拴拼拽挃挄挊挋挍挐挓挖挘挩挪挭挵挶挹挼捁捂捃捄捆捊捋捎捒捓捔捘捛捥捦捬捭捱捴捵"],["8fc0a1","捸捼捽捿掂掄掇掊掐掔掕掙掚掞掤掦掭掮掯掽揁揅揈揎揑揓揔揕揜揠揥揪揬揲揳揵揸揹搉搊搐搒搔搘搞搠搢搤搥搩搪搯搰搵搽搿摋摏摑摒摓摔摚摛摜摝摟摠摡摣摭摳摴摻摽撅撇撏撐撑撘撙撛撝撟撡撣撦撨撬撳撽撾撿"],["8fc1a1","擄擉擊擋擌擎擐擑擕擗擤擥擩擪擭擰擵擷擻擿攁攄攈攉攊攏攓攔攖攙攛攞攟攢攦攩攮攱攺攼攽敃敇敉敐敒敔敟敠敧敫敺敽斁斅斊斒斕斘斝斠斣斦斮斲斳斴斿旂旈旉旎旐旔旖旘旟旰旲旴旵旹旾旿昀昄昈昉昍昑昒昕昖昝"],["8fc2a1","昞昡昢昣昤昦昩昪昫昬昮昰昱昳昹昷晀晅晆晊晌晑晎晗晘晙晛晜晠晡曻晪晫晬晾晳晵晿晷晸晹晻暀晼暋暌暍暐暒暙暚暛暜暟暠暤暭暱暲暵暻暿曀曂曃曈曌曎曏曔曛曟曨曫曬曮曺朅朇朎朓朙朜朠朢朳朾杅杇杈杌杔杕杝"],["8fc3a1","杦杬杮杴杶杻极构枎枏枑枓枖枘枙枛枰枱枲枵枻枼枽柹柀柂柃柅柈柉柒柗柙柜柡柦柰柲柶柷桒栔栙栝栟栨栧栬栭栯栰栱栳栻栿桄桅桊桌桕桗桘桛桫桮",4,"桵桹桺桻桼梂梄梆梈梖梘梚梜梡梣梥梩梪梮梲梻棅棈棌棏"],["8fc4a1","棐棑棓棖棙棜棝棥棨棪棫棬棭棰棱棵棶棻棼棽椆椉椊椐椑椓椖椗椱椳椵椸椻楂楅楉楎楗楛楣楤楥楦楨楩楬楰楱楲楺楻楿榀榍榒榖榘榡榥榦榨榫榭榯榷榸榺榼槅槈槑槖槗槢槥槮槯槱槳槵槾樀樁樃樏樑樕樚樝樠樤樨樰樲"],["8fc5a1","樴樷樻樾樿橅橆橉橊橎橐橑橒橕橖橛橤橧橪橱橳橾檁檃檆檇檉檋檑檛檝檞檟檥檫檯檰檱檴檽檾檿櫆櫉櫈櫌櫐櫔櫕櫖櫜櫝櫤櫧櫬櫰櫱櫲櫼櫽欂欃欆欇欉欏欐欑欗欛欞欤欨欫欬欯欵欶欻欿歆歊歍歒歖歘歝歠歧歫歮歰歵歽"],["8fc6a1","歾殂殅殗殛殟殠殢殣殨殩殬殭殮殰殸殹殽殾毃毄毉毌毖毚毡毣毦毧毮毱毷毹毿氂氄氅氉氍氎氐氒氙氟氦氧氨氬氮氳氵氶氺氻氿汊汋汍汏汒汔汙汛汜汫汭汯汴汶汸汹汻沅沆沇沉沔沕沗沘沜沟沰沲沴泂泆泍泏泐泑泒泔泖"],["8fc7a1","泚泜泠泧泩泫泬泮泲泴洄洇洊洎洏洑洓洚洦洧洨汧洮洯洱洹洼洿浗浞浟浡浥浧浯浰浼涂涇涑涒涔涖涗涘涪涬涴涷涹涽涿淄淈淊淎淏淖淛淝淟淠淢淥淩淯淰淴淶淼渀渄渞渢渧渲渶渹渻渼湄湅湈湉湋湏湑湒湓湔湗湜湝湞"],["8fc8a1","湢湣湨湳湻湽溍溓溙溠溧溭溮溱溳溻溿滀滁滃滇滈滊滍滎滏滫滭滮滹滻滽漄漈漊漌漍漖漘漚漛漦漩漪漯漰漳漶漻漼漭潏潑潒潓潗潙潚潝潞潡潢潨潬潽潾澃澇澈澋澌澍澐澒澓澔澖澚澟澠澥澦澧澨澮澯澰澵澶澼濅濇濈濊"],["8fc9a1","濚濞濨濩濰濵濹濼濽瀀瀅瀆瀇瀍瀗瀠瀣瀯瀴瀷瀹瀼灃灄灈灉灊灋灔灕灝灞灎灤灥灬灮灵灶灾炁炅炆炔",4,"炛炤炫炰炱炴炷烊烑烓烔烕烖烘烜烤烺焃",4,"焋焌焏焞焠焫焭焯焰焱焸煁煅煆煇煊煋煐煒煗煚煜煞煠"],["8fcaa1","煨煹熀熅熇熌熒熚熛熠熢熯熰熲熳熺熿燀燁燄燋燌燓燖燙燚燜燸燾爀爇爈爉爓爗爚爝爟爤爫爯爴爸爹牁牂牃牅牎牏牐牓牕牖牚牜牞牠牣牨牫牮牯牱牷牸牻牼牿犄犉犍犎犓犛犨犭犮犱犴犾狁狇狉狌狕狖狘狟狥狳狴狺狻"],["8fcba1","狾猂猄猅猇猋猍猒猓猘猙猞猢猤猧猨猬猱猲猵猺猻猽獃獍獐獒獖獘獝獞獟獠獦獧獩獫獬獮獯獱獷獹獼玀玁玃玅玆玎玐玓玕玗玘玜玞玟玠玢玥玦玪玫玭玵玷玹玼玽玿珅珆珉珋珌珏珒珓珖珙珝珡珣珦珧珩珴珵珷珹珺珻珽"],["8fcca1","珿琀琁琄琇琊琑琚琛琤琦琨",9,"琹瑀瑃瑄瑆瑇瑋瑍瑑瑒瑗瑝瑢瑦瑧瑨瑫瑭瑮瑱瑲璀璁璅璆璇璉璏璐璑璒璘璙璚璜璟璠璡璣璦璨璩璪璫璮璯璱璲璵璹璻璿瓈瓉瓌瓐瓓瓘瓚瓛瓞瓟瓤瓨瓪瓫瓯瓴瓺瓻瓼瓿甆"],["8fcda1","甒甖甗甠甡甤甧甩甪甯甶甹甽甾甿畀畃畇畈畎畐畒畗畞畟畡畯畱畹",5,"疁疅疐疒疓疕疙疜疢疤疴疺疿痀痁痄痆痌痎痏痗痜痟痠痡痤痧痬痮痯痱痹瘀瘂瘃瘄瘇瘈瘊瘌瘏瘒瘓瘕瘖瘙瘛瘜瘝瘞瘣瘥瘦瘩瘭瘲瘳瘵瘸瘹"],["8fcea1","瘺瘼癊癀癁癃癄癅癉癋癕癙癟癤癥癭癮癯癱癴皁皅皌皍皕皛皜皝皟皠皢",6,"皪皭皽盁盅盉盋盌盎盔盙盠盦盨盬盰盱盶盹盼眀眆眊眎眒眔眕眗眙眚眜眢眨眭眮眯眴眵眶眹眽眾睂睅睆睊睍睎睏睒睖睗睜睞睟睠睢"],["8fcfa1","睤睧睪睬睰睲睳睴睺睽瞀瞄瞌瞍瞔瞕瞖瞚瞟瞢瞧瞪瞮瞯瞱瞵瞾矃矉矑矒矕矙矞矟矠矤矦矪矬矰矱矴矸矻砅砆砉砍砎砑砝砡砢砣砭砮砰砵砷硃硄硇硈硌硎硒硜硞硠硡硣硤硨硪确硺硾碊碏碔碘碡碝碞碟碤碨碬碭碰碱碲碳"],["8fd0a1","碻碽碿磇磈磉磌磎磒磓磕磖磤磛磟磠磡磦磪磲磳礀磶磷磺磻磿礆礌礐礚礜礞礟礠礥礧礩礭礱礴礵礻礽礿祄祅祆祊祋祏祑祔祘祛祜祧祩祫祲祹祻祼祾禋禌禑禓禔禕禖禘禛禜禡禨禩禫禯禱禴禸离秂秄秇秈秊秏秔秖秚秝秞"],["8fd1a1","秠秢秥秪秫秭秱秸秼稂稃稇稉稊稌稑稕稛稞稡稧稫稭稯稰稴稵稸稹稺穄穅穇穈穌穕穖穙穜穝穟穠穥穧穪穭穵穸穾窀窂窅窆窊窋窐窑窔窞窠窣窬窳窵窹窻窼竆竉竌竎竑竛竨竩竫竬竱竴竻竽竾笇笔笟笣笧笩笪笫笭笮笯笰"],["8fd2a1","笱笴笽笿筀筁筇筎筕筠筤筦筩筪筭筯筲筳筷箄箉箎箐箑箖箛箞箠箥箬箯箰箲箵箶箺箻箼箽篂篅篈篊篔篖篗篙篚篛篨篪篲篴篵篸篹篺篼篾簁簂簃簄簆簉簋簌簎簏簙簛簠簥簦簨簬簱簳簴簶簹簺籆籊籕籑籒籓籙",5],["8fd3a1","籡籣籧籩籭籮籰籲籹籼籽粆粇粏粔粞粠粦粰粶粷粺粻粼粿糄糇糈糉糍糏糓糔糕糗糙糚糝糦糩糫糵紃紇紈紉紏紑紒紓紖紝紞紣紦紪紭紱紼紽紾絀絁絇絈絍絑絓絗絙絚絜絝絥絧絪絰絸絺絻絿綁綂綃綅綆綈綋綌綍綑綖綗綝"],["8fd4a1","綞綦綧綪綳綶綷綹緂",4,"緌緍緎緗緙縀緢緥緦緪緫緭緱緵緶緹緺縈縐縑縕縗縜縝縠縧縨縬縭縯縳縶縿繄繅繇繎繐繒繘繟繡繢繥繫繮繯繳繸繾纁纆纇纊纍纑纕纘纚纝纞缼缻缽缾缿罃罄罇罏罒罓罛罜罝罡罣罤罥罦罭"],["8fd5a1","罱罽罾罿羀羋羍羏羐羑羖羗羜羡羢羦羪羭羴羼羿翀翃翈翎翏翛翟翣翥翨翬翮翯翲翺翽翾翿耇耈耊耍耎耏耑耓耔耖耝耞耟耠耤耦耬耮耰耴耵耷耹耺耼耾聀聄聠聤聦聭聱聵肁肈肎肜肞肦肧肫肸肹胈胍胏胒胔胕胗胘胠胭胮"],["8fd6a1","胰胲胳胶胹胺胾脃脋脖脗脘脜脞脠脤脧脬脰脵脺脼腅腇腊腌腒腗腠腡腧腨腩腭腯腷膁膐膄膅膆膋膎膖膘膛膞膢膮膲膴膻臋臃臅臊臎臏臕臗臛臝臞臡臤臫臬臰臱臲臵臶臸臹臽臿舀舃舏舓舔舙舚舝舡舢舨舲舴舺艃艄艅艆"],["8fd7a1","艋艎艏艑艖艜艠艣艧艭艴艻艽艿芀芁芃芄芇芉芊芎芑芔芖芘芚芛芠芡芣芤芧芨芩芪芮芰芲芴芷芺芼芾芿苆苐苕苚苠苢苤苨苪苭苯苶苷苽苾茀茁茇茈茊茋荔茛茝茞茟茡茢茬茭茮茰茳茷茺茼茽荂荃荄荇荍荎荑荕荖荗荰荸"],["8fd8a1","荽荿莀莂莄莆莍莒莔莕莘莙莛莜莝莦莧莩莬莾莿菀菇菉菏菐菑菔菝荓菨菪菶菸菹菼萁萆萊萏萑萕萙莭萯萹葅葇葈葊葍葏葑葒葖葘葙葚葜葠葤葥葧葪葰葳葴葶葸葼葽蒁蒅蒒蒓蒕蒞蒦蒨蒩蒪蒯蒱蒴蒺蒽蒾蓀蓂蓇蓈蓌蓏蓓"],["8fd9a1","蓜蓧蓪蓯蓰蓱蓲蓷蔲蓺蓻蓽蔂蔃蔇蔌蔎蔐蔜蔞蔢蔣蔤蔥蔧蔪蔫蔯蔳蔴蔶蔿蕆蕏",4,"蕖蕙蕜",6,"蕤蕫蕯蕹蕺蕻蕽蕿薁薅薆薉薋薌薏薓薘薝薟薠薢薥薧薴薶薷薸薼薽薾薿藂藇藊藋藎薭藘藚藟藠藦藨藭藳藶藼"],["8fdaa1","藿蘀蘄蘅蘍蘎蘐蘑蘒蘘蘙蘛蘞蘡蘧蘩蘶蘸蘺蘼蘽虀虂虆虒虓虖虗虘虙虝虠",4,"虩虬虯虵虶虷虺蚍蚑蚖蚘蚚蚜蚡蚦蚧蚨蚭蚱蚳蚴蚵蚷蚸蚹蚿蛀蛁蛃蛅蛑蛒蛕蛗蛚蛜蛠蛣蛥蛧蚈蛺蛼蛽蜄蜅蜇蜋蜎蜏蜐蜓蜔蜙蜞蜟蜡蜣"],["8fdba1","蜨蜮蜯蜱蜲蜹蜺蜼蜽蜾蝀蝃蝅蝍蝘蝝蝡蝤蝥蝯蝱蝲蝻螃",6,"螋螌螐螓螕螗螘螙螞螠螣螧螬螭螮螱螵螾螿蟁蟈蟉蟊蟎蟕蟖蟙蟚蟜蟟蟢蟣蟤蟪蟫蟭蟱蟳蟸蟺蟿蠁蠃蠆蠉蠊蠋蠐蠙蠒蠓蠔蠘蠚蠛蠜蠞蠟蠨蠭蠮蠰蠲蠵"],["8fdca1","蠺蠼衁衃衅衈衉衊衋衎衑衕衖衘衚衜衟衠衤衩衱衹衻袀袘袚袛袜袟袠袨袪袺袽袾裀裊",4,"裑裒裓裛裞裧裯裰裱裵裷褁褆褍褎褏褕褖褘褙褚褜褠褦褧褨褰褱褲褵褹褺褾襀襂襅襆襉襏襒襗襚襛襜襡襢襣襫襮襰襳襵襺"],["8fdda1","襻襼襽覉覍覐覔覕覛覜覟覠覥覰覴覵覶覷覼觔",4,"觥觩觫觭觱觳觶觹觽觿訄訅訇訏訑訒訔訕訞訠訢訤訦訫訬訯訵訷訽訾詀詃詅詇詉詍詎詓詖詗詘詜詝詡詥詧詵詶詷詹詺詻詾詿誀誃誆誋誏誐誒誖誗誙誟誧誩誮誯誳"],["8fdea1","誶誷誻誾諃諆諈諉諊諑諓諔諕諗諝諟諬諰諴諵諶諼諿謅謆謋謑謜謞謟謊謭謰謷謼譂",4,"譈譒譓譔譙譍譞譣譭譶譸譹譼譾讁讄讅讋讍讏讔讕讜讞讟谸谹谽谾豅豇豉豋豏豑豓豔豗豘豛豝豙豣豤豦豨豩豭豳豵豶豻豾貆"],["8fdfa1","貇貋貐貒貓貙貛貜貤貹貺賅賆賉賋賏賖賕賙賝賡賨賬賯賰賲賵賷賸賾賿贁贃贉贒贗贛赥赩赬赮赿趂趄趈趍趐趑趕趞趟趠趦趫趬趯趲趵趷趹趻跀跅跆跇跈跊跎跑跔跕跗跙跤跥跧跬跰趼跱跲跴跽踁踄踅踆踋踑踔踖踠踡踢"],["8fe0a1","踣踦踧踱踳踶踷踸踹踽蹀蹁蹋蹍蹎蹏蹔蹛蹜蹝蹞蹡蹢蹩蹬蹭蹯蹰蹱蹹蹺蹻躂躃躉躐躒躕躚躛躝躞躢躧躩躭躮躳躵躺躻軀軁軃軄軇軏軑軔軜軨軮軰軱軷軹軺軭輀輂輇輈輏輐輖輗輘輞輠輡輣輥輧輨輬輭輮輴輵輶輷輺轀轁"],["8fe1a1","轃轇轏轑",4,"轘轝轞轥辝辠辡辤辥辦辵辶辸达迀迁迆迊迋迍运迒迓迕迠迣迤迨迮迱迵迶迻迾适逄逈逌逘逛逨逩逯逪逬逭逳逴逷逿遃遄遌遛遝遢遦遧遬遰遴遹邅邈邋邌邎邐邕邗邘邙邛邠邡邢邥邰邲邳邴邶邽郌邾郃"],["8fe2a1","郄郅郇郈郕郗郘郙郜郝郟郥郒郶郫郯郰郴郾郿鄀鄄鄅鄆鄈鄍鄐鄔鄖鄗鄘鄚鄜鄞鄠鄥鄢鄣鄧鄩鄮鄯鄱鄴鄶鄷鄹鄺鄼鄽酃酇酈酏酓酗酙酚酛酡酤酧酭酴酹酺酻醁醃醅醆醊醎醑醓醔醕醘醞醡醦醨醬醭醮醰醱醲醳醶醻醼醽醿"],["8fe3a1","釂釃釅釓釔釗釙釚釞釤釥釩釪釬",5,"釷釹釻釽鈀鈁鈄鈅鈆鈇鈉鈊鈌鈐鈒鈓鈖鈘鈜鈝鈣鈤鈥鈦鈨鈮鈯鈰鈳鈵鈶鈸鈹鈺鈼鈾鉀鉂鉃鉆鉇鉊鉍鉎鉏鉑鉘鉙鉜鉝鉠鉡鉥鉧鉨鉩鉮鉯鉰鉵",4,"鉻鉼鉽鉿銈銉銊銍銎銒銗"],["8fe4a1","銙銟銠銤銥銧銨銫銯銲銶銸銺銻銼銽銿",4,"鋅鋆鋇鋈鋋鋌鋍鋎鋐鋓鋕鋗鋘鋙鋜鋝鋟鋠鋡鋣鋥鋧鋨鋬鋮鋰鋹鋻鋿錀錂錈錍錑錔錕錜錝錞錟錡錤錥錧錩錪錳錴錶錷鍇鍈鍉鍐鍑鍒鍕鍗鍘鍚鍞鍤鍥鍧鍩鍪鍭鍯鍰鍱鍳鍴鍶"],["8fe5a1","鍺鍽鍿鎀鎁鎂鎈鎊鎋鎍鎏鎒鎕鎘鎛鎞鎡鎣鎤鎦鎨鎫鎴鎵鎶鎺鎩鏁鏄鏅鏆鏇鏉",4,"鏓鏙鏜鏞鏟鏢鏦鏧鏹鏷鏸鏺鏻鏽鐁鐂鐄鐈鐉鐍鐎鐏鐕鐖鐗鐟鐮鐯鐱鐲鐳鐴鐻鐿鐽鑃鑅鑈鑊鑌鑕鑙鑜鑟鑡鑣鑨鑫鑭鑮鑯鑱鑲钄钃镸镹"],["8fe6a1","镾閄閈閌閍閎閝閞閟閡閦閩閫閬閴閶閺閽閿闆闈闉闋闐闑闒闓闙闚闝闞闟闠闤闦阝阞阢阤阥阦阬阱阳阷阸阹阺阼阽陁陒陔陖陗陘陡陮陴陻陼陾陿隁隂隃隄隉隑隖隚隝隟隤隥隦隩隮隯隳隺雊雒嶲雘雚雝雞雟雩雯雱雺霂"],["8fe7a1","霃霅霉霚霛霝霡霢霣霨霱霳靁靃靊靎靏靕靗靘靚靛靣靧靪靮靳靶靷靸靻靽靿鞀鞉鞕鞖鞗鞙鞚鞞鞟鞢鞬鞮鞱鞲鞵鞶鞸鞹鞺鞼鞾鞿韁韄韅韇韉韊韌韍韎韐韑韔韗韘韙韝韞韠韛韡韤韯韱韴韷韸韺頇頊頙頍頎頔頖頜頞頠頣頦"],["8fe8a1","頫頮頯頰頲頳頵頥頾顄顇顊顑顒顓顖顗顙顚顢顣顥顦顪顬颫颭颮颰颴颷颸颺颻颿飂飅飈飌飡飣飥飦飧飪飳飶餂餇餈餑餕餖餗餚餛餜餟餢餦餧餫餱",4,"餹餺餻餼饀饁饆饇饈饍饎饔饘饙饛饜饞饟饠馛馝馟馦馰馱馲馵"],["8fe9a1","馹馺馽馿駃駉駓駔駙駚駜駞駧駪駫駬駰駴駵駹駽駾騂騃騄騋騌騐騑騖騞騠騢騣騤騧騭騮騳騵騶騸驇驁驄驊驋驌驎驑驔驖驝骪骬骮骯骲骴骵骶骹骻骾骿髁髃髆髈髎髐髒髕髖髗髛髜髠髤髥髧髩髬髲髳髵髹髺髽髿",4],["8feaa1","鬄鬅鬈鬉鬋鬌鬍鬎鬐鬒鬖鬙鬛鬜鬠鬦鬫鬭鬳鬴鬵鬷鬹鬺鬽魈魋魌魕魖魗魛魞魡魣魥魦魨魪",4,"魳魵魷魸魹魿鮀鮄鮅鮆鮇鮉鮊鮋鮍鮏鮐鮔鮚鮝鮞鮦鮧鮩鮬鮰鮱鮲鮷鮸鮻鮼鮾鮿鯁鯇鯈鯎鯐鯗鯘鯝鯟鯥鯧鯪鯫鯯鯳鯷鯸"],["8feba1","鯹鯺鯽鯿鰀鰂鰋鰏鰑鰖鰘鰙鰚鰜鰞鰢鰣鰦",4,"鰱鰵鰶鰷鰽鱁鱃鱄鱅鱉鱊鱎鱏鱐鱓鱔鱖鱘鱛鱝鱞鱟鱣鱩鱪鱜鱫鱨鱮鱰鱲鱵鱷鱻鳦鳲鳷鳹鴋鴂鴑鴗鴘鴜鴝鴞鴯鴰鴲鴳鴴鴺鴼鵅鴽鵂鵃鵇鵊鵓鵔鵟鵣鵢鵥鵩鵪鵫鵰鵶鵷鵻"],["8feca1","鵼鵾鶃鶄鶆鶊鶍鶎鶒鶓鶕鶖鶗鶘鶡鶪鶬鶮鶱鶵鶹鶼鶿鷃鷇鷉鷊鷔鷕鷖鷗鷚鷞鷟鷠鷥鷧鷩鷫鷮鷰鷳鷴鷾鸊鸂鸇鸎鸐鸑鸒鸕鸖鸙鸜鸝鹺鹻鹼麀麂麃麄麅麇麎麏麖麘麛麞麤麨麬麮麯麰麳麴麵黆黈黋黕黟黤黧黬黭黮黰黱黲黵"],["8feda1","黸黿鼂鼃鼉鼏鼐鼑鼒鼔鼖鼗鼙鼚鼛鼟鼢鼦鼪鼫鼯鼱鼲鼴鼷鼹鼺鼼鼽鼿齁齃",4,"齓齕齖齗齘齚齝齞齨齩齭",4,"齳齵齺齽龏龐龑龒龔龖龗龞龡龢龣龥"]]},48:function(e){e.exports=[["0","\0",127],["a140","　，、。．‧；：？！︰…‥﹐﹑﹒·﹔﹕﹖﹗｜–︱—︳╴︴﹏（）︵︶｛｝︷︸〔〕︹︺【】︻︼《》︽︾〈〉︿﹀「」﹁﹂『』﹃﹄﹙﹚"],["a1a1","﹛﹜﹝﹞‘’“”〝〞‵′＃＆＊※§〃○●△▲◎☆★◇◆□■▽▼㊣℅¯￣＿ˍ﹉﹊﹍﹎﹋﹌﹟﹠﹡＋－×÷±√＜＞＝≦≧≠∞≒≡﹢",4,"～∩∪⊥∠∟⊿㏒㏑∫∮∵∴♀♂⊕⊙↑↓←→↖↗↙↘∥∣／"],["a240","＼∕﹨＄￥〒￠￡％＠℃℉﹩﹪﹫㏕㎜㎝㎞㏎㎡㎎㎏㏄°兙兛兞兝兡兣嗧瓩糎▁",7,"▏▎▍▌▋▊▉┼┴┬┤├▔─│▕┌┐└┘╭"],["a2a1","╮╰╯═╞╪╡◢◣◥◤╱╲╳０",9,"Ⅰ",9,"〡",8,"十卄卅Ａ",25,"ａ",21],["a340","ｗｘｙｚΑ",16,"Σ",6,"α",16,"σ",6,"ㄅ",10],["a3a1","ㄐ",25,"˙ˉˊˇˋ"],["a3e1","€"],["a440","一乙丁七乃九了二人儿入八几刀刁力匕十卜又三下丈上丫丸凡久么也乞于亡兀刃勺千叉口土士夕大女子孑孓寸小尢尸山川工己已巳巾干廾弋弓才"],["a4a1","丑丐不中丰丹之尹予云井互五亢仁什仃仆仇仍今介仄元允內六兮公冗凶分切刈勻勾勿化匹午升卅卞厄友及反壬天夫太夭孔少尤尺屯巴幻廿弔引心戈戶手扎支文斗斤方日曰月木欠止歹毋比毛氏水火爪父爻片牙牛犬王丙"],["a540","世丕且丘主乍乏乎以付仔仕他仗代令仙仞充兄冉冊冬凹出凸刊加功包匆北匝仟半卉卡占卯卮去可古右召叮叩叨叼司叵叫另只史叱台句叭叻四囚外"],["a5a1","央失奴奶孕它尼巨巧左市布平幼弁弘弗必戊打扔扒扑斥旦朮本未末札正母民氐永汁汀氾犯玄玉瓜瓦甘生用甩田由甲申疋白皮皿目矛矢石示禾穴立丞丟乒乓乩亙交亦亥仿伉伙伊伕伍伐休伏仲件任仰仳份企伋光兇兆先全"],["a640","共再冰列刑划刎刖劣匈匡匠印危吉吏同吊吐吁吋各向名合吃后吆吒因回囝圳地在圭圬圯圩夙多夷夸妄奸妃好她如妁字存宇守宅安寺尖屹州帆并年"],["a6a1","式弛忙忖戎戌戍成扣扛托收早旨旬旭曲曳有朽朴朱朵次此死氖汝汗汙江池汐汕污汛汍汎灰牟牝百竹米糸缶羊羽老考而耒耳聿肉肋肌臣自至臼舌舛舟艮色艾虫血行衣西阡串亨位住佇佗佞伴佛何估佐佑伽伺伸佃佔似但佣"],["a740","作你伯低伶余佝佈佚兌克免兵冶冷別判利刪刨劫助努劬匣即卵吝吭吞吾否呎吧呆呃吳呈呂君吩告吹吻吸吮吵吶吠吼呀吱含吟听囪困囤囫坊坑址坍"],["a7a1","均坎圾坐坏圻壯夾妝妒妨妞妣妙妖妍妤妓妊妥孝孜孚孛完宋宏尬局屁尿尾岐岑岔岌巫希序庇床廷弄弟彤形彷役忘忌志忍忱快忸忪戒我抄抗抖技扶抉扭把扼找批扳抒扯折扮投抓抑抆改攻攸旱更束李杏材村杜杖杞杉杆杠"],["a840","杓杗步每求汞沙沁沈沉沅沛汪決沐汰沌汨沖沒汽沃汲汾汴沆汶沍沔沘沂灶灼災灸牢牡牠狄狂玖甬甫男甸皂盯矣私秀禿究系罕肖肓肝肘肛肚育良芒"],["a8a1","芋芍見角言谷豆豕貝赤走足身車辛辰迂迆迅迄巡邑邢邪邦那酉釆里防阮阱阪阬並乖乳事些亞享京佯依侍佳使佬供例來侃佰併侈佩佻侖佾侏侑佺兔兒兕兩具其典冽函刻券刷刺到刮制剁劾劻卒協卓卑卦卷卸卹取叔受味呵"],["a940","咖呸咕咀呻呷咄咒咆呼咐呱呶和咚呢周咋命咎固垃坷坪坩坡坦坤坼夜奉奇奈奄奔妾妻委妹妮姑姆姐姍始姓姊妯妳姒姅孟孤季宗定官宜宙宛尚屈居"],["a9a1","屆岷岡岸岩岫岱岳帘帚帖帕帛帑幸庚店府底庖延弦弧弩往征彿彼忝忠忽念忿怏怔怯怵怖怪怕怡性怩怫怛或戕房戾所承拉拌拄抿拂抹拒招披拓拔拋拈抨抽押拐拙拇拍抵拚抱拘拖拗拆抬拎放斧於旺昔易昌昆昂明昀昏昕昊"],["aa40","昇服朋杭枋枕東果杳杷枇枝林杯杰板枉松析杵枚枓杼杪杲欣武歧歿氓氛泣注泳沱泌泥河沽沾沼波沫法泓沸泄油況沮泗泅泱沿治泡泛泊沬泯泜泖泠"],["aaa1","炕炎炒炊炙爬爭爸版牧物狀狎狙狗狐玩玨玟玫玥甽疝疙疚的盂盲直知矽社祀祁秉秈空穹竺糾罔羌羋者肺肥肢肱股肫肩肴肪肯臥臾舍芳芝芙芭芽芟芹花芬芥芯芸芣芰芾芷虎虱初表軋迎返近邵邸邱邶采金長門阜陀阿阻附"],["ab40","陂隹雨青非亟亭亮信侵侯便俠俑俏保促侶俘俟俊俗侮俐俄係俚俎俞侷兗冒冑冠剎剃削前剌剋則勇勉勃勁匍南卻厚叛咬哀咨哎哉咸咦咳哇哂咽咪品"],["aba1","哄哈咯咫咱咻咩咧咿囿垂型垠垣垢城垮垓奕契奏奎奐姜姘姿姣姨娃姥姪姚姦威姻孩宣宦室客宥封屎屏屍屋峙峒巷帝帥帟幽庠度建弈弭彥很待徊律徇後徉怒思怠急怎怨恍恰恨恢恆恃恬恫恪恤扁拜挖按拼拭持拮拽指拱拷"],["ac40","拯括拾拴挑挂政故斫施既春昭映昧是星昨昱昤曷柿染柱柔某柬架枯柵柩柯柄柑枴柚查枸柏柞柳枰柙柢柝柒歪殃殆段毒毗氟泉洋洲洪流津洌洱洞洗"],["aca1","活洽派洶洛泵洹洧洸洩洮洵洎洫炫為炳炬炯炭炸炮炤爰牲牯牴狩狠狡玷珊玻玲珍珀玳甚甭畏界畎畋疫疤疥疢疣癸皆皇皈盈盆盃盅省盹相眉看盾盼眇矜砂研砌砍祆祉祈祇禹禺科秒秋穿突竿竽籽紂紅紀紉紇約紆缸美羿耄"],["ad40","耐耍耑耶胖胥胚胃胄背胡胛胎胞胤胝致舢苧范茅苣苛苦茄若茂茉苒苗英茁苜苔苑苞苓苟苯茆虐虹虻虺衍衫要觔計訂訃貞負赴赳趴軍軌述迦迢迪迥"],["ada1","迭迫迤迨郊郎郁郃酋酊重閂限陋陌降面革韋韭音頁風飛食首香乘亳倌倍倣俯倦倥俸倩倖倆值借倚倒們俺倀倔倨俱倡個候倘俳修倭倪俾倫倉兼冤冥冢凍凌准凋剖剜剔剛剝匪卿原厝叟哨唐唁唷哼哥哲唆哺唔哩哭員唉哮哪"],["ae40","哦唧唇哽唏圃圄埂埔埋埃堉夏套奘奚娑娘娜娟娛娓姬娠娣娩娥娌娉孫屘宰害家宴宮宵容宸射屑展屐峭峽峻峪峨峰島崁峴差席師庫庭座弱徒徑徐恙"],["aea1","恣恥恐恕恭恩息悄悟悚悍悔悌悅悖扇拳挈拿捎挾振捕捂捆捏捉挺捐挽挪挫挨捍捌效敉料旁旅時晉晏晃晒晌晅晁書朔朕朗校核案框桓根桂桔栩梳栗桌桑栽柴桐桀格桃株桅栓栘桁殊殉殷氣氧氨氦氤泰浪涕消涇浦浸海浙涓"],["af40","浬涉浮浚浴浩涌涊浹涅浥涔烊烘烤烙烈烏爹特狼狹狽狸狷玆班琉珮珠珪珞畔畝畜畚留疾病症疲疳疽疼疹痂疸皋皰益盍盎眩真眠眨矩砰砧砸砝破砷"],["afa1","砥砭砠砟砲祕祐祠祟祖神祝祗祚秤秣秧租秦秩秘窄窈站笆笑粉紡紗紋紊素索純紐紕級紜納紙紛缺罟羔翅翁耆耘耕耙耗耽耿胱脂胰脅胭胴脆胸胳脈能脊胼胯臭臬舀舐航舫舨般芻茫荒荔荊茸荐草茵茴荏茲茹茶茗荀茱茨荃"],["b040","虔蚊蚪蚓蚤蚩蚌蚣蚜衰衷袁袂衽衹記訐討訌訕訊託訓訖訏訑豈豺豹財貢起躬軒軔軏辱送逆迷退迺迴逃追逅迸邕郡郝郢酒配酌釘針釗釜釙閃院陣陡"],["b0a1","陛陝除陘陞隻飢馬骨高鬥鬲鬼乾偺偽停假偃偌做偉健偶偎偕偵側偷偏倏偯偭兜冕凰剪副勒務勘動匐匏匙匿區匾參曼商啪啦啄啞啡啃啊唱啖問啕唯啤唸售啜唬啣唳啁啗圈國圉域堅堊堆埠埤基堂堵執培夠奢娶婁婉婦婪婀"],["b140","娼婢婚婆婊孰寇寅寄寂宿密尉專將屠屜屝崇崆崎崛崖崢崑崩崔崙崤崧崗巢常帶帳帷康庸庶庵庾張強彗彬彩彫得徙從徘御徠徜恿患悉悠您惋悴惦悽"],["b1a1","情悻悵惜悼惘惕惆惟悸惚惇戚戛扈掠控捲掖探接捷捧掘措捱掩掉掃掛捫推掄授掙採掬排掏掀捻捩捨捺敝敖救教敗啟敏敘敕敔斜斛斬族旋旌旎晝晚晤晨晦晞曹勗望梁梯梢梓梵桿桶梱梧梗械梃棄梭梆梅梔條梨梟梡梂欲殺"],["b240","毫毬氫涎涼淳淙液淡淌淤添淺清淇淋涯淑涮淞淹涸混淵淅淒渚涵淚淫淘淪深淮淨淆淄涪淬涿淦烹焉焊烽烯爽牽犁猜猛猖猓猙率琅琊球理現琍瓠瓶"],["b2a1","瓷甜產略畦畢異疏痔痕疵痊痍皎盔盒盛眷眾眼眶眸眺硫硃硎祥票祭移窒窕笠笨笛第符笙笞笮粒粗粕絆絃統紮紹紼絀細紳組累終紲紱缽羞羚翌翎習耜聊聆脯脖脣脫脩脰脤舂舵舷舶船莎莞莘荸莢莖莽莫莒莊莓莉莠荷荻荼"],["b340","莆莧處彪蛇蛀蚶蛄蚵蛆蛋蚱蚯蛉術袞袈被袒袖袍袋覓規訪訝訣訥許設訟訛訢豉豚販責貫貨貪貧赧赦趾趺軛軟這逍通逗連速逝逐逕逞造透逢逖逛途"],["b3a1","部郭都酗野釵釦釣釧釭釩閉陪陵陳陸陰陴陶陷陬雀雪雩章竟頂頃魚鳥鹵鹿麥麻傢傍傅備傑傀傖傘傚最凱割剴創剩勞勝勛博厥啻喀喧啼喊喝喘喂喜喪喔喇喋喃喳單喟唾喲喚喻喬喱啾喉喫喙圍堯堪場堤堰報堡堝堠壹壺奠"],["b440","婷媚婿媒媛媧孳孱寒富寓寐尊尋就嵌嵐崴嵇巽幅帽幀幃幾廊廁廂廄弼彭復循徨惑惡悲悶惠愜愣惺愕惰惻惴慨惱愎惶愉愀愒戟扉掣掌描揀揩揉揆揍"],["b4a1","插揣提握揖揭揮捶援揪換摒揚揹敞敦敢散斑斐斯普晰晴晶景暑智晾晷曾替期朝棺棕棠棘棗椅棟棵森棧棹棒棲棣棋棍植椒椎棉棚楮棻款欺欽殘殖殼毯氮氯氬港游湔渡渲湧湊渠渥渣減湛湘渤湖湮渭渦湯渴湍渺測湃渝渾滋"],["b540","溉渙湎湣湄湲湩湟焙焚焦焰無然煮焜牌犄犀猶猥猴猩琺琪琳琢琥琵琶琴琯琛琦琨甥甦畫番痢痛痣痙痘痞痠登發皖皓皴盜睏短硝硬硯稍稈程稅稀窘"],["b5a1","窗窖童竣等策筆筐筒答筍筋筏筑粟粥絞結絨絕紫絮絲絡給絢絰絳善翔翕耋聒肅腕腔腋腑腎脹腆脾腌腓腴舒舜菩萃菸萍菠菅萋菁華菱菴著萊菰萌菌菽菲菊萸萎萄菜萇菔菟虛蛟蛙蛭蛔蛛蛤蛐蛞街裁裂袱覃視註詠評詞証詁"],["b640","詔詛詐詆訴診訶詖象貂貯貼貳貽賁費賀貴買貶貿貸越超趁跎距跋跚跑跌跛跆軻軸軼辜逮逵週逸進逶鄂郵鄉郾酣酥量鈔鈕鈣鈉鈞鈍鈐鈇鈑閔閏開閑"],["b6a1","間閒閎隊階隋陽隅隆隍陲隄雁雅雄集雇雯雲韌項順須飧飪飯飩飲飭馮馭黃黍黑亂傭債傲傳僅傾催傷傻傯僇剿剷剽募勦勤勢勣匯嗟嗨嗓嗦嗎嗜嗇嗑嗣嗤嗯嗚嗡嗅嗆嗥嗉園圓塞塑塘塗塚塔填塌塭塊塢塒塋奧嫁嫉嫌媾媽媼"],["b740","媳嫂媲嵩嵯幌幹廉廈弒彙徬微愚意慈感想愛惹愁愈慎慌慄慍愾愴愧愍愆愷戡戢搓搾搞搪搭搽搬搏搜搔損搶搖搗搆敬斟新暗暉暇暈暖暄暘暍會榔業"],["b7a1","楚楷楠楔極椰概楊楨楫楞楓楹榆楝楣楛歇歲毀殿毓毽溢溯滓溶滂源溝滇滅溥溘溼溺溫滑準溜滄滔溪溧溴煎煙煩煤煉照煜煬煦煌煥煞煆煨煖爺牒猷獅猿猾瑯瑚瑕瑟瑞瑁琿瑙瑛瑜當畸瘀痰瘁痲痱痺痿痴痳盞盟睛睫睦睞督"],["b840","睹睪睬睜睥睨睢矮碎碰碗碘碌碉硼碑碓硿祺祿禁萬禽稜稚稠稔稟稞窟窠筷節筠筮筧粱粳粵經絹綑綁綏絛置罩罪署義羨群聖聘肆肄腱腰腸腥腮腳腫"],["b8a1","腹腺腦舅艇蒂葷落萱葵葦葫葉葬葛萼萵葡董葩葭葆虞虜號蛹蜓蜈蜇蜀蛾蛻蜂蜃蜆蜊衙裟裔裙補裘裝裡裊裕裒覜解詫該詳試詩詰誇詼詣誠話誅詭詢詮詬詹詻訾詨豢貊貉賊資賈賄貲賃賂賅跡跟跨路跳跺跪跤跦躲較載軾輊"],["b940","辟農運遊道遂達逼違遐遇遏過遍遑逾遁鄒鄗酬酪酩釉鈷鉗鈸鈽鉀鈾鉛鉋鉤鉑鈴鉉鉍鉅鈹鈿鉚閘隘隔隕雍雋雉雊雷電雹零靖靴靶預頑頓頊頒頌飼飴"],["b9a1","飽飾馳馱馴髡鳩麂鼎鼓鼠僧僮僥僖僭僚僕像僑僱僎僩兢凳劃劂匱厭嗾嘀嘛嘗嗽嘔嘆嘉嘍嘎嗷嘖嘟嘈嘐嗶團圖塵塾境墓墊塹墅塽壽夥夢夤奪奩嫡嫦嫩嫗嫖嫘嫣孵寞寧寡寥實寨寢寤察對屢嶄嶇幛幣幕幗幔廓廖弊彆彰徹慇"],["ba40","愿態慷慢慣慟慚慘慵截撇摘摔撤摸摟摺摑摧搴摭摻敲斡旗旖暢暨暝榜榨榕槁榮槓構榛榷榻榫榴槐槍榭槌榦槃榣歉歌氳漳演滾漓滴漩漾漠漬漏漂漢"],["baa1","滿滯漆漱漸漲漣漕漫漯澈漪滬漁滲滌滷熔熙煽熊熄熒爾犒犖獄獐瑤瑣瑪瑰瑭甄疑瘧瘍瘋瘉瘓盡監瞄睽睿睡磁碟碧碳碩碣禎福禍種稱窪窩竭端管箕箋筵算箝箔箏箸箇箄粹粽精綻綰綜綽綾綠緊綴網綱綺綢綿綵綸維緒緇綬"],["bb40","罰翠翡翟聞聚肇腐膀膏膈膊腿膂臧臺與舔舞艋蓉蒿蓆蓄蒙蒞蒲蒜蓋蒸蓀蓓蒐蒼蓑蓊蜿蜜蜻蜢蜥蜴蜘蝕蜷蜩裳褂裴裹裸製裨褚裯誦誌語誣認誡誓誤"],["bba1","說誥誨誘誑誚誧豪貍貌賓賑賒赫趙趕跼輔輒輕輓辣遠遘遜遣遙遞遢遝遛鄙鄘鄞酵酸酷酴鉸銀銅銘銖鉻銓銜銨鉼銑閡閨閩閣閥閤隙障際雌雒需靼鞅韶頗領颯颱餃餅餌餉駁骯骰髦魁魂鳴鳶鳳麼鼻齊億儀僻僵價儂儈儉儅凜"],["bc40","劇劈劉劍劊勰厲嘮嘻嘹嘲嘿嘴嘩噓噎噗噴嘶嘯嘰墀墟增墳墜墮墩墦奭嬉嫻嬋嫵嬌嬈寮寬審寫層履嶝嶔幢幟幡廢廚廟廝廣廠彈影德徵慶慧慮慝慕憂"],["bca1","慼慰慫慾憧憐憫憎憬憚憤憔憮戮摩摯摹撞撲撈撐撰撥撓撕撩撒撮播撫撚撬撙撢撳敵敷數暮暫暴暱樣樟槨樁樞標槽模樓樊槳樂樅槭樑歐歎殤毅毆漿潼澄潑潦潔澆潭潛潸潮澎潺潰潤澗潘滕潯潠潟熟熬熱熨牖犛獎獗瑩璋璃"],["bd40","瑾璀畿瘠瘩瘟瘤瘦瘡瘢皚皺盤瞎瞇瞌瞑瞋磋磅確磊碾磕碼磐稿稼穀稽稷稻窯窮箭箱範箴篆篇篁箠篌糊締練緯緻緘緬緝編緣線緞緩綞緙緲緹罵罷羯"],["bda1","翩耦膛膜膝膠膚膘蔗蔽蔚蓮蔬蔭蔓蔑蔣蔡蔔蓬蔥蓿蔆螂蝴蝶蝠蝦蝸蝨蝙蝗蝌蝓衛衝褐複褒褓褕褊誼諒談諄誕請諸課諉諂調誰論諍誶誹諛豌豎豬賠賞賦賤賬賭賢賣賜質賡赭趟趣踫踐踝踢踏踩踟踡踞躺輝輛輟輩輦輪輜輞"],["be40","輥適遮遨遭遷鄰鄭鄧鄱醇醉醋醃鋅銻銷鋪銬鋤鋁銳銼鋒鋇鋰銲閭閱霄霆震霉靠鞍鞋鞏頡頫頜颳養餓餒餘駝駐駟駛駑駕駒駙骷髮髯鬧魅魄魷魯鴆鴉"],["bea1","鴃麩麾黎墨齒儒儘儔儐儕冀冪凝劑劓勳噙噫噹噩噤噸噪器噥噱噯噬噢噶壁墾壇壅奮嬝嬴學寰導彊憲憑憩憊懍憶憾懊懈戰擅擁擋撻撼據擄擇擂操撿擒擔撾整曆曉暹曄曇暸樽樸樺橙橫橘樹橄橢橡橋橇樵機橈歙歷氅濂澱澡"],["bf40","濃澤濁澧澳激澹澶澦澠澴熾燉燐燒燈燕熹燎燙燜燃燄獨璜璣璘璟璞瓢甌甍瘴瘸瘺盧盥瞠瞞瞟瞥磨磚磬磧禦積穎穆穌穋窺篙簑築篤篛篡篩篦糕糖縊"],["bfa1","縑縈縛縣縞縝縉縐罹羲翰翱翮耨膳膩膨臻興艘艙蕊蕙蕈蕨蕩蕃蕉蕭蕪蕞螃螟螞螢融衡褪褲褥褫褡親覦諦諺諫諱謀諜諧諮諾謁謂諷諭諳諶諼豫豭貓賴蹄踱踴蹂踹踵輻輯輸輳辨辦遵遴選遲遼遺鄴醒錠錶鋸錳錯錢鋼錫錄錚"],["c040","錐錦錡錕錮錙閻隧隨險雕霎霑霖霍霓霏靛靜靦鞘頰頸頻頷頭頹頤餐館餞餛餡餚駭駢駱骸骼髻髭鬨鮑鴕鴣鴦鴨鴒鴛默黔龍龜優償儡儲勵嚎嚀嚐嚅嚇"],["c0a1","嚏壕壓壑壎嬰嬪嬤孺尷屨嶼嶺嶽嶸幫彌徽應懂懇懦懋戲戴擎擊擘擠擰擦擬擱擢擭斂斃曙曖檀檔檄檢檜櫛檣橾檗檐檠歜殮毚氈濘濱濟濠濛濤濫濯澀濬濡濩濕濮濰燧營燮燦燥燭燬燴燠爵牆獰獲璩環璦璨癆療癌盪瞳瞪瞰瞬"],["c140","瞧瞭矯磷磺磴磯礁禧禪穗窿簇簍篾篷簌篠糠糜糞糢糟糙糝縮績繆縷縲繃縫總縱繅繁縴縹繈縵縿縯罄翳翼聱聲聰聯聳臆臃膺臂臀膿膽臉膾臨舉艱薪"],["c1a1","薄蕾薜薑薔薯薛薇薨薊虧蟀蟑螳蟒蟆螫螻螺蟈蟋褻褶襄褸褽覬謎謗謙講謊謠謝謄謐豁谿豳賺賽購賸賻趨蹉蹋蹈蹊轄輾轂轅輿避遽還邁邂邀鄹醣醞醜鍍鎂錨鍵鍊鍥鍋錘鍾鍬鍛鍰鍚鍔闊闋闌闈闆隱隸雖霜霞鞠韓顆颶餵騁"],["c240","駿鮮鮫鮪鮭鴻鴿麋黏點黜黝黛鼾齋叢嚕嚮壙壘嬸彝懣戳擴擲擾攆擺擻擷斷曜朦檳檬櫃檻檸櫂檮檯歟歸殯瀉瀋濾瀆濺瀑瀏燻燼燾燸獷獵璧璿甕癖癘"],["c2a1","癒瞽瞿瞻瞼礎禮穡穢穠竄竅簫簧簪簞簣簡糧織繕繞繚繡繒繙罈翹翻職聶臍臏舊藏薩藍藐藉薰薺薹薦蟯蟬蟲蟠覆覲觴謨謹謬謫豐贅蹙蹣蹦蹤蹟蹕軀轉轍邇邃邈醫醬釐鎔鎊鎖鎢鎳鎮鎬鎰鎘鎚鎗闔闖闐闕離雜雙雛雞霤鞣鞦"],["c340","鞭韹額顏題顎顓颺餾餿餽餮馥騎髁鬃鬆魏魎魍鯊鯉鯽鯈鯀鵑鵝鵠黠鼕鼬儳嚥壞壟壢寵龐廬懲懷懶懵攀攏曠曝櫥櫝櫚櫓瀛瀟瀨瀚瀝瀕瀘爆爍牘犢獸"],["c3a1","獺璽瓊瓣疇疆癟癡矇礙禱穫穩簾簿簸簽簷籀繫繭繹繩繪羅繳羶羹羸臘藩藝藪藕藤藥藷蟻蠅蠍蟹蟾襠襟襖襞譁譜識證譚譎譏譆譙贈贊蹼蹲躇蹶蹬蹺蹴轔轎辭邊邋醱醮鏡鏑鏟鏃鏈鏜鏝鏖鏢鏍鏘鏤鏗鏨關隴難霪霧靡韜韻類"],["c440","願顛颼饅饉騖騙鬍鯨鯧鯖鯛鶉鵡鵲鵪鵬麒麗麓麴勸嚨嚷嚶嚴嚼壤孀孃孽寶巉懸懺攘攔攙曦朧櫬瀾瀰瀲爐獻瓏癢癥礦礪礬礫竇競籌籃籍糯糰辮繽繼"],["c4a1","纂罌耀臚艦藻藹蘑藺蘆蘋蘇蘊蠔蠕襤覺觸議譬警譯譟譫贏贍躉躁躅躂醴釋鐘鐃鏽闡霰飄饒饑馨騫騰騷騵鰓鰍鹹麵黨鼯齟齣齡儷儸囁囀囂夔屬巍懼懾攝攜斕曩櫻欄櫺殲灌爛犧瓖瓔癩矓籐纏續羼蘗蘭蘚蠣蠢蠡蠟襪襬覽譴"],["c540","護譽贓躊躍躋轟辯醺鐮鐳鐵鐺鐸鐲鐫闢霸霹露響顧顥饗驅驃驀騾髏魔魑鰭鰥鶯鶴鷂鶸麝黯鼙齜齦齧儼儻囈囊囉孿巔巒彎懿攤權歡灑灘玀瓤疊癮癬"],["c5a1","禳籠籟聾聽臟襲襯觼讀贖贗躑躓轡酈鑄鑑鑒霽霾韃韁顫饕驕驍髒鬚鱉鰱鰾鰻鷓鷗鼴齬齪龔囌巖戀攣攫攪曬欐瓚竊籤籣籥纓纖纔臢蘸蘿蠱變邐邏鑣鑠鑤靨顯饜驚驛驗髓體髑鱔鱗鱖鷥麟黴囑壩攬灞癱癲矗罐羈蠶蠹衢讓讒"],["c640","讖艷贛釀鑪靂靈靄韆顰驟鬢魘鱟鷹鷺鹼鹽鼇齷齲廳欖灣籬籮蠻觀躡釁鑲鑰顱饞髖鬣黌灤矚讚鑷韉驢驥纜讜躪釅鑽鑾鑼鱷鱸黷豔鑿鸚爨驪鬱鸛鸞籲"],["c940","乂乜凵匚厂万丌乇亍囗兀屮彳丏冇与丮亓仂仉仈冘勼卬厹圠夃夬尐巿旡殳毌气爿丱丼仨仜仩仡仝仚刌匜卌圢圣夗夯宁宄尒尻屴屳帄庀庂忉戉扐氕"],["c9a1","氶汃氿氻犮犰玊禸肊阞伎优伬仵伔仱伀价伈伝伂伅伢伓伄仴伒冱刓刉刐劦匢匟卍厊吇囡囟圮圪圴夼妀奼妅奻奾奷奿孖尕尥屼屺屻屾巟幵庄异弚彴忕忔忏扜扞扤扡扦扢扙扠扚扥旯旮朾朹朸朻机朿朼朳氘汆汒汜汏汊汔汋"],["ca40","汌灱牞犴犵玎甪癿穵网艸艼芀艽艿虍襾邙邗邘邛邔阢阤阠阣佖伻佢佉体佤伾佧佒佟佁佘伭伳伿佡冏冹刜刞刡劭劮匉卣卲厎厏吰吷吪呔呅吙吜吥吘"],["caa1","吽呏呁吨吤呇囮囧囥坁坅坌坉坋坒夆奀妦妘妠妗妎妢妐妏妧妡宎宒尨尪岍岏岈岋岉岒岊岆岓岕巠帊帎庋庉庌庈庍弅弝彸彶忒忑忐忭忨忮忳忡忤忣忺忯忷忻怀忴戺抃抌抎抏抔抇扱扻扺扰抁抈扷扽扲扴攷旰旴旳旲旵杅杇"],["cb40","杙杕杌杈杝杍杚杋毐氙氚汸汧汫沄沋沏汱汯汩沚汭沇沕沜汦汳汥汻沎灴灺牣犿犽狃狆狁犺狅玕玗玓玔玒町甹疔疕皁礽耴肕肙肐肒肜芐芏芅芎芑芓"],["cba1","芊芃芄豸迉辿邟邡邥邞邧邠阰阨阯阭丳侘佼侅佽侀侇佶佴侉侄佷佌侗佪侚佹侁佸侐侜侔侞侒侂侕佫佮冞冼冾刵刲刳剆刱劼匊匋匼厒厔咇呿咁咑咂咈呫呺呾呥呬呴呦咍呯呡呠咘呣呧呤囷囹坯坲坭坫坱坰坶垀坵坻坳坴坢"],["cc40","坨坽夌奅妵妺姏姎妲姌姁妶妼姃姖妱妽姀姈妴姇孢孥宓宕屄屇岮岤岠岵岯岨岬岟岣岭岢岪岧岝岥岶岰岦帗帔帙弨弢弣弤彔徂彾彽忞忥怭怦怙怲怋"],["cca1","怴怊怗怳怚怞怬怢怍怐怮怓怑怌怉怜戔戽抭抴拑抾抪抶拊抮抳抯抻抩抰抸攽斨斻昉旼昄昒昈旻昃昋昍昅旽昑昐曶朊枅杬枎枒杶杻枘枆构杴枍枌杺枟枑枙枃杽极杸杹枔欥殀歾毞氝沓泬泫泮泙沶泔沭泧沷泐泂沺泃泆泭泲"],["cd40","泒泝沴沊沝沀泞泀洰泍泇沰泹泏泩泑炔炘炅炓炆炄炑炖炂炚炃牪狖狋狘狉狜狒狔狚狌狑玤玡玭玦玢玠玬玝瓝瓨甿畀甾疌疘皯盳盱盰盵矸矼矹矻矺"],["cda1","矷祂礿秅穸穻竻籵糽耵肏肮肣肸肵肭舠芠苀芫芚芘芛芵芧芮芼芞芺芴芨芡芩苂芤苃芶芢虰虯虭虮豖迒迋迓迍迖迕迗邲邴邯邳邰阹阽阼阺陃俍俅俓侲俉俋俁俔俜俙侻侳俛俇俖侺俀侹俬剄剉勀勂匽卼厗厖厙厘咺咡咭咥哏"],["ce40","哃茍咷咮哖咶哅哆咠呰咼咢咾呲哞咰垵垞垟垤垌垗垝垛垔垘垏垙垥垚垕壴复奓姡姞姮娀姱姝姺姽姼姶姤姲姷姛姩姳姵姠姾姴姭宨屌峐峘峌峗峋峛"],["cea1","峞峚峉峇峊峖峓峔峏峈峆峎峟峸巹帡帢帣帠帤庰庤庢庛庣庥弇弮彖徆怷怹恔恲恞恅恓恇恉恛恌恀恂恟怤恄恘恦恮扂扃拏挍挋拵挎挃拫拹挏挌拸拶挀挓挔拺挕拻拰敁敃斪斿昶昡昲昵昜昦昢昳昫昺昝昴昹昮朏朐柁柲柈枺"],["cf40","柜枻柸柘柀枷柅柫柤柟枵柍枳柷柶柮柣柂枹柎柧柰枲柼柆柭柌枮柦柛柺柉柊柃柪柋欨殂殄殶毖毘毠氠氡洨洴洭洟洼洿洒洊泚洳洄洙洺洚洑洀洝浂"],["cfa1","洁洘洷洃洏浀洇洠洬洈洢洉洐炷炟炾炱炰炡炴炵炩牁牉牊牬牰牳牮狊狤狨狫狟狪狦狣玅珌珂珈珅玹玶玵玴珫玿珇玾珃珆玸珋瓬瓮甮畇畈疧疪癹盄眈眃眄眅眊盷盻盺矧矨砆砑砒砅砐砏砎砉砃砓祊祌祋祅祄秕种秏秖秎窀"],["d040","穾竑笀笁籺籸籹籿粀粁紃紈紁罘羑羍羾耇耎耏耔耷胘胇胠胑胈胂胐胅胣胙胜胊胕胉胏胗胦胍臿舡芔苙苾苹茇苨茀苕茺苫苖苴苬苡苲苵茌苻苶苰苪"],["d0a1","苤苠苺苳苭虷虴虼虳衁衎衧衪衩觓訄訇赲迣迡迮迠郱邽邿郕郅邾郇郋郈釔釓陔陏陑陓陊陎倞倅倇倓倢倰倛俵俴倳倷倬俶俷倗倜倠倧倵倯倱倎党冔冓凊凄凅凈凎剡剚剒剞剟剕剢勍匎厞唦哢唗唒哧哳哤唚哿唄唈哫唑唅哱"],["d140","唊哻哷哸哠唎唃唋圁圂埌堲埕埒垺埆垽垼垸垶垿埇埐垹埁夎奊娙娖娭娮娕娏娗娊娞娳孬宧宭宬尃屖屔峬峿峮峱峷崀峹帩帨庨庮庪庬弳弰彧恝恚恧"],["d1a1","恁悢悈悀悒悁悝悃悕悛悗悇悜悎戙扆拲挐捖挬捄捅挶捃揤挹捋捊挼挩捁挴捘捔捙挭捇挳捚捑挸捗捀捈敊敆旆旃旄旂晊晟晇晑朒朓栟栚桉栲栳栻桋桏栖栱栜栵栫栭栯桎桄栴栝栒栔栦栨栮桍栺栥栠欬欯欭欱欴歭肂殈毦毤"],["d240","毨毣毢毧氥浺浣浤浶洍浡涒浘浢浭浯涑涍淯浿涆浞浧浠涗浰浼浟涂涘洯浨涋浾涀涄洖涃浻浽浵涐烜烓烑烝烋缹烢烗烒烞烠烔烍烅烆烇烚烎烡牂牸"],["d2a1","牷牶猀狺狴狾狶狳狻猁珓珙珥珖玼珧珣珩珜珒珛珔珝珚珗珘珨瓞瓟瓴瓵甡畛畟疰痁疻痄痀疿疶疺皊盉眝眛眐眓眒眣眑眕眙眚眢眧砣砬砢砵砯砨砮砫砡砩砳砪砱祔祛祏祜祓祒祑秫秬秠秮秭秪秜秞秝窆窉窅窋窌窊窇竘笐"],["d340","笄笓笅笏笈笊笎笉笒粄粑粊粌粈粍粅紞紝紑紎紘紖紓紟紒紏紌罜罡罞罠罝罛羖羒翃翂翀耖耾耹胺胲胹胵脁胻脀舁舯舥茳茭荄茙荑茥荖茿荁茦茜茢"],["d3a1","荂荎茛茪茈茼荍茖茤茠茷茯茩荇荅荌荓茞茬荋茧荈虓虒蚢蚨蚖蚍蚑蚞蚇蚗蚆蚋蚚蚅蚥蚙蚡蚧蚕蚘蚎蚝蚐蚔衃衄衭衵衶衲袀衱衿衯袃衾衴衼訒豇豗豻貤貣赶赸趵趷趶軑軓迾迵适迿迻逄迼迶郖郠郙郚郣郟郥郘郛郗郜郤酐"],["d440","酎酏釕釢釚陜陟隼飣髟鬯乿偰偪偡偞偠偓偋偝偲偈偍偁偛偊偢倕偅偟偩偫偣偤偆偀偮偳偗偑凐剫剭剬剮勖勓匭厜啵啶唼啍啐唴唪啑啢唶唵唰啒啅"],["d4a1","唌唲啥啎唹啈唭唻啀啋圊圇埻堔埢埶埜埴堀埭埽堈埸堋埳埏堇埮埣埲埥埬埡堎埼堐埧堁堌埱埩埰堍堄奜婠婘婕婧婞娸娵婭婐婟婥婬婓婤婗婃婝婒婄婛婈媎娾婍娹婌婰婩婇婑婖婂婜孲孮寁寀屙崞崋崝崚崠崌崨崍崦崥崏"],["d540","崰崒崣崟崮帾帴庱庴庹庲庳弶弸徛徖徟悊悐悆悾悰悺惓惔惏惤惙惝惈悱惛悷惊悿惃惍惀挲捥掊掂捽掽掞掭掝掗掫掎捯掇掐据掯捵掜捭掮捼掤挻掟"],["d5a1","捸掅掁掑掍捰敓旍晥晡晛晙晜晢朘桹梇梐梜桭桮梮梫楖桯梣梬梩桵桴梲梏桷梒桼桫桲梪梀桱桾梛梖梋梠梉梤桸桻梑梌梊桽欶欳欷欸殑殏殍殎殌氪淀涫涴涳湴涬淩淢涷淶淔渀淈淠淟淖涾淥淜淝淛淴淊涽淭淰涺淕淂淏淉"],["d640","淐淲淓淽淗淍淣涻烺焍烷焗烴焌烰焄烳焐烼烿焆焓焀烸烶焋焂焎牾牻牼牿猝猗猇猑猘猊猈狿猏猞玈珶珸珵琄琁珽琇琀珺珼珿琌琋珴琈畤畣痎痒痏"],["d6a1","痋痌痑痐皏皉盓眹眯眭眱眲眴眳眽眥眻眵硈硒硉硍硊硌砦硅硐祤祧祩祪祣祫祡离秺秸秶秷窏窔窐笵筇笴笥笰笢笤笳笘笪笝笱笫笭笯笲笸笚笣粔粘粖粣紵紽紸紶紺絅紬紩絁絇紾紿絊紻紨罣羕羜羝羛翊翋翍翐翑翇翏翉耟"],["d740","耞耛聇聃聈脘脥脙脛脭脟脬脞脡脕脧脝脢舑舸舳舺舴舲艴莐莣莨莍荺荳莤荴莏莁莕莙荵莔莩荽莃莌莝莛莪莋荾莥莯莈莗莰荿莦莇莮荶莚虙虖蚿蚷"],["d7a1","蛂蛁蛅蚺蚰蛈蚹蚳蚸蛌蚴蚻蚼蛃蚽蚾衒袉袕袨袢袪袚袑袡袟袘袧袙袛袗袤袬袌袓袎覂觖觙觕訰訧訬訞谹谻豜豝豽貥赽赻赹趼跂趹趿跁軘軞軝軜軗軠軡逤逋逑逜逌逡郯郪郰郴郲郳郔郫郬郩酖酘酚酓酕釬釴釱釳釸釤釹釪"],["d840","釫釷釨釮镺閆閈陼陭陫陱陯隿靪頄飥馗傛傕傔傞傋傣傃傌傎傝偨傜傒傂傇兟凔匒匑厤厧喑喨喥喭啷噅喢喓喈喏喵喁喣喒喤啽喌喦啿喕喡喎圌堩堷"],["d8a1","堙堞堧堣堨埵塈堥堜堛堳堿堶堮堹堸堭堬堻奡媯媔媟婺媢媞婸媦婼媥媬媕媮娷媄媊媗媃媋媩婻婽媌媜媏媓媝寪寍寋寔寑寊寎尌尰崷嵃嵫嵁嵋崿崵嵑嵎嵕崳崺嵒崽崱嵙嵂崹嵉崸崼崲崶嵀嵅幄幁彘徦徥徫惉悹惌惢惎惄愔"],["d940","惲愊愖愅惵愓惸惼惾惁愃愘愝愐惿愄愋扊掔掱掰揎揥揨揯揃撝揳揊揠揶揕揲揵摡揟掾揝揜揄揘揓揂揇揌揋揈揰揗揙攲敧敪敤敜敨敥斌斝斞斮旐旒"],["d9a1","晼晬晻暀晱晹晪晲朁椌棓椄棜椪棬棪棱椏棖棷棫棤棶椓椐棳棡椇棌椈楰梴椑棯棆椔棸棐棽棼棨椋椊椗棎棈棝棞棦棴棑椆棔棩椕椥棇欹欻欿欼殔殗殙殕殽毰毲毳氰淼湆湇渟湉溈渼渽湅湢渫渿湁湝湳渜渳湋湀湑渻渃渮湞"],["da40","湨湜湡渱渨湠湱湫渹渢渰湓湥渧湸湤湷湕湹湒湦渵渶湚焠焞焯烻焮焱焣焥焢焲焟焨焺焛牋牚犈犉犆犅犋猒猋猰猢猱猳猧猲猭猦猣猵猌琮琬琰琫琖"],["daa1","琚琡琭琱琤琣琝琩琠琲瓻甯畯畬痧痚痡痦痝痟痤痗皕皒盚睆睇睄睍睅睊睎睋睌矞矬硠硤硥硜硭硱硪确硰硩硨硞硢祴祳祲祰稂稊稃稌稄窙竦竤筊笻筄筈筌筎筀筘筅粢粞粨粡絘絯絣絓絖絧絪絏絭絜絫絒絔絩絑絟絎缾缿罥"],["db40","罦羢羠羡翗聑聏聐胾胔腃腊腒腏腇脽腍脺臦臮臷臸臹舄舼舽舿艵茻菏菹萣菀菨萒菧菤菼菶萐菆菈菫菣莿萁菝菥菘菿菡菋菎菖菵菉萉萏菞萑萆菂菳"],["dba1","菕菺菇菑菪萓菃菬菮菄菻菗菢萛菛菾蛘蛢蛦蛓蛣蛚蛪蛝蛫蛜蛬蛩蛗蛨蛑衈衖衕袺裗袹袸裀袾袶袼袷袽袲褁裉覕覘覗觝觚觛詎詍訹詙詀詗詘詄詅詒詈詑詊詌詏豟貁貀貺貾貰貹貵趄趀趉跘跓跍跇跖跜跏跕跙跈跗跅軯軷軺"],["dc40","軹軦軮軥軵軧軨軶軫軱軬軴軩逭逴逯鄆鄬鄄郿郼鄈郹郻鄁鄀鄇鄅鄃酡酤酟酢酠鈁鈊鈥鈃鈚鈦鈏鈌鈀鈒釿釽鈆鈄鈧鈂鈜鈤鈙鈗鈅鈖镻閍閌閐隇陾隈"],["dca1","隉隃隀雂雈雃雱雰靬靰靮頇颩飫鳦黹亃亄亶傽傿僆傮僄僊傴僈僂傰僁傺傱僋僉傶傸凗剺剸剻剼嗃嗛嗌嗐嗋嗊嗝嗀嗔嗄嗩喿嗒喍嗏嗕嗢嗖嗈嗲嗍嗙嗂圔塓塨塤塏塍塉塯塕塎塝塙塥塛堽塣塱壼嫇嫄嫋媺媸媱媵媰媿嫈媻嫆"],["dd40","媷嫀嫊媴媶嫍媹媐寖寘寙尟尳嵱嵣嵊嵥嵲嵬嵞嵨嵧嵢巰幏幎幊幍幋廅廌廆廋廇彀徯徭惷慉慊愫慅愶愲愮慆愯慏愩慀戠酨戣戥戤揅揱揫搐搒搉搠搤"],["dda1","搳摃搟搕搘搹搷搢搣搌搦搰搨摁搵搯搊搚摀搥搧搋揧搛搮搡搎敯斒旓暆暌暕暐暋暊暙暔晸朠楦楟椸楎楢楱椿楅楪椹楂楗楙楺楈楉椵楬椳椽楥棰楸椴楩楀楯楄楶楘楁楴楌椻楋椷楜楏楑椲楒椯楻椼歆歅歃歂歈歁殛嗀毻毼"],["de40","毹毷毸溛滖滈溏滀溟溓溔溠溱溹滆滒溽滁溞滉溷溰滍溦滏溲溾滃滜滘溙溒溎溍溤溡溿溳滐滊溗溮溣煇煔煒煣煠煁煝煢煲煸煪煡煂煘煃煋煰煟煐煓"],["dea1","煄煍煚牏犍犌犑犐犎猼獂猻猺獀獊獉瑄瑊瑋瑒瑑瑗瑀瑏瑐瑎瑂瑆瑍瑔瓡瓿瓾瓽甝畹畷榃痯瘏瘃痷痾痼痹痸瘐痻痶痭痵痽皙皵盝睕睟睠睒睖睚睩睧睔睙睭矠碇碚碔碏碄碕碅碆碡碃硹碙碀碖硻祼禂祽祹稑稘稙稒稗稕稢稓"],["df40","稛稐窣窢窞竫筦筤筭筴筩筲筥筳筱筰筡筸筶筣粲粴粯綈綆綀綍絿綅絺綎絻綃絼綌綔綄絽綒罭罫罧罨罬羦羥羧翛翜耡腤腠腷腜腩腛腢腲朡腞腶腧腯"],["dfa1","腄腡舝艉艄艀艂艅蓱萿葖葶葹蒏蒍葥葑葀蒆葧萰葍葽葚葙葴葳葝蔇葞萷萺萴葺葃葸萲葅萩菙葋萯葂萭葟葰萹葎葌葒葯蓅蒎萻葇萶萳葨葾葄萫葠葔葮葐蜋蜄蛷蜌蛺蛖蛵蝍蛸蜎蜉蜁蛶蜍蜅裖裋裍裎裞裛裚裌裐覅覛觟觥觤"],["e040","觡觠觢觜触詶誆詿詡訿詷誂誄詵誃誁詴詺谼豋豊豥豤豦貆貄貅賌赨赩趑趌趎趏趍趓趔趐趒跰跠跬跱跮跐跩跣跢跧跲跫跴輆軿輁輀輅輇輈輂輋遒逿"],["e0a1","遄遉逽鄐鄍鄏鄑鄖鄔鄋鄎酮酯鉈鉒鈰鈺鉦鈳鉥鉞銃鈮鉊鉆鉭鉬鉏鉠鉧鉯鈶鉡鉰鈱鉔鉣鉐鉲鉎鉓鉌鉖鈲閟閜閞閛隒隓隑隗雎雺雽雸雵靳靷靸靲頏頍頎颬飶飹馯馲馰馵骭骫魛鳪鳭鳧麀黽僦僔僗僨僳僛僪僝僤僓僬僰僯僣僠"],["e140","凘劀劁勩勫匰厬嘧嘕嘌嘒嗼嘏嘜嘁嘓嘂嗺嘝嘄嗿嗹墉塼墐墘墆墁塿塴墋塺墇墑墎塶墂墈塻墔墏壾奫嫜嫮嫥嫕嫪嫚嫭嫫嫳嫢嫠嫛嫬嫞嫝嫙嫨嫟孷寠"],["e1a1","寣屣嶂嶀嵽嶆嵺嶁嵷嶊嶉嶈嵾嵼嶍嵹嵿幘幙幓廘廑廗廎廜廕廙廒廔彄彃彯徶愬愨慁慞慱慳慒慓慲慬憀慴慔慺慛慥愻慪慡慖戩戧戫搫摍摛摝摴摶摲摳摽摵摦撦摎撂摞摜摋摓摠摐摿搿摬摫摙摥摷敳斠暡暠暟朅朄朢榱榶槉"],["e240","榠槎榖榰榬榼榑榙榎榧榍榩榾榯榿槄榽榤槔榹槊榚槏榳榓榪榡榞槙榗榐槂榵榥槆歊歍歋殞殟殠毃毄毾滎滵滱漃漥滸漷滻漮漉潎漙漚漧漘漻漒滭漊"],["e2a1","漶潳滹滮漭潀漰漼漵滫漇漎潃漅滽滶漹漜滼漺漟漍漞漈漡熇熐熉熀熅熂熏煻熆熁熗牄牓犗犕犓獃獍獑獌瑢瑳瑱瑵瑲瑧瑮甀甂甃畽疐瘖瘈瘌瘕瘑瘊瘔皸瞁睼瞅瞂睮瞀睯睾瞃碲碪碴碭碨硾碫碞碥碠碬碢碤禘禊禋禖禕禔禓"],["e340","禗禈禒禐稫穊稰稯稨稦窨窫窬竮箈箜箊箑箐箖箍箌箛箎箅箘劄箙箤箂粻粿粼粺綧綷緂綣綪緁緀緅綝緎緄緆緋緌綯綹綖綼綟綦綮綩綡緉罳翢翣翥翞"],["e3a1","耤聝聜膉膆膃膇膍膌膋舕蒗蒤蒡蒟蒺蓎蓂蒬蒮蒫蒹蒴蓁蓍蒪蒚蒱蓐蒝蒧蒻蒢蒔蓇蓌蒛蒩蒯蒨蓖蒘蒶蓏蒠蓗蓔蓒蓛蒰蒑虡蜳蜣蜨蝫蝀蜮蜞蜡蜙蜛蝃蜬蝁蜾蝆蜠蜲蜪蜭蜼蜒蜺蜱蜵蝂蜦蜧蜸蜤蜚蜰蜑裷裧裱裲裺裾裮裼裶裻"],["e440","裰裬裫覝覡覟覞觩觫觨誫誙誋誒誏誖谽豨豩賕賏賗趖踉踂跿踍跽踊踃踇踆踅跾踀踄輐輑輎輍鄣鄜鄠鄢鄟鄝鄚鄤鄡鄛酺酲酹酳銥銤鉶銛鉺銠銔銪銍"],["e4a1","銦銚銫鉹銗鉿銣鋮銎銂銕銢鉽銈銡銊銆銌銙銧鉾銇銩銝銋鈭隞隡雿靘靽靺靾鞃鞀鞂靻鞄鞁靿韎韍頖颭颮餂餀餇馝馜駃馹馻馺駂馽駇骱髣髧鬾鬿魠魡魟鳱鳲鳵麧僿儃儰僸儆儇僶僾儋儌僽儊劋劌勱勯噈噂噌嘵噁噊噉噆噘"],["e540","噚噀嘳嘽嘬嘾嘸嘪嘺圚墫墝墱墠墣墯墬墥墡壿嫿嫴嫽嫷嫶嬃嫸嬂嫹嬁嬇嬅嬏屧嶙嶗嶟嶒嶢嶓嶕嶠嶜嶡嶚嶞幩幝幠幜緳廛廞廡彉徲憋憃慹憱憰憢憉"],["e5a1","憛憓憯憭憟憒憪憡憍慦憳戭摮摰撖撠撅撗撜撏撋撊撌撣撟摨撱撘敶敺敹敻斲斳暵暰暩暲暷暪暯樀樆樗槥槸樕槱槤樠槿槬槢樛樝槾樧槲槮樔槷槧橀樈槦槻樍槼槫樉樄樘樥樏槶樦樇槴樖歑殥殣殢殦氁氀毿氂潁漦潾澇濆澒"],["e640","澍澉澌潢潏澅潚澖潶潬澂潕潲潒潐潗澔澓潝漀潡潫潽潧澐潓澋潩潿澕潣潷潪潻熲熯熛熰熠熚熩熵熝熥熞熤熡熪熜熧熳犘犚獘獒獞獟獠獝獛獡獚獙"],["e6a1","獢璇璉璊璆璁瑽璅璈瑼瑹甈甇畾瘥瘞瘙瘝瘜瘣瘚瘨瘛皜皝皞皛瞍瞏瞉瞈磍碻磏磌磑磎磔磈磃磄磉禚禡禠禜禢禛歶稹窲窴窳箷篋箾箬篎箯箹篊箵糅糈糌糋緷緛緪緧緗緡縃緺緦緶緱緰緮緟罶羬羰羭翭翫翪翬翦翨聤聧膣膟"],["e740","膞膕膢膙膗舖艏艓艒艐艎艑蔤蔻蔏蔀蔩蔎蔉蔍蔟蔊蔧蔜蓻蔫蓺蔈蔌蓴蔪蓲蔕蓷蓫蓳蓼蔒蓪蓩蔖蓾蔨蔝蔮蔂蓽蔞蓶蔱蔦蓧蓨蓰蓯蓹蔘蔠蔰蔋蔙蔯虢"],["e7a1","蝖蝣蝤蝷蟡蝳蝘蝔蝛蝒蝡蝚蝑蝞蝭蝪蝐蝎蝟蝝蝯蝬蝺蝮蝜蝥蝏蝻蝵蝢蝧蝩衚褅褌褔褋褗褘褙褆褖褑褎褉覢覤覣觭觰觬諏諆誸諓諑諔諕誻諗誾諀諅諘諃誺誽諙谾豍貏賥賟賙賨賚賝賧趠趜趡趛踠踣踥踤踮踕踛踖踑踙踦踧"],["e840","踔踒踘踓踜踗踚輬輤輘輚輠輣輖輗遳遰遯遧遫鄯鄫鄩鄪鄲鄦鄮醅醆醊醁醂醄醀鋐鋃鋄鋀鋙銶鋏鋱鋟鋘鋩鋗鋝鋌鋯鋂鋨鋊鋈鋎鋦鋍鋕鋉鋠鋞鋧鋑鋓"],["e8a1","銵鋡鋆銴镼閬閫閮閰隤隢雓霅霈霂靚鞊鞎鞈韐韏頞頝頦頩頨頠頛頧颲餈飺餑餔餖餗餕駜駍駏駓駔駎駉駖駘駋駗駌骳髬髫髳髲髱魆魃魧魴魱魦魶魵魰魨魤魬鳼鳺鳽鳿鳷鴇鴀鳹鳻鴈鴅鴄麃黓鼏鼐儜儓儗儚儑凞匴叡噰噠噮"],["e940","噳噦噣噭噲噞噷圜圛壈墽壉墿墺壂墼壆嬗嬙嬛嬡嬔嬓嬐嬖嬨嬚嬠嬞寯嶬嶱嶩嶧嶵嶰嶮嶪嶨嶲嶭嶯嶴幧幨幦幯廩廧廦廨廥彋徼憝憨憖懅憴懆懁懌憺"],["e9a1","憿憸憌擗擖擐擏擉撽撉擃擛擳擙攳敿敼斢曈暾曀曊曋曏暽暻暺曌朣樴橦橉橧樲橨樾橝橭橶橛橑樨橚樻樿橁橪橤橐橏橔橯橩橠樼橞橖橕橍橎橆歕歔歖殧殪殫毈毇氄氃氆澭濋澣濇澼濎濈潞濄澽澞濊澨瀄澥澮澺澬澪濏澿澸"],["ea40","澢濉澫濍澯澲澰燅燂熿熸燖燀燁燋燔燊燇燏熽燘熼燆燚燛犝犞獩獦獧獬獥獫獪瑿璚璠璔璒璕璡甋疀瘯瘭瘱瘽瘳瘼瘵瘲瘰皻盦瞚瞝瞡瞜瞛瞢瞣瞕瞙"],["eaa1","瞗磝磩磥磪磞磣磛磡磢磭磟磠禤穄穈穇窶窸窵窱窷篞篣篧篝篕篥篚篨篹篔篪篢篜篫篘篟糒糔糗糐糑縒縡縗縌縟縠縓縎縜縕縚縢縋縏縖縍縔縥縤罃罻罼罺羱翯耪耩聬膱膦膮膹膵膫膰膬膴膲膷膧臲艕艖艗蕖蕅蕫蕍蕓蕡蕘"],["eb40","蕀蕆蕤蕁蕢蕄蕑蕇蕣蔾蕛蕱蕎蕮蕵蕕蕧蕠薌蕦蕝蕔蕥蕬虣虥虤螛螏螗螓螒螈螁螖螘蝹螇螣螅螐螑螝螄螔螜螚螉褞褦褰褭褮褧褱褢褩褣褯褬褟觱諠"],["eba1","諢諲諴諵諝謔諤諟諰諈諞諡諨諿諯諻貑貒貐賵賮賱賰賳赬赮趥趧踳踾踸蹀蹅踶踼踽蹁踰踿躽輶輮輵輲輹輷輴遶遹遻邆郺鄳鄵鄶醓醐醑醍醏錧錞錈錟錆錏鍺錸錼錛錣錒錁鍆錭錎錍鋋錝鋺錥錓鋹鋷錴錂錤鋿錩錹錵錪錔錌"],["ec40","錋鋾錉錀鋻錖閼闍閾閹閺閶閿閵閽隩雔霋霒霐鞙鞗鞔韰韸頵頯頲餤餟餧餩馞駮駬駥駤駰駣駪駩駧骹骿骴骻髶髺髹髷鬳鮀鮅鮇魼魾魻鮂鮓鮒鮐魺鮕"],["eca1","魽鮈鴥鴗鴠鴞鴔鴩鴝鴘鴢鴐鴙鴟麈麆麇麮麭黕黖黺鼒鼽儦儥儢儤儠儩勴嚓嚌嚍嚆嚄嚃噾嚂噿嚁壖壔壏壒嬭嬥嬲嬣嬬嬧嬦嬯嬮孻寱寲嶷幬幪徾徻懃憵憼懧懠懥懤懨懞擯擩擣擫擤擨斁斀斶旚曒檍檖檁檥檉檟檛檡檞檇檓檎"],["ed40","檕檃檨檤檑橿檦檚檅檌檒歛殭氉濌澩濴濔濣濜濭濧濦濞濲濝濢濨燡燱燨燲燤燰燢獳獮獯璗璲璫璐璪璭璱璥璯甐甑甒甏疄癃癈癉癇皤盩瞵瞫瞲瞷瞶"],["eda1","瞴瞱瞨矰磳磽礂磻磼磲礅磹磾礄禫禨穜穛穖穘穔穚窾竀竁簅簏篲簀篿篻簎篴簋篳簂簉簃簁篸篽簆篰篱簐簊糨縭縼繂縳顈縸縪繉繀繇縩繌縰縻縶繄縺罅罿罾罽翴翲耬膻臄臌臊臅臇膼臩艛艚艜薃薀薏薧薕薠薋薣蕻薤薚薞"],["ee40","蕷蕼薉薡蕺蕸蕗薎薖薆薍薙薝薁薢薂薈薅蕹蕶薘薐薟虨螾螪螭蟅螰螬螹螵螼螮蟉蟃蟂蟌螷螯蟄蟊螴螶螿螸螽蟞螲褵褳褼褾襁襒褷襂覭覯覮觲觳謞"],["eea1","謘謖謑謅謋謢謏謒謕謇謍謈謆謜謓謚豏豰豲豱豯貕貔賹赯蹎蹍蹓蹐蹌蹇轃轀邅遾鄸醚醢醛醙醟醡醝醠鎡鎃鎯鍤鍖鍇鍼鍘鍜鍶鍉鍐鍑鍠鍭鎏鍌鍪鍹鍗鍕鍒鍏鍱鍷鍻鍡鍞鍣鍧鎀鍎鍙闇闀闉闃闅閷隮隰隬霠霟霘霝霙鞚鞡鞜"],["ef40","鞞鞝韕韔韱顁顄顊顉顅顃餥餫餬餪餳餲餯餭餱餰馘馣馡騂駺駴駷駹駸駶駻駽駾駼騃骾髾髽鬁髼魈鮚鮨鮞鮛鮦鮡鮥鮤鮆鮢鮠鮯鴳鵁鵧鴶鴮鴯鴱鴸鴰"],["efa1","鵅鵂鵃鴾鴷鵀鴽翵鴭麊麉麍麰黈黚黻黿鼤鼣鼢齔龠儱儭儮嚘嚜嚗嚚嚝嚙奰嬼屩屪巀幭幮懘懟懭懮懱懪懰懫懖懩擿攄擽擸攁攃擼斔旛曚曛曘櫅檹檽櫡櫆檺檶檷櫇檴檭歞毉氋瀇瀌瀍瀁瀅瀔瀎濿瀀濻瀦濼濷瀊爁燿燹爃燽獶"],["f040","璸瓀璵瓁璾璶璻瓂甔甓癜癤癙癐癓癗癚皦皽盬矂瞺磿礌礓礔礉礐礒礑禭禬穟簜簩簙簠簟簭簝簦簨簢簥簰繜繐繖繣繘繢繟繑繠繗繓羵羳翷翸聵臑臒"],["f0a1","臐艟艞薴藆藀藃藂薳薵薽藇藄薿藋藎藈藅薱薶藒蘤薸薷薾虩蟧蟦蟢蟛蟫蟪蟥蟟蟳蟤蟔蟜蟓蟭蟘蟣螤蟗蟙蠁蟴蟨蟝襓襋襏襌襆襐襑襉謪謧謣謳謰謵譇謯謼謾謱謥謷謦謶謮謤謻謽謺豂豵貙貘貗賾贄贂贀蹜蹢蹠蹗蹖蹞蹥蹧"],["f140","蹛蹚蹡蹝蹩蹔轆轇轈轋鄨鄺鄻鄾醨醥醧醯醪鎵鎌鎒鎷鎛鎝鎉鎧鎎鎪鎞鎦鎕鎈鎙鎟鎍鎱鎑鎲鎤鎨鎴鎣鎥闒闓闑隳雗雚巂雟雘雝霣霢霥鞬鞮鞨鞫鞤鞪"],["f1a1","鞢鞥韗韙韖韘韺顐顑顒颸饁餼餺騏騋騉騍騄騑騊騅騇騆髀髜鬈鬄鬅鬩鬵魊魌魋鯇鯆鯃鮿鯁鮵鮸鯓鮶鯄鮹鮽鵜鵓鵏鵊鵛鵋鵙鵖鵌鵗鵒鵔鵟鵘鵚麎麌黟鼁鼀鼖鼥鼫鼪鼩鼨齌齕儴儵劖勷厴嚫嚭嚦嚧嚪嚬壚壝壛夒嬽嬾嬿巃幰"],["f240","徿懻攇攐攍攉攌攎斄旞旝曞櫧櫠櫌櫑櫙櫋櫟櫜櫐櫫櫏櫍櫞歠殰氌瀙瀧瀠瀖瀫瀡瀢瀣瀩瀗瀤瀜瀪爌爊爇爂爅犥犦犤犣犡瓋瓅璷瓃甖癠矉矊矄矱礝礛"],["f2a1","礡礜礗礞禰穧穨簳簼簹簬簻糬糪繶繵繸繰繷繯繺繲繴繨罋罊羃羆羷翽翾聸臗臕艤艡艣藫藱藭藙藡藨藚藗藬藲藸藘藟藣藜藑藰藦藯藞藢蠀蟺蠃蟶蟷蠉蠌蠋蠆蟼蠈蟿蠊蠂襢襚襛襗襡襜襘襝襙覈覷覶觶譐譈譊譀譓譖譔譋譕"],["f340","譑譂譒譗豃豷豶貚贆贇贉趬趪趭趫蹭蹸蹳蹪蹯蹻軂轒轑轏轐轓辴酀鄿醰醭鏞鏇鏏鏂鏚鏐鏹鏬鏌鏙鎩鏦鏊鏔鏮鏣鏕鏄鏎鏀鏒鏧镽闚闛雡霩霫霬霨霦"],["f3a1","鞳鞷鞶韝韞韟顜顙顝顗颿颽颻颾饈饇饃馦馧騚騕騥騝騤騛騢騠騧騣騞騜騔髂鬋鬊鬎鬌鬷鯪鯫鯠鯞鯤鯦鯢鯰鯔鯗鯬鯜鯙鯥鯕鯡鯚鵷鶁鶊鶄鶈鵱鶀鵸鶆鶋鶌鵽鵫鵴鵵鵰鵩鶅鵳鵻鶂鵯鵹鵿鶇鵨麔麑黀黼鼭齀齁齍齖齗齘匷嚲"],["f440","嚵嚳壣孅巆巇廮廯忀忁懹攗攖攕攓旟曨曣曤櫳櫰櫪櫨櫹櫱櫮櫯瀼瀵瀯瀷瀴瀱灂瀸瀿瀺瀹灀瀻瀳灁爓爔犨獽獼璺皫皪皾盭矌矎矏矍矲礥礣礧礨礤礩"],["f4a1","禲穮穬穭竷籉籈籊籇籅糮繻繾纁纀羺翿聹臛臙舋艨艩蘢藿蘁藾蘛蘀藶蘄蘉蘅蘌藽蠙蠐蠑蠗蠓蠖襣襦覹觷譠譪譝譨譣譥譧譭趮躆躈躄轙轖轗轕轘轚邍酃酁醷醵醲醳鐋鐓鏻鐠鐏鐔鏾鐕鐐鐨鐙鐍鏵鐀鏷鐇鐎鐖鐒鏺鐉鏸鐊鏿"],["f540","鏼鐌鏶鐑鐆闞闠闟霮霯鞹鞻韽韾顠顢顣顟飁飂饐饎饙饌饋饓騲騴騱騬騪騶騩騮騸騭髇髊髆鬐鬒鬑鰋鰈鯷鰅鰒鯸鱀鰇鰎鰆鰗鰔鰉鶟鶙鶤鶝鶒鶘鶐鶛"],["f5a1","鶠鶔鶜鶪鶗鶡鶚鶢鶨鶞鶣鶿鶩鶖鶦鶧麙麛麚黥黤黧黦鼰鼮齛齠齞齝齙龑儺儹劘劗囃嚽嚾孈孇巋巏廱懽攛欂櫼欃櫸欀灃灄灊灈灉灅灆爝爚爙獾甗癪矐礭礱礯籔籓糲纊纇纈纋纆纍罍羻耰臝蘘蘪蘦蘟蘣蘜蘙蘧蘮蘡蘠蘩蘞蘥"],["f640","蠩蠝蠛蠠蠤蠜蠫衊襭襩襮襫觺譹譸譅譺譻贐贔趯躎躌轞轛轝酆酄酅醹鐿鐻鐶鐩鐽鐼鐰鐹鐪鐷鐬鑀鐱闥闤闣霵霺鞿韡顤飉飆飀饘饖騹騽驆驄驂驁騺"],["f6a1","騿髍鬕鬗鬘鬖鬺魒鰫鰝鰜鰬鰣鰨鰩鰤鰡鶷鶶鶼鷁鷇鷊鷏鶾鷅鷃鶻鶵鷎鶹鶺鶬鷈鶱鶭鷌鶳鷍鶲鹺麜黫黮黭鼛鼘鼚鼱齎齥齤龒亹囆囅囋奱孋孌巕巑廲攡攠攦攢欋欈欉氍灕灖灗灒爞爟犩獿瓘瓕瓙瓗癭皭礵禴穰穱籗籜籙籛籚"],["f740","糴糱纑罏羇臞艫蘴蘵蘳蘬蘲蘶蠬蠨蠦蠪蠥襱覿覾觻譾讄讂讆讅譿贕躕躔躚躒躐躖躗轠轢酇鑌鑐鑊鑋鑏鑇鑅鑈鑉鑆霿韣顪顩飋饔饛驎驓驔驌驏驈驊"],["f7a1","驉驒驐髐鬙鬫鬻魖魕鱆鱈鰿鱄鰹鰳鱁鰼鰷鰴鰲鰽鰶鷛鷒鷞鷚鷋鷐鷜鷑鷟鷩鷙鷘鷖鷵鷕鷝麶黰鼵鼳鼲齂齫龕龢儽劙壨壧奲孍巘蠯彏戁戃戄攩攥斖曫欑欒欏毊灛灚爢玂玁玃癰矔籧籦纕艬蘺虀蘹蘼蘱蘻蘾蠰蠲蠮蠳襶襴襳觾"],["f840","讌讎讋讈豅贙躘轤轣醼鑢鑕鑝鑗鑞韄韅頀驖驙鬞鬟鬠鱒鱘鱐鱊鱍鱋鱕鱙鱌鱎鷻鷷鷯鷣鷫鷸鷤鷶鷡鷮鷦鷲鷰鷢鷬鷴鷳鷨鷭黂黐黲黳鼆鼜鼸鼷鼶齃齏"],["f8a1","齱齰齮齯囓囍孎屭攭曭曮欓灟灡灝灠爣瓛瓥矕礸禷禶籪纗羉艭虃蠸蠷蠵衋讔讕躞躟躠躝醾醽釂鑫鑨鑩雥靆靃靇韇韥驞髕魙鱣鱧鱦鱢鱞鱠鸂鷾鸇鸃鸆鸅鸀鸁鸉鷿鷽鸄麠鼞齆齴齵齶囔攮斸欘欙欗欚灢爦犪矘矙礹籩籫糶纚"],["f940","纘纛纙臠臡虆虇虈襹襺襼襻觿讘讙躥躤躣鑮鑭鑯鑱鑳靉顲饟鱨鱮鱭鸋鸍鸐鸏鸒鸑麡黵鼉齇齸齻齺齹圞灦籯蠼趲躦釃鑴鑸鑶鑵驠鱴鱳鱱鱵鸔鸓黶鼊"],["f9a1","龤灨灥糷虪蠾蠽蠿讞貜躩軉靋顳顴飌饡馫驤驦驧鬤鸕鸗齈戇欞爧虌躨钂钀钁驩驨鬮鸙爩虋讟钃鱹麷癵驫鱺鸝灩灪麤齾齉龘碁銹裏墻恒粧嫺╔╦╗╠╬╣╚╩╝╒╤╕╞╪╡╘╧╛╓╥╖╟╫╢╙╨╜║═╭╮╰╯▓"]]},145:function(e){"use strict";e.exports={437:"cp437",737:"cp737",775:"cp775",850:"cp850",852:"cp852",855:"cp855",856:"cp856",857:"cp857",858:"cp858",860:"cp860",861:"cp861",862:"cp862",863:"cp863",864:"cp864",865:"cp865",866:"cp866",869:"cp869",874:"windows874",922:"cp922",1046:"cp1046",1124:"cp1124",1125:"cp1125",1129:"cp1129",1133:"cp1133",1161:"cp1161",1162:"cp1162",1163:"cp1163",1250:"windows1250",1251:"windows1251",1252:"windows1252",1253:"windows1253",1254:"windows1254",1255:"windows1255",1256:"windows1256",1257:"windows1257",1258:"windows1258",28591:"iso88591",28592:"iso88592",28593:"iso88593",28594:"iso88594",28595:"iso88595",28596:"iso88596",28597:"iso88597",28598:"iso88598",28599:"iso88599",28600:"iso885910",28601:"iso885911",28603:"iso885913",28604:"iso885914",28605:"iso885915",28606:"iso885916",windows874:{type:"_sbcs",chars:"€����…�����������‘’“”•–—�������� กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},win874:"windows874",cp874:"windows874",windows1250:{type:"_sbcs",chars:"€�‚�„…†‡�‰Š‹ŚŤŽŹ�‘’“”•–—�™š›śťžź ˇ˘Ł¤Ą¦§¨©Ş«¬­®Ż°±˛ł´µ¶·¸ąş»Ľ˝ľżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙"},win1250:"windows1250",cp1250:"windows1250",windows1251:{type:"_sbcs",chars:"ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—�™љ›њќћџ ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·ё№є»јЅѕїАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},win1251:"windows1251",cp1251:"windows1251",windows1252:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰Š‹Œ�Ž��‘’“”•–—˜™š›œ�žŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},win1252:"windows1252",cp1252:"windows1252",windows1253:{type:"_sbcs",chars:"€�‚ƒ„…†‡�‰�‹�����‘’“”•–—�™�›���� ΅Ά£¤¥¦§¨©�«¬­®―°±²³΄µ¶·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�"},win1253:"windows1253",cp1253:"windows1253",windows1254:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰Š‹Œ����‘’“”•–—˜™š›œ��Ÿ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ"},win1254:"windows1254",cp1254:"windows1254",windows1255:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰�‹�����‘’“”•–—˜™�›���� ¡¢£₪¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾¿ְֱֲֳִֵֶַָֹֺֻּֽ־ֿ׀ׁׂ׃װױײ׳״�������אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�"},win1255:"windows1255",cp1255:"windows1255",windows1256:{type:"_sbcs",chars:"€پ‚ƒ„…†‡ˆ‰ٹ‹Œچژڈگ‘’“”•–—ک™ڑ›œ‌‍ں ،¢£¤¥¦§¨©ھ«¬­®¯°±²³´µ¶·¸¹؛»¼½¾؟ہءآأؤإئابةتثجحخدذرزسشصض×طظعغـفقكàلâمنهوçèéêëىيîïًٌٍَôُِ÷ّùْûü‎‏ے"},win1256:"windows1256",cp1256:"windows1256",windows1257:{type:"_sbcs",chars:"€�‚�„…†‡�‰�‹�¨ˇ¸�‘’“”•–—�™�›�¯˛� �¢£¤�¦§Ø©Ŗ«¬­®Æ°±²³´µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž˙"},win1257:"windows1257",cp1257:"windows1257",windows1258:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰�‹Œ����‘’“”•–—˜™�›œ��Ÿ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},win1258:"windows1258",cp1258:"windows1258",iso88591:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},cp28591:"iso88591",iso88592:{type:"_sbcs",chars:" Ą˘Ł¤ĽŚ§¨ŠŞŤŹ­ŽŻ°ą˛ł´ľśˇ¸šşťź˝žżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙"},cp28592:"iso88592",iso88593:{type:"_sbcs",chars:" Ħ˘£¤�Ĥ§¨İŞĞĴ­�Ż°ħ²³´µĥ·¸ışğĵ½�żÀÁÂ�ÄĊĈÇÈÉÊËÌÍÎÏ�ÑÒÓÔĠÖ×ĜÙÚÛÜŬŜßàáâ�äċĉçèéêëìíîï�ñòóôġö÷ĝùúûüŭŝ˙"},cp28593:"iso88593",iso88594:{type:"_sbcs",chars:" ĄĸŖ¤ĨĻ§¨ŠĒĢŦ­Ž¯°ą˛ŗ´ĩļˇ¸šēģŧŊžŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎĪĐŅŌĶÔÕÖ×ØŲÚÛÜŨŪßāáâãäåæįčéęëėíîīđņōķôõö÷øųúûüũū˙"},cp28594:"iso88594",iso88595:{type:"_sbcs",chars:" ЁЂЃЄЅІЇЈЉЊЋЌ­ЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя№ёђѓєѕіїјљњћќ§ўџ"},cp28595:"iso88595",iso88596:{type:"_sbcs",chars:" ���¤�������،­�������������؛���؟�ءآأؤإئابةتثجحخدذرزسشصضطظعغ�����ـفقكلمنهوىيًٌٍَُِّْ�������������"},cp28596:"iso88596",iso88597:{type:"_sbcs",chars:" ‘’£€₯¦§¨©ͺ«¬­�―°±²³΄΅Ά·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�"},cp28597:"iso88597",iso88598:{type:"_sbcs",chars:" �¢£¤¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾��������������������������������‗אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�"},cp28598:"iso88598",iso88599:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ"},cp28599:"iso88599",iso885910:{type:"_sbcs",chars:" ĄĒĢĪĨĶ§ĻĐŠŦŽ­ŪŊ°ąēģīĩķ·ļđšŧž―ūŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎÏÐŅŌÓÔÕÖŨØŲÚÛÜÝÞßāáâãäåæįčéęëėíîïðņōóôõöũøųúûüýþĸ"},cp28600:"iso885910",iso885911:{type:"_sbcs",chars:" กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},cp28601:"iso885911",iso885913:{type:"_sbcs",chars:" ”¢£¤„¦§Ø©Ŗ«¬­®Æ°±²³“µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž’"},cp28603:"iso885913",iso885914:{type:"_sbcs",chars:" Ḃḃ£ĊċḊ§Ẁ©ẂḋỲ­®ŸḞḟĠġṀṁ¶ṖẁṗẃṠỳẄẅṡÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏŴÑÒÓÔÕÖṪØÙÚÛÜÝŶßàáâãäåæçèéêëìíîïŵñòóôõöṫøùúûüýŷÿ"},cp28604:"iso885914",iso885915:{type:"_sbcs",chars:" ¡¢£€¥Š§š©ª«¬­®¯°±²³Žµ¶·ž¹º»ŒœŸ¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},cp28605:"iso885915",iso885916:{type:"_sbcs",chars:" ĄąŁ€„Š§š©Ș«Ź­źŻ°±ČłŽ”¶·žčș»ŒœŸżÀÁÂĂÄĆÆÇÈÉÊËÌÍÎÏĐŃÒÓÔŐÖŚŰÙÚÛÜĘȚßàáâăäćæçèéêëìíîïđńòóôőöśűùúûüęțÿ"},cp28606:"iso885916",cp437:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm437:"cp437",csibm437:"cp437",cp737:{type:"_sbcs",chars:"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀ωάέήϊίόύϋώΆΈΉΊΌΎΏ±≥≤ΪΫ÷≈°∙·√ⁿ²■ "},ibm737:"cp737",csibm737:"cp737",cp775:{type:"_sbcs",chars:"ĆüéāäģåćłēŖŗīŹÄÅÉæÆōöĢ¢ŚśÖÜø£Ø×¤ĀĪóŻżź”¦©®¬½¼Ł«»░▒▓│┤ĄČĘĖ╣║╗╝ĮŠ┐└┴┬├─┼ŲŪ╚╔╩╦╠═╬Žąčęėįšųūž┘┌█▄▌▐▀ÓßŌŃõÕµńĶķĻļņĒŅ’­±“¾¶§÷„°∙·¹³²■ "},ibm775:"cp775",csibm775:"cp775",cp850:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm850:"cp850",csibm850:"cp850",cp852:{type:"_sbcs",chars:"ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁ×čáíóúĄąŽžĘę¬źČş«»░▒▓│┤ÁÂĚŞ╣║╗╝Żż┐└┴┬├─┼Ăă╚╔╩╦╠═╬¤đĐĎËďŇÍÎě┘┌█▄ŢŮ▀ÓßÔŃńňŠšŔÚŕŰýÝţ´­˝˛ˇ˘§÷¸°¨˙űŘř■ "},ibm852:"cp852",csibm852:"cp852",cp855:{type:"_sbcs",chars:"ђЂѓЃёЁєЄѕЅіІїЇјЈљЉњЊћЋќЌўЎџЏюЮъЪаАбБцЦдДеЕфФгГ«»░▒▓│┤хХиИ╣║╗╝йЙ┐└┴┬├─┼кК╚╔╩╦╠═╬¤лЛмМнНоОп┘┌█▄Пя▀ЯрРсСтТуУжЖвВьЬ№­ыЫзЗшШэЭщЩчЧ§■ "},ibm855:"cp855",csibm855:"cp855",cp856:{type:"_sbcs",chars:"אבגדהוזחטיךכלםמןנסעףפץצקרשת�£�×����������®¬½¼�«»░▒▓│┤���©╣║╗╝¢¥┐└┴┬├─┼��╚╔╩╦╠═╬¤���������┘┌█▄¦�▀������µ�������¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm856:"cp856",csibm856:"cp856",cp857:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîıÄÅÉæÆôöòûùİÖÜø£ØŞşáíóúñÑĞğ¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ºªÊËÈ�ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµ�×ÚÛÙìÿ¯´­±�¾¶§÷¸°¨·¹³²■ "},ibm857:"cp857",csibm857:"cp857",cp858:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈ€ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm858:"cp858",csibm858:"cp858",cp860:{type:"_sbcs",chars:"ÇüéâãàÁçêÊèÍÔìÃÂÉÀÈôõòÚùÌÕÜ¢£Ù₧ÓáíóúñÑªº¿Ò¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm860:"cp860",csibm860:"cp860",cp861:{type:"_sbcs",chars:"ÇüéâäàåçêëèÐðÞÄÅÉæÆôöþûÝýÖÜø£Ø₧ƒáíóúÁÍÓÚ¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm861:"cp861",csibm861:"cp861",cp862:{type:"_sbcs",chars:"אבגדהוזחטיךכלםמןנסעףפץצקרשת¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm862:"cp862",csibm862:"cp862",cp863:{type:"_sbcs",chars:"ÇüéâÂà¶çêëèïî‗À§ÉÈÊôËÏûù¤ÔÜ¢£ÙÛƒ¦´óú¨¸³¯Î⌐¬½¼¾«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm863:"cp863",csibm863:"cp863",cp864:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#$٪&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~°·∙√▒─│┼┤┬├┴┐┌└┘β∞φ±½¼≈«»ﻷﻸ��ﻻﻼ� ­ﺂ£¤ﺄ��ﺎﺏﺕﺙ،ﺝﺡﺥ٠١٢٣٤٥٦٧٨٩ﻑ؛ﺱﺵﺹ؟¢ﺀﺁﺃﺅﻊﺋﺍﺑﺓﺗﺛﺟﺣﺧﺩﺫﺭﺯﺳﺷﺻﺿﻁﻅﻋﻏ¦¬÷×ﻉـﻓﻗﻛﻟﻣﻧﻫﻭﻯﻳﺽﻌﻎﻍﻡﹽّﻥﻩﻬﻰﻲﻐﻕﻵﻶﻝﻙﻱ■�"},ibm864:"cp864",csibm864:"cp864",cp865:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø₧ƒáíóúñÑªº¿⌐¬½¼¡«¤░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm865:"cp865",csibm865:"cp865",cp866:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■ "},ibm866:"cp866",csibm866:"cp866",cp869:{type:"_sbcs",chars:"������Ά�·¬¦‘’Έ―ΉΊΪΌ��ΎΫ©Ώ²³ά£έήίϊΐόύΑΒΓΔΕΖΗ½ΘΙ«»░▒▓│┤ΚΛΜΝ╣║╗╝ΞΟ┐└┴┬├─┼ΠΡ╚╔╩╦╠═╬ΣΤΥΦΧΨΩαβγ┘┌█▄δε▀ζηθικλμνξοπρσςτ΄­±υφχ§ψ΅°¨ωϋΰώ■ "},ibm869:"cp869",csibm869:"cp869",cp922:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®‾°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏŠÑÒÓÔÕÖ×ØÙÚÛÜÝŽßàáâãäåæçèéêëìíîïšñòóôõö÷øùúûüýžÿ"},ibm922:"cp922",csibm922:"cp922",cp1046:{type:"_sbcs",chars:"ﺈ×÷ﹱ■│─┐┌└┘ﹹﹻﹽﹿﹷﺊﻰﻳﻲﻎﻏﻐﻶﻸﻺﻼ ¤ﺋﺑﺗﺛﺟﺣ،­ﺧﺳ٠١٢٣٤٥٦٧٨٩ﺷ؛ﺻﺿﻊ؟ﻋءآأؤإئابةتثجحخدذرزسشصضطﻇعغﻌﺂﺄﺎﻓـفقكلمنهوىيًٌٍَُِّْﻗﻛﻟﻵﻷﻹﻻﻣﻧﻬﻩ�"},ibm1046:"cp1046",csibm1046:"cp1046",cp1124:{type:"_sbcs",chars:" ЁЂҐЄЅІЇЈЉЊЋЌ­ЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя№ёђґєѕіїјљњћќ§ўџ"},ibm1124:"cp1124",csibm1124:"cp1124",cp1125:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёҐґЄєІіЇї·√№¤■ "},ibm1125:"cp1125",csibm1125:"cp1125",cp1129:{type:"_sbcs",chars:" ¡¢£¤¥¦§œ©ª«¬­®¯°±²³Ÿµ¶·Œ¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},ibm1129:"cp1129",csibm1129:"cp1129",cp1133:{type:"_sbcs",chars:" ກຂຄງຈສຊຍດຕຖທນບປຜຝພຟມຢຣລວຫອຮ���ຯະາຳິີຶືຸູຼັົຽ���ເແໂໃໄ່້໊໋໌ໍໆ�ໜໝ₭����������������໐໑໒໓໔໕໖໗໘໙��¢¬¦�"},ibm1133:"cp1133",csibm1133:"cp1133",cp1161:{type:"_sbcs",chars:"��������������������������������่กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู้๊๋€฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛¢¬¦ "},ibm1161:"cp1161",csibm1161:"cp1161",cp1162:{type:"_sbcs",chars:"€…‘’“”•–— กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},ibm1162:"cp1162",csibm1162:"cp1162",cp1163:{type:"_sbcs",chars:" ¡¢£€¥¦§œ©ª«¬­®¯°±²³Ÿµ¶·Œ¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},ibm1163:"cp1163",csibm1163:"cp1163",maccroatian:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®Š™´¨≠ŽØ∞±≤≥∆µ∂∑∏š∫ªºΩžø¿¡¬√ƒ≈Ć«Č… ÀÃÕŒœĐ—“”‘’÷◊�©⁄¤‹›Æ»–·‚„‰ÂćÁčÈÍÎÏÌÓÔđÒÚÛÙıˆ˜¯πË˚¸Êæˇ"},maccyrillic:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ†°¢£§•¶І®©™Ђђ≠Ѓѓ∞±≤≥іµ∂ЈЄєЇїЉљЊњјЅ¬√ƒ≈∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёяабвгдежзийклмнопрстуфхцчшщъыьэю¤"},macgreek:{type:"_sbcs",chars:"Ä¹²É³ÖÜ΅àâä΄¨çéèêë£™îï•½‰ôö¦­ùûü†ΓΔΘΛΞΠß®©ΣΪ§≠°·Α±≤≥¥ΒΕΖΗΙΚΜΦΫΨΩάΝ¬ΟΡ≈Τ«»… ΥΧΆΈœ–―“”‘’÷ΉΊΌΎέήίόΏύαβψδεφγηιξκλμνοπώρστθωςχυζϊϋΐΰ�"},maciceland:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûüÝ°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤ÐðÞþý·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macroman:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macromania:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ĂŞ∞±≤≥¥µ∂∑∏π∫ªºΩăş¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›Ţţ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macthai:{type:"_sbcs",chars:"«»…“”�•‘’� กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู\ufeff​–—฿เแโใไๅๆ็่้๊๋์ํ™๏๐๑๒๓๔๕๖๗๘๙®©����"},macturkish:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸĞğİıŞş‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙ�ˆ˜¯˘˙˚¸˝˛ˇ"},macukraine:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ†°Ґ£§•¶І®©™Ђђ≠Ѓѓ∞±≤≥іµґЈЄєЇїЉљЊњјЅ¬√ƒ≈∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёяабвгдежзийклмнопрстуфхцчшщъыьэю¤"},koi8r:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8u:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ёє╔ії╗╘╙╚╛ґ╝╞╟╠╡ЁЄ╣ІЇ╦╧╨╩╪Ґ╬©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8ru:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ёє╔ії╗╘╙╚╛ґў╞╟╠╡ЁЄ╣ІЇ╦╧╨╩╪ҐЎ©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8t:{type:"_sbcs",chars:"қғ‚Ғ„…†‡�‰ҳ‹ҲҷҶ�Қ‘’“”•–—�™�›�����ӯӮё¤ӣ¦§���«¬­®�°±²Ё�Ӣ¶·�№�»���©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},armscii8:{type:"_sbcs",chars:" �և։)(»«—.՝,-֊…՜՛՞ԱաԲբԳգԴդԵեԶզԷէԸըԹթԺժԻիԼլԽխԾծԿկՀհՁձՂղՃճՄմՅյՆնՇշՈոՉչՊպՋջՌռՍսՎվՏտՐրՑցՒւՓփՔքՕօՖֆ՚�"},rk1048:{type:"_sbcs",chars:"ЂЃ‚ѓ„…†‡€‰Љ‹ЊҚҺЏђ‘’“”•–—�™љ›њқһџ ҰұӘ¤Ө¦§Ё©Ғ«¬­®Ү°±Ііөµ¶·ё№ғ»әҢңүАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},tcvn:{type:"_sbcs",chars:"\0ÚỤỪỬỮ\b\t\n\v\f\rỨỰỲỶỸÝỴ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ÀẢÃÁẠẶẬÈẺẼÉẸỆÌỈĨÍỊÒỎÕÓỌỘỜỞỠỚỢÙỦŨ ĂÂÊÔƠƯĐăâêôơưđẶ̀̀̉̃́àảãáạẲằẳẵắẴẮẦẨẪẤỀặầẩẫấậèỂẻẽéẹềểễếệìỉỄẾỒĩíịòỔỏõóọồổỗốộờởỡớợùỖủũúụừửữứựỳỷỹýỵỐ"},georgianacademy:{type:"_sbcs",chars:"‚ƒ„…†‡ˆ‰Š‹Œ‘’“”•–—˜™š›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰჱჲჳჴჵჶçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},georgianps:{type:"_sbcs",chars:"‚ƒ„…†‡ˆ‰Š‹Œ‘’“”•–—˜™š›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿აბგდევზჱთიკლმნჲოპჟრსტჳუფქღყშჩცძწჭხჴჯჰჵæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},pt154:{type:"_sbcs",chars:"ҖҒӮғ„…ҶҮҲүҠӢҢҚҺҸҗ‘’“”•–—ҳҷҡӣңқһҹ ЎўЈӨҘҰ§Ё©Ә«¬ӯ®Ҝ°ұІіҙө¶·ё№ә»јҪҫҝАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},viscii:{type:"_sbcs",chars:"\0ẲẴẪ\b\t\n\v\f\rỶỸỴ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ẠẮẰẶẤẦẨẬẼẸẾỀỂỄỆỐỒỔỖỘỢỚỜỞỊỎỌỈỦŨỤỲÕắằặấầẩậẽẹếềểễệốồổỗỠƠộờởịỰỨỪỬơớƯÀÁÂÃẢĂẳẵÈÉÊẺÌÍĨỳĐứÒÓÔạỷừửÙÚỹỵÝỡưàáâãảăữẫèéêẻìíĩỉđựòóôõỏọụùúũủýợỮ"},iso646cn:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#¥%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}‾��������������������������������������������������������������������������������������������������������������������������������"},iso646jp:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[¥]^_`abcdefghijklmnopqrstuvwxyz{|}‾��������������������������������������������������������������������������������������������������������������������������������"},hproman8:{type:"_sbcs",chars:" ÀÂÈÊËÎÏ´ˋˆ¨˜ÙÛ₤¯Ýý°ÇçÑñ¡¿¤£¥§ƒ¢âêôûáéóúàèòùäëöüÅîØÆåíøæÄìÖÜÉïßÔÁÃãÐðÍÌÓÒÕõŠšÚŸÿÞþ·µ¶¾—¼½ªº«■»±�"},macintosh:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},ascii:{type:"_sbcs",chars:"��������������������������������������������������������������������������������������������������������������������������������"},tis620:{type:"_sbcs",chars:"���������������������������������กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"}}},165:function(e,t){"use strict";var r="\ufeff";t.PrependBOM=PrependBOMWrapper;function PrependBOMWrapper(e,t){this.encoder=e;this.addBOM=true}PrependBOMWrapper.prototype.write=function(e){if(this.addBOM){e=r+e;this.addBOM=false}return this.encoder.write(e)};PrependBOMWrapper.prototype.end=function(){return this.encoder.end()};t.StripBOM=StripBOMWrapper;function StripBOMWrapper(e,t){this.decoder=e;this.pass=false;this.options=t||{}}StripBOMWrapper.prototype.write=function(e){var t=this.decoder.write(e);if(this.pass||!t)return t;if(t[0]===r){t=t.slice(1);if(typeof this.options.stripBOM==="function")this.options.stripBOM()}this.pass=true;return t};StripBOMWrapper.prototype.end=function(){return this.decoder.end()}},189:function(e,t,r){"use strict";var i=r(293).Buffer,n=r(413).Transform;e.exports=function(e){e.encodeStream=function encodeStream(t,r){return new IconvLiteEncoderStream(e.getEncoder(t,r),r)};e.decodeStream=function decodeStream(t,r){return new IconvLiteDecoderStream(e.getDecoder(t,r),r)};e.supportsStreams=true;e.IconvLiteEncoderStream=IconvLiteEncoderStream;e.IconvLiteDecoderStream=IconvLiteDecoderStream;e._collect=IconvLiteDecoderStream.prototype.collect};function IconvLiteEncoderStream(e,t){this.conv=e;t=t||{};t.decodeStrings=false;n.call(this,t)}IconvLiteEncoderStream.prototype=Object.create(n.prototype,{constructor:{value:IconvLiteEncoderStream}});IconvLiteEncoderStream.prototype._transform=function(e,t,r){if(typeof e!="string")return r(new Error("Iconv encoding stream needs strings as its input."));try{var i=this.conv.write(e);if(i&&i.length)this.push(i);r()}catch(e){r(e)}};IconvLiteEncoderStream.prototype._flush=function(e){try{var t=this.conv.end();if(t&&t.length)this.push(t);e()}catch(t){e(t)}};IconvLiteEncoderStream.prototype.collect=function(e){var t=[];this.on("error",e);this.on("data",function(e){t.push(e)});this.on("end",function(){e(null,i.concat(t))});return this};function IconvLiteDecoderStream(e,t){this.conv=e;t=t||{};t.encoding=this.encoding="utf8";n.call(this,t)}IconvLiteDecoderStream.prototype=Object.create(n.prototype,{constructor:{value:IconvLiteDecoderStream}});IconvLiteDecoderStream.prototype._transform=function(e,t,r){if(!i.isBuffer(e))return r(new Error("Iconv decoding stream needs buffers as its input."));try{var n=this.conv.write(e);if(n&&n.length)this.push(n,this.encoding);r()}catch(e){r(e)}};IconvLiteDecoderStream.prototype._flush=function(e){try{var t=this.conv.end();if(t&&t.length)this.push(t,this.encoding);e()}catch(t){e(t)}};IconvLiteDecoderStream.prototype.collect=function(e){var t="";this.on("error",e);this.on("data",function(e){t+=e});this.on("end",function(){e(null,t)});return this}},212:function(e,t,r){try{var i=r(669);if(typeof i.inherits!=="function")throw"";e.exports=i.inherits}catch(t){e.exports=r(223)}},223:function(e){if(typeof Object.create==="function"){e.exports=function inherits(e,t){if(t){e.super_=t;e.prototype=Object.create(t.prototype,{constructor:{value:e,enumerable:false,writable:true,configurable:true}})}}}else{e.exports=function inherits(e,t){if(t){e.super_=t;var r=function(){};r.prototype=t.prototype;e.prototype=new r;e.prototype.constructor=e}}}},237:function(e){e.exports=[["0","\0",127],["8141","갂갃갅갆갋",4,"갘갞갟갡갢갣갥",6,"갮갲갳갴"],["8161","갵갶갷갺갻갽갾갿걁",9,"걌걎",5,"걕"],["8181","걖걗걙걚걛걝",18,"걲걳걵걶걹걻",4,"겂겇겈겍겎겏겑겒겓겕",6,"겞겢",5,"겫겭겮겱",6,"겺겾겿곀곂곃곅곆곇곉곊곋곍",7,"곖곘",7,"곢곣곥곦곩곫곭곮곲곴곷",4,"곾곿괁괂괃괅괇",4,"괎괐괒괓"],["8241","괔괕괖괗괙괚괛괝괞괟괡",7,"괪괫괮",5],["8261","괶괷괹괺괻괽",6,"굆굈굊",5,"굑굒굓굕굖굗"],["8281","굙",7,"굢굤",7,"굮굯굱굲굷굸굹굺굾궀궃",4,"궊궋궍궎궏궑",10,"궞",5,"궥",17,"궸",7,"귂귃귅귆귇귉",6,"귒귔",7,"귝귞귟귡귢귣귥",18],["8341","귺귻귽귾긂",5,"긊긌긎",5,"긕",7],["8361","긝",18,"긲긳긵긶긹긻긼"],["8381","긽긾긿깂깄깇깈깉깋깏깑깒깓깕깗",4,"깞깢깣깤깦깧깪깫깭깮깯깱",6,"깺깾",5,"꺆",5,"꺍",46,"꺿껁껂껃껅",6,"껎껒",5,"껚껛껝",8],["8441","껦껧껩껪껬껮",5,"껵껶껷껹껺껻껽",8],["8461","꼆꼉꼊꼋꼌꼎꼏꼑",18],["8481","꼤",7,"꼮꼯꼱꼳꼵",6,"꼾꽀꽄꽅꽆꽇꽊",5,"꽑",10,"꽞",5,"꽦",18,"꽺",5,"꾁꾂꾃꾅꾆꾇꾉",6,"꾒꾓꾔꾖",5,"꾝",26,"꾺꾻꾽꾾"],["8541","꾿꿁",5,"꿊꿌꿏",4,"꿕",6,"꿝",4],["8561","꿢",5,"꿪",5,"꿲꿳꿵꿶꿷꿹",6,"뀂뀃"],["8581","뀅",6,"뀍뀎뀏뀑뀒뀓뀕",6,"뀞",9,"뀩",26,"끆끇끉끋끍끏끐끑끒끖끘끚끛끜끞",29,"끾끿낁낂낃낅",6,"낎낐낒",5,"낛낝낞낣낤"],["8641","낥낦낧낪낰낲낶낷낹낺낻낽",6,"냆냊",5,"냒"],["8661","냓냕냖냗냙",6,"냡냢냣냤냦",10],["8681","냱",22,"넊넍넎넏넑넔넕넖넗넚넞",4,"넦넧넩넪넫넭",6,"넶넺",5,"녂녃녅녆녇녉",6,"녒녓녖녗녙녚녛녝녞녟녡",22,"녺녻녽녾녿놁놃",4,"놊놌놎놏놐놑놕놖놗놙놚놛놝"],["8741","놞",9,"놩",15],["8761","놹",18,"뇍뇎뇏뇑뇒뇓뇕"],["8781","뇖",5,"뇞뇠",7,"뇪뇫뇭뇮뇯뇱",7,"뇺뇼뇾",5,"눆눇눉눊눍",6,"눖눘눚",5,"눡",18,"눵",6,"눽",26,"뉙뉚뉛뉝뉞뉟뉡",6,"뉪",4],["8841","뉯",4,"뉶",5,"뉽",6,"늆늇늈늊",4],["8861","늏늒늓늕늖늗늛",4,"늢늤늧늨늩늫늭늮늯늱늲늳늵늶늷"],["8881","늸",15,"닊닋닍닎닏닑닓",4,"닚닜닞닟닠닡닣닧닩닪닰닱닲닶닼닽닾댂댃댅댆댇댉",6,"댒댖",5,"댝",54,"덗덙덚덝덠덡덢덣"],["8941","덦덨덪덬덭덯덲덳덵덶덷덹",6,"뎂뎆",5,"뎍"],["8961","뎎뎏뎑뎒뎓뎕",10,"뎢",5,"뎩뎪뎫뎭"],["8981","뎮",21,"돆돇돉돊돍돏돑돒돓돖돘돚돜돞돟돡돢돣돥돦돧돩",18,"돽",18,"됑",6,"됙됚됛됝됞됟됡",6,"됪됬",7,"됵",15],["8a41","둅",10,"둒둓둕둖둗둙",6,"둢둤둦"],["8a61","둧",4,"둭",18,"뒁뒂"],["8a81","뒃",4,"뒉",19,"뒞",5,"뒥뒦뒧뒩뒪뒫뒭",7,"뒶뒸뒺",5,"듁듂듃듅듆듇듉",6,"듑듒듓듔듖",5,"듞듟듡듢듥듧",4,"듮듰듲",5,"듹",26,"딖딗딙딚딝"],["8b41","딞",5,"딦딫",4,"딲딳딵딶딷딹",6,"땂땆"],["8b61","땇땈땉땊땎땏땑땒땓땕",6,"땞땢",8],["8b81","땫",52,"떢떣떥떦떧떩떬떭떮떯떲떶",4,"떾떿뗁뗂뗃뗅",6,"뗎뗒",5,"뗙",18,"뗭",18],["8c41","똀",15,"똒똓똕똖똗똙",4],["8c61","똞",6,"똦",5,"똭",6,"똵",5],["8c81","똻",12,"뙉",26,"뙥뙦뙧뙩",50,"뚞뚟뚡뚢뚣뚥",5,"뚭뚮뚯뚰뚲",16],["8d41","뛃",16,"뛕",8],["8d61","뛞",17,"뛱뛲뛳뛵뛶뛷뛹뛺"],["8d81","뛻",4,"뜂뜃뜄뜆",33,"뜪뜫뜭뜮뜱",6,"뜺뜼",7,"띅띆띇띉띊띋띍",6,"띖",9,"띡띢띣띥띦띧띩",6,"띲띴띶",5,"띾띿랁랂랃랅",6,"랎랓랔랕랚랛랝랞"],["8e41","랟랡",6,"랪랮",5,"랶랷랹",8],["8e61","럂",4,"럈럊",19],["8e81","럞",13,"럮럯럱럲럳럵",6,"럾렂",4,"렊렋렍렎렏렑",6,"렚렜렞",5,"렦렧렩렪렫렭",6,"렶렺",5,"롁롂롃롅",11,"롒롔",7,"롞롟롡롢롣롥",6,"롮롰롲",5,"롹롺롻롽",7],["8f41","뢅",7,"뢎",17],["8f61","뢠",7,"뢩",6,"뢱뢲뢳뢵뢶뢷뢹",4],["8f81","뢾뢿룂룄룆",5,"룍룎룏룑룒룓룕",7,"룞룠룢",5,"룪룫룭룮룯룱",6,"룺룼룾",5,"뤅",18,"뤙",6,"뤡",26,"뤾뤿륁륂륃륅",6,"륍륎륐륒",5],["9041","륚륛륝륞륟륡",6,"륪륬륮",5,"륶륷륹륺륻륽"],["9061","륾",5,"릆릈릋릌릏",15],["9081","릟",12,"릮릯릱릲릳릵",6,"릾맀맂",5,"맊맋맍맓",4,"맚맜맟맠맢맦맧맩맪맫맭",6,"맶맻",4,"먂",5,"먉",11,"먖",33,"먺먻먽먾먿멁멃멄멅멆"],["9141","멇멊멌멏멐멑멒멖멗멙멚멛멝",6,"멦멪",5],["9161","멲멳멵멶멷멹",9,"몆몈몉몊몋몍",5],["9181","몓",20,"몪몭몮몯몱몳",4,"몺몼몾",5,"뫅뫆뫇뫉",14,"뫚",33,"뫽뫾뫿묁묂묃묅",7,"묎묐묒",5,"묙묚묛묝묞묟묡",6],["9241","묨묪묬",7,"묷묹묺묿",4,"뭆뭈뭊뭋뭌뭎뭑뭒"],["9261","뭓뭕뭖뭗뭙",7,"뭢뭤",7,"뭭",4],["9281","뭲",21,"뮉뮊뮋뮍뮎뮏뮑",18,"뮥뮦뮧뮩뮪뮫뮭",6,"뮵뮶뮸",7,"믁믂믃믅믆믇믉",6,"믑믒믔",35,"믺믻믽믾밁"],["9341","밃",4,"밊밎밐밒밓밙밚밠밡밢밣밦밨밪밫밬밮밯밲밳밵"],["9361","밶밷밹",6,"뱂뱆뱇뱈뱊뱋뱎뱏뱑",8],["9381","뱚뱛뱜뱞",37,"벆벇벉벊벍벏",4,"벖벘벛",4,"벢벣벥벦벩",6,"벲벶",5,"벾벿볁볂볃볅",7,"볎볒볓볔볖볗볙볚볛볝",22,"볷볹볺볻볽"],["9441","볾",5,"봆봈봊",5,"봑봒봓봕",8],["9461","봞",5,"봥",6,"봭",12],["9481","봺",5,"뵁",6,"뵊뵋뵍뵎뵏뵑",6,"뵚",9,"뵥뵦뵧뵩",22,"붂붃붅붆붋",4,"붒붔붖붗붘붛붝",6,"붥",10,"붱",6,"붹",24],["9541","뷒뷓뷖뷗뷙뷚뷛뷝",11,"뷪",5,"뷱"],["9561","뷲뷳뷵뷶뷷뷹",6,"븁븂븄븆",5,"븎븏븑븒븓"],["9581","븕",6,"븞븠",35,"빆빇빉빊빋빍빏",4,"빖빘빜빝빞빟빢빣빥빦빧빩빫",4,"빲빶",4,"빾빿뺁뺂뺃뺅",6,"뺎뺒",5,"뺚",13,"뺩",14],["9641","뺸",23,"뻒뻓"],["9661","뻕뻖뻙",6,"뻡뻢뻦",5,"뻭",8],["9681","뻶",10,"뼂",5,"뼊",13,"뼚뼞",33,"뽂뽃뽅뽆뽇뽉",6,"뽒뽓뽔뽖",44],["9741","뾃",16,"뾕",8],["9761","뾞",17,"뾱",7],["9781","뾹",11,"뿆",5,"뿎뿏뿑뿒뿓뿕",6,"뿝뿞뿠뿢",89,"쀽쀾쀿"],["9841","쁀",16,"쁒",5,"쁙쁚쁛"],["9861","쁝쁞쁟쁡",6,"쁪",15],["9881","쁺",21,"삒삓삕삖삗삙",6,"삢삤삦",5,"삮삱삲삷",4,"삾샂샃샄샆샇샊샋샍샎샏샑",6,"샚샞",5,"샦샧샩샪샫샭",6,"샶샸샺",5,"섁섂섃섅섆섇섉",6,"섑섒섓섔섖",5,"섡섢섥섨섩섪섫섮"],["9941","섲섳섴섵섷섺섻섽섾섿셁",6,"셊셎",5,"셖셗"],["9961","셙셚셛셝",6,"셦셪",5,"셱셲셳셵셶셷셹셺셻"],["9981","셼",8,"솆",5,"솏솑솒솓솕솗",4,"솞솠솢솣솤솦솧솪솫솭솮솯솱",11,"솾",5,"쇅쇆쇇쇉쇊쇋쇍",6,"쇕쇖쇙",6,"쇡쇢쇣쇥쇦쇧쇩",6,"쇲쇴",7,"쇾쇿숁숂숃숅",6,"숎숐숒",5,"숚숛숝숞숡숢숣"],["9a41","숤숥숦숧숪숬숮숰숳숵",16],["9a61","쉆쉇쉉",6,"쉒쉓쉕쉖쉗쉙",6,"쉡쉢쉣쉤쉦"],["9a81","쉧",4,"쉮쉯쉱쉲쉳쉵",6,"쉾슀슂",5,"슊",5,"슑",6,"슙슚슜슞",5,"슦슧슩슪슫슮",5,"슶슸슺",33,"싞싟싡싢싥",5,"싮싰싲싳싴싵싷싺싽싾싿쌁",6,"쌊쌋쌎쌏"],["9b41","쌐쌑쌒쌖쌗쌙쌚쌛쌝",6,"쌦쌧쌪",8],["9b61","쌳",17,"썆",7],["9b81","썎",25,"썪썫썭썮썯썱썳",4,"썺썻썾",5,"쎅쎆쎇쎉쎊쎋쎍",50,"쏁",22,"쏚"],["9c41","쏛쏝쏞쏡쏣",4,"쏪쏫쏬쏮",5,"쏶쏷쏹",5],["9c61","쏿",8,"쐉",6,"쐑",9],["9c81","쐛",8,"쐥",6,"쐭쐮쐯쐱쐲쐳쐵",6,"쐾",9,"쑉",26,"쑦쑧쑩쑪쑫쑭",6,"쑶쑷쑸쑺",5,"쒁",18,"쒕",6,"쒝",12],["9d41","쒪",13,"쒹쒺쒻쒽",8],["9d61","쓆",25],["9d81","쓠",8,"쓪",5,"쓲쓳쓵쓶쓷쓹쓻쓼쓽쓾씂",9,"씍씎씏씑씒씓씕",6,"씝",10,"씪씫씭씮씯씱",6,"씺씼씾",5,"앆앇앋앏앐앑앒앖앚앛앜앟앢앣앥앦앧앩",6,"앲앶",5,"앾앿얁얂얃얅얆얈얉얊얋얎얐얒얓얔"],["9e41","얖얙얚얛얝얞얟얡",7,"얪",9,"얶"],["9e61","얷얺얿",4,"엋엍엏엒엓엕엖엗엙",6,"엢엤엦엧"],["9e81","엨엩엪엫엯엱엲엳엵엸엹엺엻옂옃옄옉옊옋옍옎옏옑",6,"옚옝",6,"옦옧옩옪옫옯옱옲옶옸옺옼옽옾옿왂왃왅왆왇왉",6,"왒왖",5,"왞왟왡",10,"왭왮왰왲",5,"왺왻왽왾왿욁",6,"욊욌욎",5,"욖욗욙욚욛욝",6,"욦"],["9f41","욨욪",5,"욲욳욵욶욷욻",4,"웂웄웆",5,"웎"],["9f61","웏웑웒웓웕",6,"웞웟웢",5,"웪웫웭웮웯웱웲"],["9f81","웳",4,"웺웻웼웾",5,"윆윇윉윊윋윍",6,"윖윘윚",5,"윢윣윥윦윧윩",6,"윲윴윶윸윹윺윻윾윿읁읂읃읅",4,"읋읎읐읙읚읛읝읞읟읡",6,"읩읪읬",7,"읶읷읹읺읻읿잀잁잂잆잋잌잍잏잒잓잕잙잛",4,"잢잧",4,"잮잯잱잲잳잵잶잷"],["a041","잸잹잺잻잾쟂",5,"쟊쟋쟍쟏쟑",6,"쟙쟚쟛쟜"],["a061","쟞",5,"쟥쟦쟧쟩쟪쟫쟭",13],["a081","쟻",4,"젂젃젅젆젇젉젋",4,"젒젔젗",4,"젞젟젡젢젣젥",6,"젮젰젲",5,"젹젺젻젽젾젿졁",6,"졊졋졎",5,"졕",26,"졲졳졵졶졷졹졻",4,"좂좄좈좉좊좎",5,"좕",7,"좞좠좢좣좤"],["a141","좥좦좧좩",18,"좾좿죀죁"],["a161","죂죃죅죆죇죉죊죋죍",6,"죖죘죚",5,"죢죣죥"],["a181","죦",14,"죶",5,"죾죿줁줂줃줇",4,"줎　、。·‥…¨〃­―∥＼∼‘’“”〔〕〈",9,"±×÷≠≤≥∞∴°′″℃Å￠￡￥♂♀∠⊥⌒∂∇≡≒§※☆★○●◎◇◆□■△▲▽▼→←↑↓↔〓≪≫√∽∝∵∫∬∈∋⊆⊇⊂⊃∪∩∧∨￢"],["a241","줐줒",5,"줙",18],["a261","줭",6,"줵",18],["a281","쥈",7,"쥒쥓쥕쥖쥗쥙",6,"쥢쥤",7,"쥭쥮쥯⇒⇔∀∃´～ˇ˘˝˚˙¸˛¡¿ː∮∑∏¤℉‰◁◀▷▶♤♠♡♥♧♣⊙◈▣◐◑▒▤▥▨▧▦▩♨☏☎☜☞¶†‡↕↗↙↖↘♭♩♪♬㉿㈜№㏇™㏂㏘℡€®"],["a341","쥱쥲쥳쥵",6,"쥽",10,"즊즋즍즎즏"],["a361","즑",6,"즚즜즞",16],["a381","즯",16,"짂짃짅짆짉짋",4,"짒짔짗짘짛！",58,"￦］",32,"￣"],["a441","짞짟짡짣짥짦짨짩짪짫짮짲",5,"짺짻짽짾짿쨁쨂쨃쨄"],["a461","쨅쨆쨇쨊쨎",5,"쨕쨖쨗쨙",12],["a481","쨦쨧쨨쨪",28,"ㄱ",93],["a541","쩇",4,"쩎쩏쩑쩒쩓쩕",6,"쩞쩢",5,"쩩쩪"],["a561","쩫",17,"쩾",5,"쪅쪆"],["a581","쪇",16,"쪙",14,"ⅰ",9],["a5b0","Ⅰ",9],["a5c1","Α",16,"Σ",6],["a5e1","α",16,"σ",6],["a641","쪨",19,"쪾쪿쫁쫂쫃쫅"],["a661","쫆",5,"쫎쫐쫒쫔쫕쫖쫗쫚",5,"쫡",6],["a681","쫨쫩쫪쫫쫭",6,"쫵",18,"쬉쬊─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂┒┑┚┙┖┕┎┍┞┟┡┢┦┧┩┪┭┮┱┲┵┶┹┺┽┾╀╁╃",7],["a741","쬋",4,"쬑쬒쬓쬕쬖쬗쬙",6,"쬢",7],["a761","쬪",22,"쭂쭃쭄"],["a781","쭅쭆쭇쭊쭋쭍쭎쭏쭑",6,"쭚쭛쭜쭞",5,"쭥",7,"㎕㎖㎗ℓ㎘㏄㎣㎤㎥㎦㎙",9,"㏊㎍㎎㎏㏏㎈㎉㏈㎧㎨㎰",9,"㎀",4,"㎺",5,"㎐",4,"Ω㏀㏁㎊㎋㎌㏖㏅㎭㎮㎯㏛㎩㎪㎫㎬㏝㏐㏓㏃㏉㏜㏆"],["a841","쭭",10,"쭺",14],["a861","쮉",18,"쮝",6],["a881","쮤",19,"쮹",11,"ÆÐªĦ"],["a8a6","Ĳ"],["a8a8","ĿŁØŒºÞŦŊ"],["a8b1","㉠",27,"ⓐ",25,"①",14,"½⅓⅔¼¾⅛⅜⅝⅞"],["a941","쯅",14,"쯕",10],["a961","쯠쯡쯢쯣쯥쯦쯨쯪",18],["a981","쯽",14,"찎찏찑찒찓찕",6,"찞찟찠찣찤æđðħıĳĸŀłøœßþŧŋŉ㈀",27,"⒜",25,"⑴",14,"¹²³⁴ⁿ₁₂₃₄"],["aa41","찥찦찪찫찭찯찱",6,"찺찿",4,"챆챇챉챊챋챍챎"],["aa61","챏",4,"챖챚",5,"챡챢챣챥챧챩",6,"챱챲"],["aa81","챳챴챶",29,"ぁ",82],["ab41","첔첕첖첗첚첛첝첞첟첡",6,"첪첮",5,"첶첷첹"],["ab61","첺첻첽",6,"쳆쳈쳊",5,"쳑쳒쳓쳕",5],["ab81","쳛",8,"쳥",6,"쳭쳮쳯쳱",12,"ァ",85],["ac41","쳾쳿촀촂",5,"촊촋촍촎촏촑",6,"촚촜촞촟촠"],["ac61","촡촢촣촥촦촧촩촪촫촭",11,"촺",4],["ac81","촿",28,"쵝쵞쵟А",5,"ЁЖ",25],["acd1","а",5,"ёж",25],["ad41","쵡쵢쵣쵥",6,"쵮쵰쵲",5,"쵹",7],["ad61","춁",6,"춉",10,"춖춗춙춚춛춝춞춟"],["ad81","춠춡춢춣춦춨춪",5,"춱",18,"췅"],["ae41","췆",5,"췍췎췏췑",16],["ae61","췢",5,"췩췪췫췭췮췯췱",6,"췺췼췾",4],["ae81","츃츅츆츇츉츊츋츍",6,"츕츖츗츘츚",5,"츢츣츥츦츧츩츪츫"],["af41","츬츭츮츯츲츴츶",19],["af61","칊",13,"칚칛칝칞칢",5,"칪칬"],["af81","칮",5,"칶칷칹칺칻칽",6,"캆캈캊",5,"캒캓캕캖캗캙"],["b041","캚",5,"캢캦",5,"캮",12],["b061","캻",5,"컂",19],["b081","컖",13,"컦컧컩컪컭",6,"컶컺",5,"가각간갇갈갉갊감",7,"같",4,"갠갤갬갭갯갰갱갸갹갼걀걋걍걔걘걜거걱건걷걸걺검겁것겄겅겆겉겊겋게겐겔겜겝겟겠겡겨격겪견겯결겸겹겻겼경곁계곈곌곕곗고곡곤곧골곪곬곯곰곱곳공곶과곽관괄괆"],["b141","켂켃켅켆켇켉",6,"켒켔켖",5,"켝켞켟켡켢켣"],["b161","켥",6,"켮켲",5,"켹",11],["b181","콅",14,"콖콗콙콚콛콝",6,"콦콨콪콫콬괌괍괏광괘괜괠괩괬괭괴괵괸괼굄굅굇굉교굔굘굡굣구국군굳굴굵굶굻굼굽굿궁궂궈궉권궐궜궝궤궷귀귁귄귈귐귑귓규균귤그극근귿글긁금급긋긍긔기긱긴긷길긺김깁깃깅깆깊까깍깎깐깔깖깜깝깟깠깡깥깨깩깬깰깸"],["b241","콭콮콯콲콳콵콶콷콹",6,"쾁쾂쾃쾄쾆",5,"쾍"],["b261","쾎",18,"쾢",5,"쾩"],["b281","쾪",5,"쾱",18,"쿅",6,"깹깻깼깽꺄꺅꺌꺼꺽꺾껀껄껌껍껏껐껑께껙껜껨껫껭껴껸껼꼇꼈꼍꼐꼬꼭꼰꼲꼴꼼꼽꼿꽁꽂꽃꽈꽉꽐꽜꽝꽤꽥꽹꾀꾄꾈꾐꾑꾕꾜꾸꾹꾼꿀꿇꿈꿉꿋꿍꿎꿔꿜꿨꿩꿰꿱꿴꿸뀀뀁뀄뀌뀐뀔뀜뀝뀨끄끅끈끊끌끎끓끔끕끗끙"],["b341","쿌",19,"쿢쿣쿥쿦쿧쿩"],["b361","쿪",5,"쿲쿴쿶",5,"쿽쿾쿿퀁퀂퀃퀅",5],["b381","퀋",5,"퀒",5,"퀙",19,"끝끼끽낀낄낌낍낏낑나낙낚난낟날낡낢남납낫",4,"낱낳내낵낸낼냄냅냇냈냉냐냑냔냘냠냥너넉넋넌널넒넓넘넙넛넜넝넣네넥넨넬넴넵넷넸넹녀녁년녈념녑녔녕녘녜녠노녹논놀놂놈놉놋농높놓놔놘놜놨뇌뇐뇔뇜뇝"],["b441","퀮",5,"퀶퀷퀹퀺퀻퀽",6,"큆큈큊",5],["b461","큑큒큓큕큖큗큙",6,"큡",10,"큮큯"],["b481","큱큲큳큵",6,"큾큿킀킂",18,"뇟뇨뇩뇬뇰뇹뇻뇽누눅눈눋눌눔눕눗눙눠눴눼뉘뉜뉠뉨뉩뉴뉵뉼늄늅늉느늑는늘늙늚늠늡늣능늦늪늬늰늴니닉닌닐닒님닙닛닝닢다닥닦단닫",4,"닳담답닷",4,"닿대댁댄댈댐댑댓댔댕댜더덕덖던덛덜덞덟덤덥"],["b541","킕",14,"킦킧킩킪킫킭",5],["b561","킳킶킸킺",5,"탂탃탅탆탇탊",5,"탒탖",4],["b581","탛탞탟탡탢탣탥",6,"탮탲",5,"탹",11,"덧덩덫덮데덱덴델뎀뎁뎃뎄뎅뎌뎐뎔뎠뎡뎨뎬도독돈돋돌돎돐돔돕돗동돛돝돠돤돨돼됐되된될됨됩됫됴두둑둔둘둠둡둣둥둬뒀뒈뒝뒤뒨뒬뒵뒷뒹듀듄듈듐듕드득든듣들듦듬듭듯등듸디딕딘딛딜딤딥딧딨딩딪따딱딴딸"],["b641","턅",7,"턎",17],["b661","턠",15,"턲턳턵턶턷턹턻턼턽턾"],["b681","턿텂텆",5,"텎텏텑텒텓텕",6,"텞텠텢",5,"텩텪텫텭땀땁땃땄땅땋때땍땐땔땜땝땟땠땡떠떡떤떨떪떫떰떱떳떴떵떻떼떽뗀뗄뗌뗍뗏뗐뗑뗘뗬또똑똔똘똥똬똴뙈뙤뙨뚜뚝뚠뚤뚫뚬뚱뛔뛰뛴뛸뜀뜁뜅뜨뜩뜬뜯뜰뜸뜹뜻띄띈띌띔띕띠띤띨띰띱띳띵라락란랄람랍랏랐랑랒랖랗"],["b741","텮",13,"텽",6,"톅톆톇톉톊"],["b761","톋",20,"톢톣톥톦톧"],["b781","톩",6,"톲톴톶톷톸톹톻톽톾톿퇁",14,"래랙랜랠램랩랫랬랭랴략랸럇량러럭런럴럼럽럿렀렁렇레렉렌렐렘렙렛렝려력련렬렴렵렷렸령례롄롑롓로록론롤롬롭롯롱롸롼뢍뢨뢰뢴뢸룀룁룃룅료룐룔룝룟룡루룩룬룰룸룹룻룽뤄뤘뤠뤼뤽륀륄륌륏륑류륙륜률륨륩"],["b841","퇐",7,"퇙",17],["b861","퇫",8,"퇵퇶퇷퇹",13],["b881","툈툊",5,"툑",24,"륫륭르륵른를름릅릇릉릊릍릎리릭린릴림립릿링마막만많",4,"맘맙맛망맞맡맣매맥맨맬맴맵맷맸맹맺먀먁먈먕머먹먼멀멂멈멉멋멍멎멓메멕멘멜멤멥멧멨멩며멱면멸몃몄명몇몌모목몫몬몰몲몸몹못몽뫄뫈뫘뫙뫼"],["b941","툪툫툮툯툱툲툳툵",6,"툾퉀퉂",5,"퉉퉊퉋퉌"],["b961","퉍",14,"퉝",6,"퉥퉦퉧퉨"],["b981","퉩",22,"튂튃튅튆튇튉튊튋튌묀묄묍묏묑묘묜묠묩묫무묵묶문묻물묽묾뭄뭅뭇뭉뭍뭏뭐뭔뭘뭡뭣뭬뮈뮌뮐뮤뮨뮬뮴뮷므믄믈믐믓미믹민믿밀밂밈밉밋밌밍및밑바",4,"받",4,"밤밥밧방밭배백밴밸뱀뱁뱃뱄뱅뱉뱌뱍뱐뱝버벅번벋벌벎범법벗"],["ba41","튍튎튏튒튓튔튖",5,"튝튞튟튡튢튣튥",6,"튭"],["ba61","튮튯튰튲",5,"튺튻튽튾틁틃",4,"틊틌",5],["ba81","틒틓틕틖틗틙틚틛틝",6,"틦",9,"틲틳틵틶틷틹틺벙벚베벡벤벧벨벰벱벳벴벵벼벽변별볍볏볐병볕볘볜보복볶본볼봄봅봇봉봐봔봤봬뵀뵈뵉뵌뵐뵘뵙뵤뵨부북분붇불붉붊붐붑붓붕붙붚붜붤붰붸뷔뷕뷘뷜뷩뷰뷴뷸븀븃븅브븍븐블븜븝븟비빅빈빌빎빔빕빗빙빚빛빠빡빤"],["bb41","틻",4,"팂팄팆",5,"팏팑팒팓팕팗",4,"팞팢팣"],["bb61","팤팦팧팪팫팭팮팯팱",6,"팺팾",5,"퍆퍇퍈퍉"],["bb81","퍊",31,"빨빪빰빱빳빴빵빻빼빽뺀뺄뺌뺍뺏뺐뺑뺘뺙뺨뻐뻑뻔뻗뻘뻠뻣뻤뻥뻬뼁뼈뼉뼘뼙뼛뼜뼝뽀뽁뽄뽈뽐뽑뽕뾔뾰뿅뿌뿍뿐뿔뿜뿟뿡쀼쁑쁘쁜쁠쁨쁩삐삑삔삘삠삡삣삥사삭삯산삳살삵삶삼삽삿샀상샅새색샌샐샘샙샛샜생샤"],["bc41","퍪",17,"퍾퍿펁펂펃펅펆펇"],["bc61","펈펉펊펋펎펒",5,"펚펛펝펞펟펡",6,"펪펬펮"],["bc81","펯",4,"펵펶펷펹펺펻펽",6,"폆폇폊",5,"폑",5,"샥샨샬샴샵샷샹섀섄섈섐섕서",4,"섣설섦섧섬섭섯섰성섶세섹센셀셈셉셋셌셍셔셕션셜셤셥셧셨셩셰셴셸솅소속솎손솔솖솜솝솟송솥솨솩솬솰솽쇄쇈쇌쇔쇗쇘쇠쇤쇨쇰쇱쇳쇼쇽숀숄숌숍숏숑수숙순숟술숨숩숫숭"],["bd41","폗폙",7,"폢폤",7,"폮폯폱폲폳폵폶폷"],["bd61","폸폹폺폻폾퐀퐂",5,"퐉",13],["bd81","퐗",5,"퐞",25,"숯숱숲숴쉈쉐쉑쉔쉘쉠쉥쉬쉭쉰쉴쉼쉽쉿슁슈슉슐슘슛슝스슥슨슬슭슴습슷승시식신싣실싫심십싯싱싶싸싹싻싼쌀쌈쌉쌌쌍쌓쌔쌕쌘쌜쌤쌥쌨쌩썅써썩썬썰썲썸썹썼썽쎄쎈쎌쏀쏘쏙쏜쏟쏠쏢쏨쏩쏭쏴쏵쏸쐈쐐쐤쐬쐰"],["be41","퐸",7,"푁푂푃푅",14],["be61","푔",7,"푝푞푟푡푢푣푥",7,"푮푰푱푲"],["be81","푳",4,"푺푻푽푾풁풃",4,"풊풌풎",5,"풕",8,"쐴쐼쐽쑈쑤쑥쑨쑬쑴쑵쑹쒀쒔쒜쒸쒼쓩쓰쓱쓴쓸쓺쓿씀씁씌씐씔씜씨씩씬씰씸씹씻씽아악안앉않알앍앎앓암압앗았앙앝앞애액앤앨앰앱앳앴앵야약얀얄얇얌얍얏양얕얗얘얜얠얩어억언얹얻얼얽얾엄",6,"엌엎"],["bf41","풞",10,"풪",14],["bf61","풹",18,"퓍퓎퓏퓑퓒퓓퓕"],["bf81","퓖",5,"퓝퓞퓠",7,"퓩퓪퓫퓭퓮퓯퓱",6,"퓹퓺퓼에엑엔엘엠엡엣엥여역엮연열엶엷염",5,"옅옆옇예옌옐옘옙옛옜오옥온올옭옮옰옳옴옵옷옹옻와왁완왈왐왑왓왔왕왜왝왠왬왯왱외왹왼욀욈욉욋욍요욕욘욜욤욥욧용우욱운울욹욺움웁웃웅워웍원월웜웝웠웡웨"],["c041","퓾",5,"픅픆픇픉픊픋픍",6,"픖픘",5],["c061","픞",25],["c081","픸픹픺픻픾픿핁핂핃핅",6,"핎핐핒",5,"핚핛핝핞핟핡핢핣웩웬웰웸웹웽위윅윈윌윔윕윗윙유육윤율윰윱윳융윷으윽은을읊음읍읏응",7,"읜읠읨읫이익인일읽읾잃임입잇있잉잊잎자작잔잖잗잘잚잠잡잣잤장잦재잭잰잴잼잽잿쟀쟁쟈쟉쟌쟎쟐쟘쟝쟤쟨쟬저적전절젊"],["c141","핤핦핧핪핬핮",5,"핶핷핹핺핻핽",6,"햆햊햋"],["c161","햌햍햎햏햑",19,"햦햧"],["c181","햨",31,"점접젓정젖제젝젠젤젬젭젯젱져젼졀졈졉졌졍졔조족존졸졺좀좁좃종좆좇좋좌좍좔좝좟좡좨좼좽죄죈죌죔죕죗죙죠죡죤죵주죽준줄줅줆줌줍줏중줘줬줴쥐쥑쥔쥘쥠쥡쥣쥬쥰쥴쥼즈즉즌즐즘즙즛증지직진짇질짊짐집짓"],["c241","헊헋헍헎헏헑헓",4,"헚헜헞",5,"헦헧헩헪헫헭헮"],["c261","헯",4,"헶헸헺",5,"혂혃혅혆혇혉",6,"혒"],["c281","혖",5,"혝혞혟혡혢혣혥",7,"혮",9,"혺혻징짖짙짚짜짝짠짢짤짧짬짭짯짰짱째짹짼쨀쨈쨉쨋쨌쨍쨔쨘쨩쩌쩍쩐쩔쩜쩝쩟쩠쩡쩨쩽쪄쪘쪼쪽쫀쫄쫌쫍쫏쫑쫓쫘쫙쫠쫬쫴쬈쬐쬔쬘쬠쬡쭁쭈쭉쭌쭐쭘쭙쭝쭤쭸쭹쮜쮸쯔쯤쯧쯩찌찍찐찔찜찝찡찢찧차착찬찮찰참찹찻"],["c341","혽혾혿홁홂홃홄홆홇홊홌홎홏홐홒홓홖홗홙홚홛홝",4],["c361","홢",4,"홨홪",5,"홲홳홵",11],["c381","횁횂횄횆",5,"횎횏횑횒횓횕",7,"횞횠횢",5,"횩횪찼창찾채책챈챌챔챕챗챘챙챠챤챦챨챰챵처척천철첨첩첫첬청체첵첸첼쳄쳅쳇쳉쳐쳔쳤쳬쳰촁초촉촌촐촘촙촛총촤촨촬촹최쵠쵤쵬쵭쵯쵱쵸춈추축춘출춤춥춧충춰췄췌췐취췬췰췸췹췻췽츄츈츌츔츙츠측츤츨츰츱츳층"],["c441","횫횭횮횯횱",7,"횺횼",7,"훆훇훉훊훋"],["c461","훍훎훏훐훒훓훕훖훘훚",5,"훡훢훣훥훦훧훩",4],["c481","훮훯훱훲훳훴훶",5,"훾훿휁휂휃휅",11,"휒휓휔치칙친칟칠칡침칩칫칭카칵칸칼캄캅캇캉캐캑캔캘캠캡캣캤캥캬캭컁커컥컨컫컬컴컵컷컸컹케켁켄켈켐켑켓켕켜켠켤켬켭켯켰켱켸코콕콘콜콤콥콧콩콰콱콴콸쾀쾅쾌쾡쾨쾰쿄쿠쿡쿤쿨쿰쿱쿳쿵쿼퀀퀄퀑퀘퀭퀴퀵퀸퀼"],["c541","휕휖휗휚휛휝휞휟휡",6,"휪휬휮",5,"휶휷휹"],["c561","휺휻휽",6,"흅흆흈흊",5,"흒흓흕흚",4],["c581","흟흢흤흦흧흨흪흫흭흮흯흱흲흳흵",6,"흾흿힀힂",5,"힊힋큄큅큇큉큐큔큘큠크큭큰클큼큽킁키킥킨킬킴킵킷킹타탁탄탈탉탐탑탓탔탕태택탠탤탬탭탯탰탱탸턍터턱턴털턺텀텁텃텄텅테텍텐텔템텝텟텡텨텬텼톄톈토톡톤톨톰톱톳통톺톼퇀퇘퇴퇸툇툉툐투툭툰툴툼툽툿퉁퉈퉜"],["c641","힍힎힏힑",6,"힚힜힞",5],["c6a1","퉤튀튁튄튈튐튑튕튜튠튤튬튱트특튼튿틀틂틈틉틋틔틘틜틤틥티틱틴틸팀팁팃팅파팍팎판팔팖팜팝팟팠팡팥패팩팬팰팸팹팻팼팽퍄퍅퍼퍽펀펄펌펍펏펐펑페펙펜펠펨펩펫펭펴편펼폄폅폈평폐폘폡폣포폭폰폴폼폽폿퐁"],["c7a1","퐈퐝푀푄표푠푤푭푯푸푹푼푿풀풂품풉풋풍풔풩퓌퓐퓔퓜퓟퓨퓬퓰퓸퓻퓽프픈플픔픕픗피픽핀필핌핍핏핑하학한할핥함합핫항해핵핸핼햄햅햇했행햐향허헉헌헐헒험헙헛헝헤헥헨헬헴헵헷헹혀혁현혈혐협혓혔형혜혠"],["c8a1","혤혭호혹혼홀홅홈홉홋홍홑화확환활홧황홰홱홴횃횅회획횐횔횝횟횡효횬횰횹횻후훅훈훌훑훔훗훙훠훤훨훰훵훼훽휀휄휑휘휙휜휠휨휩휫휭휴휵휸휼흄흇흉흐흑흔흖흗흘흙흠흡흣흥흩희흰흴흼흽힁히힉힌힐힘힙힛힝"],["caa1","伽佳假價加可呵哥嘉嫁家暇架枷柯歌珂痂稼苛茄街袈訶賈跏軻迦駕刻却各恪慤殼珏脚覺角閣侃刊墾奸姦干幹懇揀杆柬桿澗癎看磵稈竿簡肝艮艱諫間乫喝曷渴碣竭葛褐蝎鞨勘坎堪嵌感憾戡敢柑橄減甘疳監瞰紺邯鑑鑒龕"],["cba1","匣岬甲胛鉀閘剛堈姜岡崗康强彊慷江畺疆糠絳綱羌腔舡薑襁講鋼降鱇介价個凱塏愷愾慨改槪漑疥皆盖箇芥蓋豈鎧開喀客坑更粳羹醵倨去居巨拒据據擧渠炬祛距踞車遽鉅鋸乾件健巾建愆楗腱虔蹇鍵騫乞傑杰桀儉劍劒檢"],["cca1","瞼鈐黔劫怯迲偈憩揭擊格檄激膈覡隔堅牽犬甄絹繭肩見譴遣鵑抉決潔結缺訣兼慊箝謙鉗鎌京俓倞傾儆勁勍卿坰境庚徑慶憬擎敬景暻更梗涇炅烱璟璥瓊痙硬磬竟競絅經耕耿脛莖警輕逕鏡頃頸驚鯨係啓堺契季屆悸戒桂械"],["cda1","棨溪界癸磎稽系繫繼計誡谿階鷄古叩告呱固姑孤尻庫拷攷故敲暠枯槁沽痼皐睾稿羔考股膏苦苽菰藁蠱袴誥賈辜錮雇顧高鼓哭斛曲梏穀谷鵠困坤崑昆梱棍滾琨袞鯤汨滑骨供公共功孔工恐恭拱控攻珙空蚣貢鞏串寡戈果瓜"],["cea1","科菓誇課跨過鍋顆廓槨藿郭串冠官寬慣棺款灌琯瓘管罐菅觀貫關館刮恝括适侊光匡壙廣曠洸炚狂珖筐胱鑛卦掛罫乖傀塊壞怪愧拐槐魁宏紘肱轟交僑咬喬嬌嶠巧攪敎校橋狡皎矯絞翹膠蕎蛟較轎郊餃驕鮫丘久九仇俱具勾"],["cfa1","區口句咎嘔坵垢寇嶇廐懼拘救枸柩構歐毆毬求溝灸狗玖球瞿矩究絿耉臼舅舊苟衢謳購軀逑邱鉤銶駒驅鳩鷗龜國局菊鞠鞫麴君窘群裙軍郡堀屈掘窟宮弓穹窮芎躬倦券勸卷圈拳捲權淃眷厥獗蕨蹶闕机櫃潰詭軌饋句晷歸貴"],["d0a1","鬼龜叫圭奎揆槻珪硅窺竅糾葵規赳逵閨勻均畇筠菌鈞龜橘克剋劇戟棘極隙僅劤勤懃斤根槿瑾筋芹菫覲謹近饉契今妗擒昑檎琴禁禽芩衾衿襟金錦伋及急扱汲級給亘兢矜肯企伎其冀嗜器圻基埼夔奇妓寄岐崎己幾忌技旗旣"],["d1a1","朞期杞棋棄機欺氣汽沂淇玘琦琪璂璣畸畿碁磯祁祇祈祺箕紀綺羈耆耭肌記譏豈起錡錤飢饑騎騏驥麒緊佶吉拮桔金喫儺喇奈娜懦懶拏拿癩",5,"那樂",4,"諾酪駱亂卵暖欄煖爛蘭難鸞捏捺南嵐枏楠湳濫男藍襤拉"],["d2a1","納臘蠟衲囊娘廊",4,"乃來內奈柰耐冷女年撚秊念恬拈捻寧寗努勞奴弩怒擄櫓爐瑙盧",5,"駑魯",10,"濃籠聾膿農惱牢磊腦賂雷尿壘",7,"嫩訥杻紐勒",5,"能菱陵尼泥匿溺多茶"],["d3a1","丹亶但單團壇彖斷旦檀段湍短端簞緞蛋袒鄲鍛撻澾獺疸達啖坍憺擔曇淡湛潭澹痰聃膽蕁覃談譚錟沓畓答踏遝唐堂塘幢戇撞棠當糖螳黨代垈坮大對岱帶待戴擡玳臺袋貸隊黛宅德悳倒刀到圖堵塗導屠島嶋度徒悼挑掉搗桃"],["d4a1","棹櫂淘渡滔濤燾盜睹禱稻萄覩賭跳蹈逃途道都鍍陶韜毒瀆牘犢獨督禿篤纛讀墩惇敦旽暾沌焞燉豚頓乭突仝冬凍動同憧東桐棟洞潼疼瞳童胴董銅兜斗杜枓痘竇荳讀豆逗頭屯臀芚遁遯鈍得嶝橙燈登等藤謄鄧騰喇懶拏癩羅"],["d5a1","蘿螺裸邏樂洛烙珞絡落諾酪駱丹亂卵欄欒瀾爛蘭鸞剌辣嵐擥攬欖濫籃纜藍襤覽拉臘蠟廊朗浪狼琅瑯螂郞來崍徠萊冷掠略亮倆兩凉梁樑粮粱糧良諒輛量侶儷勵呂廬慮戾旅櫚濾礪藜蠣閭驢驪麗黎力曆歷瀝礫轢靂憐戀攣漣"],["d6a1","煉璉練聯蓮輦連鍊冽列劣洌烈裂廉斂殮濂簾獵令伶囹寧岺嶺怜玲笭羚翎聆逞鈴零靈領齡例澧禮醴隷勞怒撈擄櫓潞瀘爐盧老蘆虜路輅露魯鷺鹵碌祿綠菉錄鹿麓論壟弄朧瀧瓏籠聾儡瀨牢磊賂賚賴雷了僚寮廖料燎療瞭聊蓼"],["d7a1","遼鬧龍壘婁屢樓淚漏瘻累縷蔞褸鏤陋劉旒柳榴流溜瀏琉瑠留瘤硫謬類六戮陸侖倫崙淪綸輪律慄栗率隆勒肋凜凌楞稜綾菱陵俚利厘吏唎履悧李梨浬犁狸理璃異痢籬罹羸莉裏裡里釐離鯉吝潾燐璘藺躪隣鱗麟林淋琳臨霖砬"],["d8a1","立笠粒摩瑪痲碼磨馬魔麻寞幕漠膜莫邈万卍娩巒彎慢挽晩曼滿漫灣瞞萬蔓蠻輓饅鰻唜抹末沫茉襪靺亡妄忘忙望網罔芒茫莽輞邙埋妹媒寐昧枚梅每煤罵買賣邁魅脈貊陌驀麥孟氓猛盲盟萌冪覓免冕勉棉沔眄眠綿緬面麵滅"],["d9a1","蔑冥名命明暝椧溟皿瞑茗蓂螟酩銘鳴袂侮冒募姆帽慕摸摹暮某模母毛牟牡瑁眸矛耗芼茅謀謨貌木沐牧目睦穆鶩歿沒夢朦蒙卯墓妙廟描昴杳渺猫竗苗錨務巫憮懋戊拇撫无楙武毋無珷畝繆舞茂蕪誣貿霧鵡墨默們刎吻問文"],["daa1","汶紊紋聞蚊門雯勿沕物味媚尾嵋彌微未梶楣渼湄眉米美薇謎迷靡黴岷悶愍憫敏旻旼民泯玟珉緡閔密蜜謐剝博拍搏撲朴樸泊珀璞箔粕縛膊舶薄迫雹駁伴半反叛拌搬攀斑槃泮潘班畔瘢盤盼磐磻礬絆般蟠返頒飯勃拔撥渤潑"],["dba1","發跋醱鉢髮魃倣傍坊妨尨幇彷房放方旁昉枋榜滂磅紡肪膀舫芳蒡蚌訪謗邦防龐倍俳北培徘拜排杯湃焙盃背胚裴裵褙賠輩配陪伯佰帛柏栢白百魄幡樊煩燔番磻繁蕃藩飜伐筏罰閥凡帆梵氾汎泛犯範范法琺僻劈壁擘檗璧癖"],["dca1","碧蘗闢霹便卞弁變辨辯邊別瞥鱉鼈丙倂兵屛幷昞昺柄棅炳甁病秉竝輧餠騈保堡報寶普步洑湺潽珤甫菩補褓譜輔伏僕匐卜宓復服福腹茯蔔複覆輹輻馥鰒本乶俸奉封峯峰捧棒烽熢琫縫蓬蜂逢鋒鳳不付俯傅剖副否咐埠夫婦"],["dda1","孚孵富府復扶敷斧浮溥父符簿缶腐腑膚艀芙莩訃負賦賻赴趺部釜阜附駙鳧北分吩噴墳奔奮忿憤扮昐汾焚盆粉糞紛芬賁雰不佛弗彿拂崩朋棚硼繃鵬丕備匕匪卑妃婢庇悲憊扉批斐枇榧比毖毗毘沸泌琵痺砒碑秕秘粃緋翡肥"],["dea1","脾臂菲蜚裨誹譬費鄙非飛鼻嚬嬪彬斌檳殯浜濱瀕牝玭貧賓頻憑氷聘騁乍事些仕伺似使俟僿史司唆嗣四士奢娑寫寺射巳師徙思捨斜斯柶査梭死沙泗渣瀉獅砂社祀祠私篩紗絲肆舍莎蓑蛇裟詐詞謝賜赦辭邪飼駟麝削數朔索"],["dfa1","傘刪山散汕珊産疝算蒜酸霰乷撒殺煞薩三參杉森渗芟蔘衫揷澁鈒颯上傷像償商喪嘗孀尙峠常床庠廂想桑橡湘爽牀狀相祥箱翔裳觴詳象賞霜塞璽賽嗇塞穡索色牲生甥省笙墅壻嶼序庶徐恕抒捿敍暑曙書栖棲犀瑞筮絮緖署"],["e0a1","胥舒薯西誓逝鋤黍鼠夕奭席惜昔晳析汐淅潟石碩蓆釋錫仙僊先善嬋宣扇敾旋渲煽琁瑄璇璿癬禪線繕羨腺膳船蘚蟬詵跣選銑鐥饍鮮卨屑楔泄洩渫舌薛褻設說雪齧剡暹殲纖蟾贍閃陝攝涉燮葉城姓宬性惺成星晟猩珹盛省筬"],["e1a1","聖聲腥誠醒世勢歲洗稅笹細說貰召嘯塑宵小少巢所掃搔昭梳沼消溯瀟炤燒甦疏疎瘙笑篠簫素紹蔬蕭蘇訴逍遡邵銷韶騷俗屬束涑粟續謖贖速孫巽損蓀遜飡率宋悚松淞訟誦送頌刷殺灑碎鎖衰釗修受嗽囚垂壽嫂守岫峀帥愁"],["e2a1","戍手授搜收數樹殊水洙漱燧狩獸琇璲瘦睡秀穗竪粹綏綬繡羞脩茱蒐蓚藪袖誰讐輸遂邃酬銖銹隋隧隨雖需須首髓鬚叔塾夙孰宿淑潚熟琡璹肅菽巡徇循恂旬栒楯橓殉洵淳珣盾瞬筍純脣舜荀蓴蕣詢諄醇錞順馴戌術述鉥崇崧"],["e3a1","嵩瑟膝蝨濕拾習褶襲丞乘僧勝升承昇繩蠅陞侍匙嘶始媤尸屎屍市弑恃施是時枾柴猜矢示翅蒔蓍視試詩諡豕豺埴寔式息拭植殖湜熄篒蝕識軾食飾伸侁信呻娠宸愼新晨燼申神紳腎臣莘薪藎蜃訊身辛辰迅失室實悉審尋心沁"],["e4a1","沈深瀋甚芯諶什十拾雙氏亞俄兒啞娥峨我牙芽莪蛾衙訝阿雅餓鴉鵝堊岳嶽幄惡愕握樂渥鄂鍔顎鰐齷安岸按晏案眼雁鞍顔鮟斡謁軋閼唵岩巖庵暗癌菴闇壓押狎鴨仰央怏昻殃秧鴦厓哀埃崖愛曖涯碍艾隘靄厄扼掖液縊腋額"],["e5a1","櫻罌鶯鸚也倻冶夜惹揶椰爺耶若野弱掠略約若葯蒻藥躍亮佯兩凉壤孃恙揚攘敭暘梁楊樣洋瀁煬痒瘍禳穰糧羊良襄諒讓釀陽量養圄御於漁瘀禦語馭魚齬億憶抑檍臆偃堰彦焉言諺孼蘖俺儼嚴奄掩淹嶪業円予余勵呂女如廬"],["e6a1","旅歟汝濾璵礖礪與艅茹輿轝閭餘驪麗黎亦力域役易曆歷疫繹譯轢逆驛嚥堧姸娟宴年延憐戀捐挻撚椽沇沿涎涓淵演漣烟然煙煉燃燕璉硏硯秊筵緣練縯聯衍軟輦蓮連鉛鍊鳶列劣咽悅涅烈熱裂說閱厭廉念捻染殮炎焰琰艶苒"],["e7a1","簾閻髥鹽曄獵燁葉令囹塋寧嶺嶸影怜映暎楹榮永泳渶潁濚瀛瀯煐營獰玲瑛瑩瓔盈穎纓羚聆英詠迎鈴鍈零霙靈領乂倪例刈叡曳汭濊猊睿穢芮藝蘂禮裔詣譽豫醴銳隸霓預五伍俉傲午吾吳嗚塢墺奧娛寤悟惡懊敖旿晤梧汚澳"],["e8a1","烏熬獒筽蜈誤鰲鼇屋沃獄玉鈺溫瑥瘟穩縕蘊兀壅擁瓮甕癰翁邕雍饔渦瓦窩窪臥蛙蝸訛婉完宛梡椀浣玩琓琬碗緩翫脘腕莞豌阮頑曰往旺枉汪王倭娃歪矮外嵬巍猥畏了僚僥凹堯夭妖姚寥寮尿嶢拗搖撓擾料曜樂橈燎燿瑤療"],["e9a1","窈窯繇繞耀腰蓼蟯要謠遙遼邀饒慾欲浴縟褥辱俑傭冗勇埇墉容庸慂榕涌湧溶熔瑢用甬聳茸蓉踊鎔鏞龍于佑偶優又友右宇寓尤愚憂旴牛玗瑀盂祐禑禹紆羽芋藕虞迂遇郵釪隅雨雩勖彧旭昱栯煜稶郁頊云暈橒殞澐熉耘芸蕓"],["eaa1","運隕雲韻蔚鬱亐熊雄元原員圓園垣媛嫄寃怨愿援沅洹湲源爰猿瑗苑袁轅遠阮院願鴛月越鉞位偉僞危圍委威尉慰暐渭爲瑋緯胃萎葦蔿蝟衛褘謂違韋魏乳侑儒兪劉唯喩孺宥幼幽庾悠惟愈愉揄攸有杻柔柚柳楡楢油洧流游溜"],["eba1","濡猶猷琉瑜由留癒硫紐維臾萸裕誘諛諭踰蹂遊逾遺酉釉鍮類六堉戮毓肉育陸倫允奫尹崙淪潤玧胤贇輪鈗閏律慄栗率聿戎瀜絨融隆垠恩慇殷誾銀隱乙吟淫蔭陰音飮揖泣邑凝應膺鷹依倚儀宜意懿擬椅毅疑矣義艤薏蟻衣誼"],["eca1","議醫二以伊利吏夷姨履已弛彛怡易李梨泥爾珥理異痍痢移罹而耳肄苡荑裏裡貽貳邇里離飴餌匿溺瀷益翊翌翼謚人仁刃印吝咽因姻寅引忍湮燐璘絪茵藺蚓認隣靭靷鱗麟一佚佾壹日溢逸鎰馹任壬妊姙恁林淋稔臨荏賃入卄"],["eda1","立笠粒仍剩孕芿仔刺咨姉姿子字孜恣慈滋炙煮玆瓷疵磁紫者自茨蔗藉諮資雌作勺嚼斫昨灼炸爵綽芍酌雀鵲孱棧殘潺盞岑暫潛箴簪蠶雜丈仗匠場墻壯奬將帳庄張掌暲杖樟檣欌漿牆狀獐璋章粧腸臟臧莊葬蔣薔藏裝贓醬長"],["eea1","障再哉在宰才材栽梓渽滓災縡裁財載齋齎爭箏諍錚佇低儲咀姐底抵杵楮樗沮渚狙猪疽箸紵苧菹著藷詛貯躇這邸雎齟勣吊嫡寂摘敵滴狄炙的積笛籍績翟荻謫賊赤跡蹟迪迹適鏑佃佺傳全典前剪塡塼奠專展廛悛戰栓殿氈澱"],["efa1","煎琠田甸畑癲筌箋箭篆纏詮輾轉鈿銓錢鐫電顚顫餞切截折浙癤竊節絶占岾店漸点粘霑鮎點接摺蝶丁井亭停偵呈姃定幀庭廷征情挺政整旌晶晸柾楨檉正汀淀淨渟湞瀞炡玎珽町睛碇禎程穽精綎艇訂諪貞鄭酊釘鉦鋌錠霆靖"],["f0a1","靜頂鼎制劑啼堤帝弟悌提梯濟祭第臍薺製諸蹄醍除際霽題齊俎兆凋助嘲弔彫措操早晁曺曹朝條棗槽漕潮照燥爪璪眺祖祚租稠窕粗糟組繰肇藻蚤詔調趙躁造遭釣阻雕鳥族簇足鏃存尊卒拙猝倧宗從悰慫棕淙琮種終綜縱腫"],["f1a1","踪踵鍾鐘佐坐左座挫罪主住侏做姝胄呪周嗾奏宙州廚晝朱柱株注洲湊澍炷珠疇籌紂紬綢舟蛛註誅走躊輳週酎酒鑄駐竹粥俊儁准埈寯峻晙樽浚準濬焌畯竣蠢逡遵雋駿茁中仲衆重卽櫛楫汁葺增憎曾拯烝甑症繒蒸證贈之只"],["f2a1","咫地址志持指摯支旨智枝枳止池沚漬知砥祉祗紙肢脂至芝芷蜘誌識贄趾遲直稙稷織職唇嗔塵振搢晉晋桭榛殄津溱珍瑨璡畛疹盡眞瞋秦縉縝臻蔯袗診賑軫辰進鎭陣陳震侄叱姪嫉帙桎瓆疾秩窒膣蛭質跌迭斟朕什執潗緝輯"],["f3a1","鏶集徵懲澄且侘借叉嗟嵯差次此磋箚茶蹉車遮捉搾着窄錯鑿齪撰澯燦璨瓚竄簒纂粲纘讚贊鑽餐饌刹察擦札紮僭參塹慘慙懺斬站讒讖倉倡創唱娼廠彰愴敞昌昶暢槍滄漲猖瘡窓脹艙菖蒼債埰寀寨彩採砦綵菜蔡采釵冊柵策"],["f4a1","責凄妻悽處倜刺剔尺慽戚拓擲斥滌瘠脊蹠陟隻仟千喘天川擅泉淺玔穿舛薦賤踐遷釧闡阡韆凸哲喆徹撤澈綴輟轍鐵僉尖沾添甛瞻簽籤詹諂堞妾帖捷牒疊睫諜貼輒廳晴淸聽菁請靑鯖切剃替涕滯締諦逮遞體初剿哨憔抄招梢"],["f5a1","椒楚樵炒焦硝礁礎秒稍肖艸苕草蕉貂超酢醋醮促囑燭矗蜀觸寸忖村邨叢塚寵悤憁摠總聰蔥銃撮催崔最墜抽推椎楸樞湫皺秋芻萩諏趨追鄒酋醜錐錘鎚雛騶鰍丑畜祝竺筑築縮蓄蹙蹴軸逐春椿瑃出朮黜充忠沖蟲衝衷悴膵萃"],["f6a1","贅取吹嘴娶就炊翠聚脆臭趣醉驟鷲側仄厠惻測層侈値嗤峙幟恥梔治淄熾痔痴癡稚穉緇緻置致蚩輜雉馳齒則勅飭親七柒漆侵寢枕沈浸琛砧針鍼蟄秤稱快他咤唾墮妥惰打拖朶楕舵陀馱駝倬卓啄坼度托拓擢晫柝濁濯琢琸託"],["f7a1","鐸呑嘆坦彈憚歎灘炭綻誕奪脫探眈耽貪塔搭榻宕帑湯糖蕩兌台太怠態殆汰泰笞胎苔跆邰颱宅擇澤撑攄兎吐土討慟桶洞痛筒統通堆槌腿褪退頹偸套妬投透鬪慝特闖坡婆巴把播擺杷波派爬琶破罷芭跛頗判坂板版瓣販辦鈑"],["f8a1","阪八叭捌佩唄悖敗沛浿牌狽稗覇貝彭澎烹膨愎便偏扁片篇編翩遍鞭騙貶坪平枰萍評吠嬖幣廢弊斃肺蔽閉陛佈包匍匏咆哺圃布怖抛抱捕暴泡浦疱砲胞脯苞葡蒲袍褒逋鋪飽鮑幅暴曝瀑爆輻俵剽彪慓杓標漂瓢票表豹飇飄驃"],["f9a1","品稟楓諷豊風馮彼披疲皮被避陂匹弼必泌珌畢疋筆苾馝乏逼下何厦夏廈昰河瑕荷蝦賀遐霞鰕壑學虐謔鶴寒恨悍旱汗漢澣瀚罕翰閑閒限韓割轄函含咸啣喊檻涵緘艦銜陷鹹合哈盒蛤閤闔陜亢伉姮嫦巷恒抗杭桁沆港缸肛航"],["faa1","行降項亥偕咳垓奚孩害懈楷海瀣蟹解該諧邂駭骸劾核倖幸杏荇行享向嚮珦鄕響餉饗香噓墟虛許憲櫶獻軒歇險驗奕爀赫革俔峴弦懸晛泫炫玄玹現眩睍絃絢縣舷衒見賢鉉顯孑穴血頁嫌俠協夾峽挾浹狹脅脇莢鋏頰亨兄刑型"],["fba1","形泂滎瀅灐炯熒珩瑩荊螢衡逈邢鎣馨兮彗惠慧暳蕙蹊醯鞋乎互呼壕壺好岵弧戶扈昊晧毫浩淏湖滸澔濠濩灝狐琥瑚瓠皓祜糊縞胡芦葫蒿虎號蝴護豪鎬頀顥惑或酷婚昏混渾琿魂忽惚笏哄弘汞泓洪烘紅虹訌鴻化和嬅樺火畵"],["fca1","禍禾花華話譁貨靴廓擴攫確碻穫丸喚奐宦幻患換歡晥桓渙煥環紈還驩鰥活滑猾豁闊凰幌徨恍惶愰慌晃晄榥況湟滉潢煌璜皇篁簧荒蝗遑隍黃匯回廻徊恢悔懷晦會檜淮澮灰獪繪膾茴蛔誨賄劃獲宖橫鐄哮嚆孝效斅曉梟涍淆"],["fda1","爻肴酵驍侯候厚后吼喉嗅帿後朽煦珝逅勛勳塤壎焄熏燻薰訓暈薨喧暄煊萱卉喙毁彙徽揮暉煇諱輝麾休携烋畦虧恤譎鷸兇凶匈洶胸黑昕欣炘痕吃屹紇訖欠欽歆吸恰洽翕興僖凞喜噫囍姬嬉希憙憘戱晞曦熙熹熺犧禧稀羲詰"]]},272:function(e){e.exports={100:"Continue",101:"Switching Protocols",102:"Processing",103:"Early Hints",200:"OK",201:"Created",202:"Accepted",203:"Non-Authoritative Information",204:"No Content",205:"Reset Content",206:"Partial Content",207:"Multi-Status",208:"Already Reported",226:"IM Used",300:"Multiple Choices",301:"Moved Permanently",302:"Found",303:"See Other",304:"Not Modified",305:"Use Proxy",306:"(Unused)",307:"Temporary Redirect",308:"Permanent Redirect",400:"Bad Request",401:"Unauthorized",402:"Payment Required",403:"Forbidden",404:"Not Found",405:"Method Not Allowed",406:"Not Acceptable",407:"Proxy Authentication Required",408:"Request Timeout",409:"Conflict",410:"Gone",411:"Length Required",412:"Precondition Failed",413:"Payload Too Large",414:"URI Too Long",415:"Unsupported Media Type",416:"Range Not Satisfiable",417:"Expectation Failed",418:"I'm a teapot",421:"Misdirected Request",422:"Unprocessable Entity",423:"Locked",424:"Failed Dependency",425:"Unordered Collection",426:"Upgrade Required",428:"Precondition Required",429:"Too Many Requests",431:"Request Header Fields Too Large",451:"Unavailable For Legal Reasons",500:"Internal Server Error",501:"Not Implemented",502:"Bad Gateway",503:"Service Unavailable",504:"Gateway Timeout",505:"HTTP Version Not Supported",506:"Variant Also Negotiates",507:"Insufficient Storage",508:"Loop Detected",509:"Bandwidth Limit Exceeded",510:"Not Extended",511:"Network Authentication Required"}},293:function(e){e.exports=__webpack_require__("NkYg")},304:function(e){e.exports=__webpack_require__("tlh6")},317:function(e){"use strict";e.exports={10029:"maccenteuro",maccenteuro:{type:"_sbcs",chars:"ÄĀāÉĄÖÜáąČäčĆćéŹźĎíďĒēĖóėôöõúĚěü†°Ę£§•¶ß®©™ę¨≠ģĮįĪ≤≥īĶ∂∑łĻļĽľĹĺŅņŃ¬√ńŇ∆«»… ňŐÕőŌ–—“”‘’÷◊ōŔŕŘ‹›řŖŗŠ‚„šŚśÁŤťÍŽžŪÓÔūŮÚůŰűŲųÝýķŻŁżĢˇ"},808:"cp808",ibm808:"cp808",cp808:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№€■ "},mik:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя└┴┬├─┼╣║╚╔╩╦╠═╬┐░▒▓│┤№§╗╝┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ascii8bit:"ascii",usascii:"ascii",ansix34:"ascii",ansix341968:"ascii",ansix341986:"ascii",csascii:"ascii",cp367:"ascii",ibm367:"ascii",isoir6:"ascii",iso646us:"ascii",iso646irv:"ascii",us:"ascii",latin1:"iso88591",latin2:"iso88592",latin3:"iso88593",latin4:"iso88594",latin5:"iso88599",latin6:"iso885910",latin7:"iso885913",latin8:"iso885914",latin9:"iso885915",latin10:"iso885916",csisolatin1:"iso88591",csisolatin2:"iso88592",csisolatin3:"iso88593",csisolatin4:"iso88594",csisolatincyrillic:"iso88595",csisolatinarabic:"iso88596",csisolatingreek:"iso88597",csisolatinhebrew:"iso88598",csisolatin5:"iso88599",csisolatin6:"iso885910",l1:"iso88591",l2:"iso88592",l3:"iso88593",l4:"iso88594",l5:"iso88599",l6:"iso885910",l7:"iso885913",l8:"iso885914",l9:"iso885915",l10:"iso885916",isoir14:"iso646jp",isoir57:"iso646cn",isoir100:"iso88591",isoir101:"iso88592",isoir109:"iso88593",isoir110:"iso88594",isoir144:"iso88595",isoir127:"iso88596",isoir126:"iso88597",isoir138:"iso88598",isoir148:"iso88599",isoir157:"iso885910",isoir166:"tis620",isoir179:"iso885913",isoir199:"iso885914",isoir203:"iso885915",isoir226:"iso885916",cp819:"iso88591",ibm819:"iso88591",cyrillic:"iso88595",arabic:"iso88596",arabic8:"iso88596",ecma114:"iso88596",asmo708:"iso88596",greek:"iso88597",greek8:"iso88597",ecma118:"iso88597",elot928:"iso88597",hebrew:"iso88598",hebrew8:"iso88598",turkish:"iso88599",turkish8:"iso88599",thai:"iso885911",thai8:"iso885911",celtic:"iso885914",celtic8:"iso885914",isoceltic:"iso885914",tis6200:"tis620",tis62025291:"tis620",tis62025330:"tis620",10000:"macroman",10006:"macgreek",10007:"maccyrillic",10079:"maciceland",10081:"macturkish",cspc8codepage437:"cp437",cspc775baltic:"cp775",cspc850multilingual:"cp850",cspcp852:"cp852",cspc862latinhebrew:"cp862",cpgr:"cp869",msee:"cp1250",mscyrl:"cp1251",msansi:"cp1252",msgreek:"cp1253",msturk:"cp1254",mshebr:"cp1255",msarab:"cp1256",winbaltrim:"cp1257",cp20866:"koi8r",20866:"koi8r",ibm878:"koi8r",cskoi8r:"koi8r",cp21866:"koi8u",21866:"koi8u",ibm1168:"koi8u",strk10482002:"rk1048",tcvn5712:"tcvn",tcvn57121:"tcvn",gb198880:"iso646cn",cn:"iso646cn",csiso14jisc6220ro:"iso646jp",jisc62201969ro:"iso646jp",jp:"iso646jp",cshproman8:"hproman8",r8:"hproman8",roman8:"hproman8",xroman8:"hproman8",ibm1051:"hproman8",mac:"macintosh",csmacintosh:"macintosh"}},319:function(module,__unusedexports,__webpack_require__){var callSiteToString=__webpack_require__(571).callSiteToString;var eventListenerCount=__webpack_require__(571).eventListenerCount;var relative=__webpack_require__(622).relative;module.exports=depd;var basePath=process.cwd();function containsNamespace(e,t){var r=e.split(/[ ,]+/);var i=String(t).toLowerCase();for(var n=0;n<r.length;n++){var a=r[n];if(a&&(a==="*"||a.toLowerCase()===i)){return true}}return false}function convertDataDescriptorToAccessor(e,t,r){var i=Object.getOwnPropertyDescriptor(e,t);var n=i.value;i.get=function getter(){return n};if(i.writable){i.set=function setter(e){return n=e}}delete i.value;delete i.writable;Object.defineProperty(e,t,i);return i}function createArgumentsString(e){var t="";for(var r=0;r<e;r++){t+=", arg"+r}return t.substr(2)}function createStackString(e){var t=this.name+": "+this.namespace;if(this.message){t+=" deprecated "+this.message}for(var r=0;r<e.length;r++){t+="\n    at "+callSiteToString(e[r])}return t}function depd(e){if(!e){throw new TypeError("argument namespace is required")}var t=getStack();var r=callSiteLocation(t[1]);var i=r[0];function deprecate(e){log.call(deprecate,e)}deprecate._file=i;deprecate._ignored=isignored(e);deprecate._namespace=e;deprecate._traced=istraced(e);deprecate._warned=Object.create(null);deprecate.function=wrapfunction;deprecate.property=wrapproperty;return deprecate}function isignored(e){if(process.noDeprecation){return true}var t=process.env.NO_DEPRECATION||"";return containsNamespace(t,e)}function istraced(e){if(process.traceDeprecation){return true}var t=process.env.TRACE_DEPRECATION||"";return containsNamespace(t,e)}function log(e,t){var r=eventListenerCount(process,"deprecation")!==0;if(!r&&this._ignored){return}var i;var n;var a;var o;var c=0;var s=false;var f=getStack();var p=this._file;if(t){o=t;a=callSiteLocation(f[1]);a.name=o.name;p=a[0]}else{c=2;o=callSiteLocation(f[c]);a=o}for(;c<f.length;c++){i=callSiteLocation(f[c]);n=i[0];if(n===p){s=true}else if(n===this._file){p=this._file}else if(s){break}}var u=i?o.join(":")+"__"+i.join(":"):undefined;if(u!==undefined&&u in this._warned){return}this._warned[u]=true;var h=e;if(!h){h=a===o||!a.name?defaultMessage(o):defaultMessage(a)}if(r){var d=DeprecationError(this._namespace,h,f.slice(c));process.emit("deprecation",d);return}var b=process.stderr.isTTY?formatColor:formatPlain;var l=b.call(this,h,i,f.slice(c));process.stderr.write(l+"\n","utf8")}function callSiteLocation(e){var t=e.getFileName()||"<anonymous>";var r=e.getLineNumber();var i=e.getColumnNumber();if(e.isEval()){t=e.getEvalOrigin()+", "+t}var n=[t,r,i];n.callSite=e;n.name=e.getFunctionName();return n}function defaultMessage(e){var t=e.callSite;var r=e.name;if(!r){r="<anonymous@"+formatLocation(e)+">"}var i=t.getThis();var n=i&&t.getTypeName();if(n==="Object"){n=undefined}if(n==="Function"){n=i.name||n}return n&&t.getMethodName()?n+"."+r:r}function formatPlain(e,t,r){var i=(new Date).toUTCString();var n=i+" "+this._namespace+" deprecated "+e;if(this._traced){for(var a=0;a<r.length;a++){n+="\n    at "+callSiteToString(r[a])}return n}if(t){n+=" at "+formatLocation(t)}return n}function formatColor(e,t,r){var i="[36;1m"+this._namespace+"[22;39m"+" [33;1mdeprecated[22;39m"+" [0m"+e+"[39m";if(this._traced){for(var n=0;n<r.length;n++){i+="\n    [36mat "+callSiteToString(r[n])+"[39m"}return i}if(t){i+=" [36m"+formatLocation(t)+"[39m"}return i}function formatLocation(e){return relative(basePath,e[0])+":"+e[1]+":"+e[2]}function getStack(){var e=Error.stackTraceLimit;var t={};var r=Error.prepareStackTrace;Error.prepareStackTrace=prepareObjectStackTrace;Error.stackTraceLimit=Math.max(10,e);Error.captureStackTrace(t);var i=t.stack.slice(1);Error.prepareStackTrace=r;Error.stackTraceLimit=e;return i}function prepareObjectStackTrace(e,t){return t}function wrapfunction(fn,message){if(typeof fn!=="function"){throw new TypeError("argument fn must be a function")}var args=createArgumentsString(fn.length);var deprecate=this;var stack=getStack();var site=callSiteLocation(stack[1]);site.name=fn.name;var deprecatedfn=eval("(function ("+args+") {\n"+'"use strict"\n'+"log.call(deprecate, message, site)\n"+"return fn.apply(this, arguments)\n"+"})");return deprecatedfn}function wrapproperty(e,t,r){if(!e||typeof e!=="object"&&typeof e!=="function"){throw new TypeError("argument obj must be object")}var i=Object.getOwnPropertyDescriptor(e,t);if(!i){throw new TypeError("must call property on owner object")}if(!i.configurable){throw new TypeError("property must be configurable")}var n=this;var a=getStack();var o=callSiteLocation(a[1]);o.name=t;if("value"in i){i=convertDataDescriptorToAccessor(e,t,r)}var c=i.get;var s=i.set;if(typeof c==="function"){i.get=function getter(){log.call(n,r,o);return c.apply(this,arguments)}}if(typeof s==="function"){i.set=function setter(){log.call(n,r,o);return s.apply(this,arguments)}}Object.defineProperty(e,t,i)}function DeprecationError(e,t,r){var i=new Error;var n;Object.defineProperty(i,"constructor",{value:DeprecationError});Object.defineProperty(i,"message",{configurable:true,enumerable:false,value:t,writable:true});Object.defineProperty(i,"name",{enumerable:false,configurable:true,value:"DeprecationError",writable:true});Object.defineProperty(i,"namespace",{configurable:true,enumerable:false,value:e,writable:true});Object.defineProperty(i,"stack",{configurable:true,enumerable:false,get:function(){if(n!==undefined){return n}return n=createStackString.call(this,r)},set:function setter(e){n=e}});return i}},371:function(e){"use strict";e.exports=eventListenerCount;function eventListenerCount(e,t){return e.listeners(t).length}},413:function(e){e.exports=__webpack_require__("msIP")},416:function(e,t,r){"use strict";var i=r(319)("http-errors");var n=r(579);var a=r(839);var o=r(212);var c=r(500);e.exports=createError;e.exports.HttpError=createHttpErrorConstructor();populateConstructorExports(e.exports,a.codes,e.exports.HttpError);function codeClass(e){return Number(String(e).charAt(0)+"00")}function createError(){var e;var t;var r=500;var n={};for(var o=0;o<arguments.length;o++){var c=arguments[o];if(c instanceof Error){e=c;r=e.status||e.statusCode||r;continue}switch(typeof c){case"string":t=c;break;case"number":r=c;if(o!==0){i("non-first-argument status code; replace with createError("+c+", ...)")}break;case"object":n=c;break}}if(typeof r==="number"&&(r<400||r>=600)){i("non-error status code; use only 4xx or 5xx status codes")}if(typeof r!=="number"||!a[r]&&(r<400||r>=600)){r=500}var s=createError[r]||createError[codeClass(r)];if(!e){e=s?new s(t):new Error(t||a[r]);Error.captureStackTrace(e,createError)}if(!s||!(e instanceof s)||e.status!==r){e.expose=r<500;e.status=e.statusCode=r}for(var f in n){if(f!=="status"&&f!=="statusCode"){e[f]=n[f]}}return e}function createHttpErrorConstructor(){function HttpError(){throw new TypeError("cannot construct abstract class")}o(HttpError,Error);return HttpError}function createClientErrorConstructor(e,t,r){var i=t.match(/Error$/)?t:t+"Error";function ClientError(e){var t=e!=null?e:a[r];var o=new Error(t);Error.captureStackTrace(o,ClientError);n(o,ClientError.prototype);Object.defineProperty(o,"message",{enumerable:true,configurable:true,value:t,writable:true});Object.defineProperty(o,"name",{enumerable:false,configurable:true,value:i,writable:true});return o}o(ClientError,e);nameFunc(ClientError,i);ClientError.prototype.status=r;ClientError.prototype.statusCode=r;ClientError.prototype.expose=true;return ClientError}function createServerErrorConstructor(e,t,r){var i=t.match(/Error$/)?t:t+"Error";function ServerError(e){var t=e!=null?e:a[r];var o=new Error(t);Error.captureStackTrace(o,ServerError);n(o,ServerError.prototype);Object.defineProperty(o,"message",{enumerable:true,configurable:true,value:t,writable:true});Object.defineProperty(o,"name",{enumerable:false,configurable:true,value:i,writable:true});return o}o(ServerError,e);nameFunc(ServerError,i);ServerError.prototype.status=r;ServerError.prototype.statusCode=r;ServerError.prototype.expose=false;return ServerError}function nameFunc(e,t){var r=Object.getOwnPropertyDescriptor(e,"name");if(r&&r.configurable){r.value=t;Object.defineProperty(e,"name",r)}}function populateConstructorExports(e,t,r){t.forEach(function forEachCode(t){var i;var n=c(a[t]);switch(codeClass(t)){case 400:i=createClientErrorConstructor(r,n,t);break;case 500:i=createServerErrorConstructor(r,n,t);break}if(i){e[t]=i;e[n]=i}});e["I'mateapot"]=i.function(e.ImATeapot,'"I\'mateapot"; use "ImATeapot" instead')}},422:function(e,t,r){"use strict";var i=r(986).Buffer;e.exports={utf8:{type:"_internal",bomAware:true},cesu8:{type:"_internal",bomAware:true},unicode11utf8:"utf8",ucs2:{type:"_internal",bomAware:true},utf16le:"ucs2",binary:{type:"_internal"},base64:{type:"_internal"},hex:{type:"_internal"},_internal:InternalCodec};function InternalCodec(e,t){this.enc=e.encodingName;this.bomAware=e.bomAware;if(this.enc==="base64")this.encoder=InternalEncoderBase64;else if(this.enc==="cesu8"){this.enc="utf8";this.encoder=InternalEncoderCesu8;if(i.from("eda0bdedb2a9","hex").toString()!=="💩"){this.decoder=InternalDecoderCesu8;this.defaultCharUnicode=t.defaultCharUnicode}}}InternalCodec.prototype.encoder=InternalEncoder;InternalCodec.prototype.decoder=InternalDecoder;var n=r(304).StringDecoder;if(!n.prototype.end)n.prototype.end=function(){};function InternalDecoder(e,t){n.call(this,t.enc)}InternalDecoder.prototype=n.prototype;function InternalEncoder(e,t){this.enc=t.enc}InternalEncoder.prototype.write=function(e){return i.from(e,this.enc)};InternalEncoder.prototype.end=function(){};function InternalEncoderBase64(e,t){this.prevStr=""}InternalEncoderBase64.prototype.write=function(e){e=this.prevStr+e;var t=e.length-e.length%4;this.prevStr=e.slice(t);e=e.slice(0,t);return i.from(e,"base64")};InternalEncoderBase64.prototype.end=function(){return i.from(this.prevStr,"base64")};function InternalEncoderCesu8(e,t){}InternalEncoderCesu8.prototype.write=function(e){var t=i.alloc(e.length*3),r=0;for(var n=0;n<e.length;n++){var a=e.charCodeAt(n);if(a<128)t[r++]=a;else if(a<2048){t[r++]=192+(a>>>6);t[r++]=128+(a&63)}else{t[r++]=224+(a>>>12);t[r++]=128+(a>>>6&63);t[r++]=128+(a&63)}}return t.slice(0,r)};InternalEncoderCesu8.prototype.end=function(){};function InternalDecoderCesu8(e,t){this.acc=0;this.contBytes=0;this.accBytes=0;this.defaultCharUnicode=t.defaultCharUnicode}InternalDecoderCesu8.prototype.write=function(e){var t=this.acc,r=this.contBytes,i=this.accBytes,n="";for(var a=0;a<e.length;a++){var o=e[a];if((o&192)!==128){if(r>0){n+=this.defaultCharUnicode;r=0}if(o<128){n+=String.fromCharCode(o)}else if(o<224){t=o&31;r=1;i=1}else if(o<240){t=o&15;r=2;i=1}else{n+=this.defaultCharUnicode}}else{if(r>0){t=t<<6|o&63;r--;i++;if(r===0){if(i===2&&t<128&&t>0)n+=this.defaultCharUnicode;else if(i===3&&t<2048)n+=this.defaultCharUnicode;else n+=String.fromCharCode(t)}}else{n+=this.defaultCharUnicode}}}this.acc=t;this.contBytes=r;this.accBytes=i;return n};InternalDecoderCesu8.prototype.end=function(){var e=0;if(this.contBytes>0)e+=this.defaultCharUnicode;return e}},424:function(e){"use strict";e.exports=unpipe;function hasPipeDataListeners(e){var t=e.listeners("data");for(var r=0;r<t.length;r++){if(t[r].name==="ondata"){return true}}return false}function unpipe(e){if(!e){throw new TypeError("argument stream is required")}if(typeof e.unpipe==="function"){e.unpipe();return}if(!hasPipeDataListeners(e)){return}var t;var r=e.listeners("close");for(var i=0;i<r.length;i++){t=r[i];if(t.name!=="cleanup"&&t.name!=="onclose"){continue}t.call(e)}}},445:function(e){e.exports=[["a140","",62],["a180","",32],["a240","",62],["a280","",32],["a2ab","",5],["a2e3","€"],["a2ef",""],["a2fd",""],["a340","",62],["a380","",31,"　"],["a440","",62],["a480","",32],["a4f4","",10],["a540","",62],["a580","",32],["a5f7","",7],["a640","",62],["a680","",32],["a6b9","",7],["a6d9","",6],["a6ec",""],["a6f3",""],["a6f6","",8],["a740","",62],["a780","",32],["a7c2","",14],["a7f2","",12],["a896","",10],["a8bc",""],["a8bf","ǹ"],["a8c1",""],["a8ea","",20],["a958",""],["a95b",""],["a95d",""],["a989","〾⿰",11],["a997","",12],["a9f0","",14],["aaa1","",93],["aba1","",93],["aca1","",93],["ada1","",93],["aea1","",93],["afa1","",93],["d7fa","",4],["f8a1","",93],["f9a1","",93],["faa1","",93],["fba1","",93],["fca1","",93],["fda1","",93],["fe50","⺁⺄㑳㑇⺈⺋㖞㘚㘎⺌⺗㥮㤘㧏㧟㩳㧐㭎㱮㳠⺧⺪䁖䅟⺮䌷⺳⺶⺷䎱䎬⺻䏝䓖䙡䙌"],["fe80","䜣䜩䝼䞍⻊䥇䥺䥽䦂䦃䦅䦆䦟䦛䦷䦶䲣䲟䲠䲡䱷䲢䴓",6,"䶮",93]]},467:function(e,t,r){"use strict";var i=[r(422),r(945),r(811),r(475),r(317),r(145),r(484),r(615)];for(var n=0;n<i.length;n++){var a=i[n];for(var o in a)if(Object.prototype.hasOwnProperty.call(a,o))t[o]=a[o]}},475:function(e,t,r){"use strict";var i=r(986).Buffer;t._sbcs=SBCSCodec;function SBCSCodec(e,t){if(!e)throw new Error("SBCS codec is called without the data.");if(!e.chars||e.chars.length!==128&&e.chars.length!==256)throw new Error("Encoding '"+e.type+"' has incorrect 'chars' (must be of len 128 or 256)");if(e.chars.length===128){var r="";for(var n=0;n<128;n++)r+=String.fromCharCode(n);e.chars=r+e.chars}this.decodeBuf=i.from(e.chars,"ucs2");var a=i.alloc(65536,t.defaultCharSingleByte.charCodeAt(0));for(var n=0;n<e.chars.length;n++)a[e.chars.charCodeAt(n)]=n;this.encodeBuf=a}SBCSCodec.prototype.encoder=SBCSEncoder;SBCSCodec.prototype.decoder=SBCSDecoder;function SBCSEncoder(e,t){this.encodeBuf=t.encodeBuf}SBCSEncoder.prototype.write=function(e){var t=i.alloc(e.length);for(var r=0;r<e.length;r++)t[r]=this.encodeBuf[e.charCodeAt(r)];return t};SBCSEncoder.prototype.end=function(){};function SBCSDecoder(e,t){this.decodeBuf=t.decodeBuf}SBCSDecoder.prototype.write=function(e){var t=this.decodeBuf;var r=i.alloc(e.length*2);var n=0,a=0;for(var o=0;o<e.length;o++){n=e[o]*2;a=o*2;r[a]=t[n];r[a+1]=t[n+1]}return r.toString("ucs2")};SBCSDecoder.prototype.end=function(){}},484:function(e,t,r){"use strict";var i=r(986).Buffer;t._dbcs=DBCSCodec;var n=-1,a=-2,o=-10,c=-1e3,s=new Array(256),f=-1;for(var p=0;p<256;p++)s[p]=n;function DBCSCodec(e,t){this.encodingName=e.encodingName;if(!e)throw new Error("DBCS codec is called without the data.");if(!e.table)throw new Error("Encoding '"+this.encodingName+"' has no data.");var r=e.table();this.decodeTables=[];this.decodeTables[0]=s.slice(0);this.decodeTableSeq=[];for(var i=0;i<r.length;i++)this._addDecodeChunk(r[i]);this.defaultCharUnicode=t.defaultCharUnicode;this.encodeTable=[];this.encodeTableSeq=[];var o={};if(e.encodeSkipVals)for(var i=0;i<e.encodeSkipVals.length;i++){var f=e.encodeSkipVals[i];if(typeof f==="number")o[f]=true;else for(var p=f.from;p<=f.to;p++)o[p]=true}this._fillEncodeTable(0,0,o);if(e.encodeAdd){for(var u in e.encodeAdd)if(Object.prototype.hasOwnProperty.call(e.encodeAdd,u))this._setEncodeChar(u.charCodeAt(0),e.encodeAdd[u])}this.defCharSB=this.encodeTable[0][t.defaultCharSingleByte.charCodeAt(0)];if(this.defCharSB===n)this.defCharSB=this.encodeTable[0]["?"];if(this.defCharSB===n)this.defCharSB="?".charCodeAt(0);if(typeof e.gb18030==="function"){this.gb18030=e.gb18030();var h=this.decodeTables.length;var d=this.decodeTables[h]=s.slice(0);var b=this.decodeTables.length;var l=this.decodeTables[b]=s.slice(0);for(var i=129;i<=254;i++){var v=c-this.decodeTables[0][i];var g=this.decodeTables[v];for(var p=48;p<=57;p++)g[p]=c-h}for(var i=129;i<=254;i++)d[i]=c-b;for(var i=48;i<=57;i++)l[i]=a}}DBCSCodec.prototype.encoder=DBCSEncoder;DBCSCodec.prototype.decoder=DBCSDecoder;DBCSCodec.prototype._getDecodeTrieNode=function(e){var t=[];for(;e>0;e>>=8)t.push(e&255);if(t.length==0)t.push(0);var r=this.decodeTables[0];for(var i=t.length-1;i>0;i--){var a=r[t[i]];if(a==n){r[t[i]]=c-this.decodeTables.length;this.decodeTables.push(r=s.slice(0))}else if(a<=c){r=this.decodeTables[c-a]}else throw new Error("Overwrite byte in "+this.encodingName+", addr: "+e.toString(16))}return r};DBCSCodec.prototype._addDecodeChunk=function(e){var t=parseInt(e[0],16);var r=this._getDecodeTrieNode(t);t=t&255;for(var i=1;i<e.length;i++){var n=e[i];if(typeof n==="string"){for(var a=0;a<n.length;){var c=n.charCodeAt(a++);if(55296<=c&&c<56320){var s=n.charCodeAt(a++);if(56320<=s&&s<57344)r[t++]=65536+(c-55296)*1024+(s-56320);else throw new Error("Incorrect surrogate pair in "+this.encodingName+" at chunk "+e[0])}else if(4080<c&&c<=4095){var f=4095-c+2;var p=[];for(var u=0;u<f;u++)p.push(n.charCodeAt(a++));r[t++]=o-this.decodeTableSeq.length;this.decodeTableSeq.push(p)}else r[t++]=c}}else if(typeof n==="number"){var h=r[t-1]+1;for(var a=0;a<n;a++)r[t++]=h++}else throw new Error("Incorrect type '"+typeof n+"' given in "+this.encodingName+" at chunk "+e[0])}if(t>255)throw new Error("Incorrect chunk in "+this.encodingName+" at addr "+e[0]+": too long"+t)};DBCSCodec.prototype._getEncodeBucket=function(e){var t=e>>8;if(this.encodeTable[t]===undefined)this.encodeTable[t]=s.slice(0);return this.encodeTable[t]};DBCSCodec.prototype._setEncodeChar=function(e,t){var r=this._getEncodeBucket(e);var i=e&255;if(r[i]<=o)this.encodeTableSeq[o-r[i]][f]=t;else if(r[i]==n)r[i]=t};DBCSCodec.prototype._setEncodeSequence=function(e,t){var r=e[0];var i=this._getEncodeBucket(r);var a=r&255;var c;if(i[a]<=o){c=this.encodeTableSeq[o-i[a]]}else{c={};if(i[a]!==n)c[f]=i[a];i[a]=o-this.encodeTableSeq.length;this.encodeTableSeq.push(c)}for(var s=1;s<e.length-1;s++){var p=c[r];if(typeof p==="object")c=p;else{c=c[r]={};if(p!==undefined)c[f]=p}}r=e[e.length-1];c[r]=t};DBCSCodec.prototype._fillEncodeTable=function(e,t,r){var i=this.decodeTables[e];for(var n=0;n<256;n++){var a=i[n];var s=t+n;if(r[s])continue;if(a>=0)this._setEncodeChar(a,s);else if(a<=c)this._fillEncodeTable(c-a,s<<8,r);else if(a<=o)this._setEncodeSequence(this.decodeTableSeq[o-a],s)}};function DBCSEncoder(e,t){this.leadSurrogate=-1;this.seqObj=undefined;this.encodeTable=t.encodeTable;this.encodeTableSeq=t.encodeTableSeq;this.defaultCharSingleByte=t.defCharSB;this.gb18030=t.gb18030}DBCSEncoder.prototype.write=function(e){var t=i.alloc(e.length*(this.gb18030?4:3)),r=this.leadSurrogate,a=this.seqObj,c=-1,s=0,p=0;while(true){if(c===-1){if(s==e.length)break;var u=e.charCodeAt(s++)}else{var u=c;c=-1}if(55296<=u&&u<57344){if(u<56320){if(r===-1){r=u;continue}else{r=u;u=n}}else{if(r!==-1){u=65536+(r-55296)*1024+(u-56320);r=-1}else{u=n}}}else if(r!==-1){c=u;u=n;r=-1}var h=n;if(a!==undefined&&u!=n){var d=a[u];if(typeof d==="object"){a=d;continue}else if(typeof d=="number"){h=d}else if(d==undefined){d=a[f];if(d!==undefined){h=d;c=u}else{}}a=undefined}else if(u>=0){var b=this.encodeTable[u>>8];if(b!==undefined)h=b[u&255];if(h<=o){a=this.encodeTableSeq[o-h];continue}if(h==n&&this.gb18030){var l=findIdx(this.gb18030.uChars,u);if(l!=-1){var h=this.gb18030.gbChars[l]+(u-this.gb18030.uChars[l]);t[p++]=129+Math.floor(h/12600);h=h%12600;t[p++]=48+Math.floor(h/1260);h=h%1260;t[p++]=129+Math.floor(h/10);h=h%10;t[p++]=48+h;continue}}}if(h===n)h=this.defaultCharSingleByte;if(h<256){t[p++]=h}else if(h<65536){t[p++]=h>>8;t[p++]=h&255}else{t[p++]=h>>16;t[p++]=h>>8&255;t[p++]=h&255}}this.seqObj=a;this.leadSurrogate=r;return t.slice(0,p)};DBCSEncoder.prototype.end=function(){if(this.leadSurrogate===-1&&this.seqObj===undefined)return;var e=i.alloc(10),t=0;if(this.seqObj){var r=this.seqObj[f];if(r!==undefined){if(r<256){e[t++]=r}else{e[t++]=r>>8;e[t++]=r&255}}else{}this.seqObj=undefined}if(this.leadSurrogate!==-1){e[t++]=this.defaultCharSingleByte;this.leadSurrogate=-1}return e.slice(0,t)};DBCSEncoder.prototype.findIdx=findIdx;function DBCSDecoder(e,t){this.nodeIdx=0;this.prevBuf=i.alloc(0);this.decodeTables=t.decodeTables;this.decodeTableSeq=t.decodeTableSeq;this.defaultCharUnicode=t.defaultCharUnicode;this.gb18030=t.gb18030}DBCSDecoder.prototype.write=function(e){var t=i.alloc(e.length*2),r=this.nodeIdx,s=this.prevBuf,f=this.prevBuf.length,p=-this.prevBuf.length,u;if(f>0)s=i.concat([s,e.slice(0,10)]);for(var h=0,d=0;h<e.length;h++){var b=h>=0?e[h]:s[h+f];var u=this.decodeTables[r][b];if(u>=0){}else if(u===n){h=p;u=this.defaultCharUnicode.charCodeAt(0)}else if(u===a){var l=p>=0?e.slice(p,h+1):s.slice(p+f,h+1+f);var v=(l[0]-129)*12600+(l[1]-48)*1260+(l[2]-129)*10+(l[3]-48);var g=findIdx(this.gb18030.gbChars,v);u=this.gb18030.uChars[g]+v-this.gb18030.gbChars[g]}else if(u<=c){r=c-u;continue}else if(u<=o){var y=this.decodeTableSeq[o-u];for(var w=0;w<y.length-1;w++){u=y[w];t[d++]=u&255;t[d++]=u>>8}u=y[y.length-1]}else throw new Error("iconv-lite internal error: invalid decoding table value "+u+" at "+r+"/"+b);if(u>65535){u-=65536;var m=55296+Math.floor(u/1024);t[d++]=m&255;t[d++]=m>>8;u=56320+u%1024}t[d++]=u&255;t[d++]=u>>8;r=0;p=h+1}this.nodeIdx=r;this.prevBuf=p>=0?e.slice(p):s.slice(p+f);return t.slice(0,d).toString("ucs2")};DBCSDecoder.prototype.end=function(){var e="";while(this.prevBuf.length>0){e+=this.defaultCharUnicode;var t=this.prevBuf.slice(1);this.prevBuf=i.alloc(0);this.nodeIdx=0;if(t.length>0)e+=this.write(t)}this.nodeIdx=0;return e};function findIdx(e,t){if(e[0]>t)return-1;var r=0,i=e.length;while(r<i-1){var n=r+Math.floor((i-r+1)/2);if(e[n]<=t)r=n;else i=n}return r}},500:function(e){e.exports=toIdentifier;function toIdentifier(e){return e.split(" ").map(function(e){return e.slice(0,1).toUpperCase()+e.slice(1)}).join("").replace(/[^ _0-9a-z]/gi,"")}},571:function(e,t,r){"use strict";var i=r(614).EventEmitter;lazyProperty(e.exports,"callSiteToString",function callSiteToString(){var e=Error.stackTraceLimit;var t={};var i=Error.prepareStackTrace;function prepareObjectStackTrace(e,t){return t}Error.prepareStackTrace=prepareObjectStackTrace;Error.stackTraceLimit=2;Error.captureStackTrace(t);var n=t.stack.slice();Error.prepareStackTrace=i;Error.stackTraceLimit=e;return n[0].toString?toString:r(999)});lazyProperty(e.exports,"eventListenerCount",function eventListenerCount(){return i.listenerCount||r(371)});function lazyProperty(e,t,r){function get(){var i=r();Object.defineProperty(e,t,{configurable:true,enumerable:true,value:i});return i}Object.defineProperty(e,t,{configurable:true,enumerable:true,get:get})}function toString(e){return e.toString()}},579:function(e){"use strict";e.exports=Object.setPrototypeOf||({__proto__:[]}instanceof Array?setProtoOf:mixinProperties);function setProtoOf(e,t){e.__proto__=t;return e}function mixinProperties(e,t){for(var r in t){if(!e.hasOwnProperty(r)){e[r]=t[r]}}return e}},614:function(e){e.exports=__webpack_require__("/0p4")},615:function(e,t,r){"use strict";e.exports={shiftjis:{type:"_dbcs",table:function(){return r(693)},encodeAdd:{"¥":92,"‾":126},encodeSkipVals:[{from:60736,to:63808}]},csshiftjis:"shiftjis",mskanji:"shiftjis",sjis:"shiftjis",windows31j:"shiftjis",ms31j:"shiftjis",xsjis:"shiftjis",windows932:"shiftjis",ms932:"shiftjis",932:"shiftjis",cp932:"shiftjis",eucjp:{type:"_dbcs",table:function(){return r(42)},encodeAdd:{"¥":92,"‾":126}},gb2312:"cp936",gb231280:"cp936",gb23121980:"cp936",csgb2312:"cp936",csiso58gb231280:"cp936",euccn:"cp936",windows936:"cp936",ms936:"cp936",936:"cp936",cp936:{type:"_dbcs",table:function(){return r(791)}},gbk:{type:"_dbcs",table:function(){return r(791).concat(r(445))}},xgbk:"gbk",isoir58:"gbk",gb18030:{type:"_dbcs",table:function(){return r(791).concat(r(445))},gb18030:function(){return r(910)},encodeSkipVals:[128],encodeAdd:{"€":41699}},chinese:"gb18030",windows949:"cp949",ms949:"cp949",949:"cp949",cp949:{type:"_dbcs",table:function(){return r(237)}},cseuckr:"cp949",csksc56011987:"cp949",euckr:"cp949",isoir149:"cp949",korean:"cp949",ksc56011987:"cp949",ksc56011989:"cp949",ksc5601:"cp949",windows950:"cp950",ms950:"cp950",950:"cp950",cp950:{type:"_dbcs",table:function(){return r(48)}},big5:"big5hkscs",big5hkscs:{type:"_dbcs",table:function(){return r(48).concat(r(637))},encodeSkipVals:[41676]},cnbig5:"big5hkscs",csbig5:"big5hkscs",xxbig5:"big5hkscs"}},622:function(e){e.exports=__webpack_require__("oyvS")},637:function(e){e.exports=[["8740","䏰䰲䘃䖦䕸𧉧䵷䖳𧲱䳢𧳅㮕䜶䝄䱇䱀𤊿𣘗𧍒𦺋𧃒䱗𪍑䝏䗚䲅𧱬䴇䪤䚡𦬣爥𥩔𡩣𣸆𣽡晍囻"],["8767","綕夝𨮹㷴霴𧯯寛𡵞媤㘥𩺰嫑宷峼杮薓𩥅瑡璝㡵𡵓𣚞𦀡㻬"],["87a1","𥣞㫵竼龗𤅡𨤍𣇪𠪊𣉞䌊蒄龖鐯䤰蘓墖靊鈘秐稲晠権袝瑌篅枂稬剏遆㓦珄𥶹瓆鿇垳䤯呌䄱𣚎堘穲𧭥讏䚮𦺈䆁𥶙箮𢒼鿈𢓁𢓉𢓌鿉蔄𣖻䂴鿊䓡𪷿拁灮鿋"],["8840","㇀",4,"𠄌㇅𠃑𠃍㇆㇇𠃋𡿨㇈𠃊㇉㇊㇋㇌𠄎㇍㇎ĀÁǍÀĒÉĚÈŌÓǑÒ࿿Ê̄Ế࿿Ê̌ỀÊāáǎàɑēéěèīíǐìōóǒòūúǔùǖǘǚ"],["88a1","ǜü࿿ê̄ế࿿ê̌ềêɡ⏚⏛"],["8940","𪎩𡅅"],["8943","攊"],["8946","丽滝鵎釟"],["894c","𧜵撑会伨侨兖兴农凤务动医华发变团声处备夲头学实実岚庆总斉柾栄桥济炼电纤纬纺织经统缆缷艺苏药视设询车轧轮"],["89a1","琑糼緍楆竉刧"],["89ab","醌碸酞肼"],["89b0","贋胶𠧧"],["89b5","肟黇䳍鷉鸌䰾𩷶𧀎鸊𪄳㗁"],["89c1","溚舾甙"],["89c5","䤑马骏龙禇𨑬𡷊𠗐𢫦两亁亀亇亿仫伷㑌侽㹈倃傈㑽㒓㒥円夅凛凼刅争剹劐匧㗇厩㕑厰㕓参吣㕭㕲㚁咓咣咴咹哐哯唘唣唨㖘唿㖥㖿嗗㗅"],["8a40","𧶄唥"],["8a43","𠱂𠴕𥄫喐𢳆㧬𠍁蹆𤶸𩓥䁓𨂾睺𢰸㨴䟕𨅝𦧲𤷪擝𠵼𠾴𠳕𡃴撍蹾𠺖𠰋𠽤𢲩𨉖𤓓"],["8a64","𠵆𩩍𨃩䟴𤺧𢳂骲㩧𩗴㿭㔆𥋇𩟔𧣈𢵄鵮頕"],["8a76","䏙𦂥撴哣𢵌𢯊𡁷㧻𡁯"],["8aa1","𦛚𦜖𧦠擪𥁒𠱃蹨𢆡𨭌𠜱"],["8aac","䠋𠆩㿺塳𢶍"],["8ab2","𤗈𠓼𦂗𠽌𠶖啹䂻䎺"],["8abb","䪴𢩦𡂝膪飵𠶜捹㧾𢝵跀嚡摼㹃"],["8ac9","𪘁𠸉𢫏𢳉"],["8ace","𡃈𣧂㦒㨆𨊛㕸𥹉𢃇噒𠼱𢲲𩜠㒼氽𤸻"],["8adf","𧕴𢺋𢈈𪙛𨳍𠹺𠰴𦠜羓𡃏𢠃𢤹㗻𥇣𠺌𠾍𠺪㾓𠼰𠵇𡅏𠹌"],["8af6","𠺫𠮩𠵈𡃀𡄽㿹𢚖搲𠾭"],["8b40","𣏴𧘹𢯎𠵾𠵿𢱑𢱕㨘𠺘𡃇𠼮𪘲𦭐𨳒𨶙𨳊閪哌苄喹"],["8b55","𩻃鰦骶𧝞𢷮煀腭胬尜𦕲脴㞗卟𨂽醶𠻺𠸏𠹷𠻻㗝𤷫㘉𠳖嚯𢞵𡃉𠸐𠹸𡁸𡅈𨈇𡑕𠹹𤹐𢶤婔𡀝𡀞𡃵𡃶垜𠸑"],["8ba1","𧚔𨋍𠾵𠹻𥅾㜃𠾶𡆀𥋘𪊽𤧚𡠺𤅷𨉼墙剨㘚𥜽箲孨䠀䬬鼧䧧鰟鮍𥭴𣄽嗻㗲嚉丨夂𡯁屮靑𠂆乛亻㔾尣彑忄㣺扌攵歺氵氺灬爫丬犭𤣩罒礻糹罓𦉪㓁"],["8bde","𦍋耂肀𦘒𦥑卝衤见𧢲讠贝钅镸长门𨸏韦页风飞饣𩠐鱼鸟黄歯龜丷𠂇阝户钢"],["8c40","倻淾𩱳龦㷉袏𤅎灷峵䬠𥇍㕙𥴰愢𨨲辧釶熑朙玺𣊁𪄇㲋𡦀䬐磤琂冮𨜏䀉橣𪊺䈣蘏𠩯稪𩥇𨫪靕灍匤𢁾鏴盙𨧣龧矝亣俰傼丯众龨吴綋墒壐𡶶庒庙忂𢜒斋"],["8ca1","𣏹椙橃𣱣泿"],["8ca7","爀𤔅玌㻛𤨓嬕璹讃𥲤𥚕窓篬糃繬苸薗龩袐龪躹龫迏蕟駠鈡龬𨶹𡐿䁱䊢娚"],["8cc9","顨杫䉶圽"],["8cce","藖𤥻芿𧄍䲁𦵴嵻𦬕𦾾龭龮宖龯曧繛湗秊㶈䓃𣉖𢞖䎚䔶"],["8ce6","峕𣬚諹屸㴒𣕑嵸龲煗䕘𤃬𡸣䱷㥸㑊𠆤𦱁諌侴𠈹妿腬顖𩣺弻"],["8d40","𠮟"],["8d42","𢇁𨥭䄂䚻𩁹㼇龳𪆵䃸㟖䛷𦱆䅼𨚲𧏿䕭㣔𥒚䕡䔛䶉䱻䵶䗪㿈𤬏㙡䓞䒽䇭崾嵈嵖㷼㠏嶤嶹㠠㠸幂庽弥徃㤈㤔㤿㥍惗愽峥㦉憷憹懏㦸戬抐拥挘㧸嚱"],["8da1","㨃揢揻搇摚㩋擀崕嘡龟㪗斆㪽旿晓㫲暒㬢朖㭂枤栀㭘桊梄㭲㭱㭻椉楃牜楤榟榅㮼槖㯝橥橴橱檂㯬檙㯲檫檵櫔櫶殁毁毪汵沪㳋洂洆洦涁㳯涤涱渕渘温溆𨧀溻滢滚齿滨滩漤漴㵆𣽁澁澾㵪㵵熷岙㶊瀬㶑灐灔灯灿炉𠌥䏁㗱𠻘"],["8e40","𣻗垾𦻓焾𥟠㙎榢𨯩孴穉𥣡𩓙穥穽𥦬窻窰竂竃燑𦒍䇊竚竝竪䇯咲𥰁笋筕笩𥌎𥳾箢筯莜𥮴𦱿篐萡箒箸𥴠㶭𥱥蒒篺簆簵𥳁籄粃𤢂粦晽𤕸糉糇糦籴糳糵糎"],["8ea1","繧䔝𦹄絝𦻖璍綉綫焵綳緒𤁗𦀩緤㴓緵𡟹緥𨍭縝𦄡𦅚繮纒䌫鑬縧罀罁罇礶𦋐駡羗𦍑羣𡙡𠁨䕜𣝦䔃𨌺翺𦒉者耈耝耨耯𪂇𦳃耻耼聡𢜔䦉𦘦𣷣𦛨朥肧𨩈脇脚墰𢛶汿𦒘𤾸擧𡒊舘𡡞橓𤩥𤪕䑺舩𠬍𦩒𣵾俹𡓽蓢荢𦬊𤦧𣔰𡝳𣷸芪椛芳䇛"],["8f40","蕋苐茚𠸖𡞴㛁𣅽𣕚艻苢茘𣺋𦶣𦬅𦮗𣗎㶿茝嗬莅䔋𦶥莬菁菓㑾𦻔橗蕚㒖𦹂𢻯葘𥯤葱㷓䓤檧葊𣲵祘蒨𦮖𦹷𦹃蓞萏莑䒠蒓蓤𥲑䉀𥳀䕃蔴嫲𦺙䔧蕳䔖枿蘖"],["8fa1","𨘥𨘻藁𧂈蘂𡖂𧃍䕫䕪蘨㙈𡢢号𧎚虾蝱𪃸蟮𢰧螱蟚蠏噡虬桖䘏衅衆𧗠𣶹𧗤衞袜䙛袴袵揁装睷𧜏覇覊覦覩覧覼𨨥觧𧤤𧪽誜瞓釾誐𧩙竩𧬺𣾏䜓𧬸煼謌謟𥐰𥕥謿譌譍誩𤩺讐讛誯𡛟䘕衏貛𧵔𧶏貫㜥𧵓賖𧶘𧶽贒贃𡤐賛灜贑𤳉㻐起"],["9040","趩𨀂𡀔𤦊㭼𨆼𧄌竧躭躶軃鋔輙輭𨍥𨐒辥錃𪊟𠩐辳䤪𨧞𨔽𣶻廸𣉢迹𪀔𨚼𨔁𢌥㦀𦻗逷𨔼𧪾遡𨕬𨘋邨𨜓郄𨛦邮都酧㫰醩釄粬𨤳𡺉鈎沟鉁鉢𥖹銹𨫆𣲛𨬌𥗛"],["90a1","𠴱錬鍫𨫡𨯫炏嫃𨫢𨫥䥥鉄𨯬𨰹𨯿鍳鑛躼閅閦鐦閠濶䊹𢙺𨛘𡉼𣸮䧟氜陻隖䅬隣𦻕懚隶磵𨫠隽双䦡𦲸𠉴𦐐𩂯𩃥𤫑𡤕𣌊霱虂霶䨏䔽䖅𤫩灵孁霛靜𩇕靗孊𩇫靟鐥僐𣂷𣂼鞉鞟鞱鞾韀韒韠𥑬韮琜𩐳響韵𩐝𧥺䫑頴頳顋顦㬎𧅵㵑𠘰𤅜"],["9140","𥜆飊颷飈飇䫿𦴧𡛓喰飡飦飬鍸餹𤨩䭲𩡗𩤅駵騌騻騐驘𥜥㛄𩂱𩯕髠髢𩬅髴䰎鬔鬭𨘀倴鬴𦦨㣃𣁽魐魀𩴾婅𡡣鮎𤉋鰂鯿鰌𩹨鷔𩾷𪆒𪆫𪃡𪄣𪇟鵾鶃𪄴鸎梈"],["91a1","鷄𢅛𪆓𪈠𡤻𪈳鴹𪂹𪊴麐麕麞麢䴴麪麯𤍤黁㭠㧥㴝伲㞾𨰫鼂鼈䮖鐤𦶢鼗鼖鼹嚟嚊齅馸𩂋韲葿齢齩竜龎爖䮾𤥵𤦻煷𤧸𤍈𤩑玞𨯚𡣺禟𨥾𨸶鍩鏳𨩄鋬鎁鏋𨥬𤒹爗㻫睲穃烐𤑳𤏸煾𡟯炣𡢾𣖙㻇𡢅𥐯𡟸㜢𡛻𡠹㛡𡝴𡣑𥽋㜣𡛀坛𤨥𡏾𡊨"],["9240","𡏆𡒶蔃𣚦蔃葕𤦔𧅥𣸱𥕜𣻻𧁒䓴𣛮𩦝𦼦柹㜳㰕㷧塬𡤢栐䁗𣜿𤃡𤂋𤄏𦰡哋嚞𦚱嚒𠿟𠮨𠸍鏆𨬓鎜仸儫㠙𤐶亼𠑥𠍿佋侊𥙑婨𠆫𠏋㦙𠌊𠐔㐵伩𠋀𨺳𠉵諚𠈌亘"],["92a1","働儍侢伃𤨎𣺊佂倮偬傁俌俥偘僼兙兛兝兞湶𣖕𣸹𣺿浲𡢄𣺉冨凃𠗠䓝𠒣𠒒𠒑赺𨪜𠜎剙劤𠡳勡鍮䙺熌𤎌𠰠𤦬𡃤槑𠸝瑹㻞璙琔瑖玘䮎𤪼𤂍叐㖄爏𤃉喴𠍅响𠯆圝鉝雴鍦埝垍坿㘾壋媙𨩆𡛺𡝯𡜐娬妸銏婾嫏娒𥥆𡧳𡡡𤊕㛵洅瑃娡𥺃"],["9340","媁𨯗𠐓鏠璌𡌃焅䥲鐈𨧻鎽㞠尞岞幞幈𡦖𡥼𣫮廍孏𡤃𡤄㜁𡢠㛝𡛾㛓脪𨩇𡶺𣑲𨦨弌弎𡤧𡞫婫𡜻孄蘔𧗽衠恾𢡠𢘫忛㺸𢖯𢖾𩂈𦽳懀𠀾𠁆𢘛憙憘恵𢲛𢴇𤛔𩅍"],["93a1","摱𤙥𢭪㨩𢬢𣑐𩣪𢹸挷𪑛撶挱揑𤧣𢵧护𢲡搻敫楲㯴𣂎𣊭𤦉𣊫唍𣋠𡣙𩐿曎𣊉𣆳㫠䆐𥖄𨬢𥖏𡛼𥕛𥐥磮𣄃𡠪𣈴㑤𣈏𣆂𤋉暎𦴤晫䮓昰𧡰𡷫晣𣋒𣋡昞𥡲㣑𣠺𣞼㮙𣞢𣏾瓐㮖枏𤘪梶栞㯄檾㡣𣟕𤒇樳橒櫉欅𡤒攑梘橌㯗橺歗𣿀𣲚鎠鋲𨯪𨫋"],["9440","銉𨀞𨧜鑧涥漋𤧬浧𣽿㶏渄𤀼娽渊塇洤硂焻𤌚𤉶烱牐犇犔𤞏𤜥兹𤪤𠗫瑺𣻸𣙟𤩊𤤗𥿡㼆㺱𤫟𨰣𣼵悧㻳瓌琼鎇琷䒟𦷪䕑疃㽣𤳙𤴆㽘畕癳𪗆㬙瑨𨫌𤦫𤦎㫻"],["94a1","㷍𤩎㻿𤧅𤣳釺圲鍂𨫣𡡤僟𥈡𥇧睸𣈲眎眏睻𤚗𣞁㩞𤣰琸璛㺿𤪺𤫇䃈𤪖𦆮錇𥖁砞碍碈磒珐祙𧝁𥛣䄎禛蒖禥樭𣻺稺秴䅮𡛦䄲鈵秱𠵌𤦌𠊙𣶺𡝮㖗啫㕰㚪𠇔𠰍竢婙𢛵𥪯𥪜娍𠉛磰娪𥯆竾䇹籝籭䈑𥮳𥺼𥺦糍𤧹𡞰粎籼粮檲緜縇緓罎𦉡"],["9540","𦅜𧭈綗𥺂䉪𦭵𠤖柖𠁎𣗏埄𦐒𦏸𤥢翝笧𠠬𥫩𥵃笌𥸎駦虅驣樜𣐿㧢𤧷𦖭騟𦖠蒀𧄧𦳑䓪脷䐂胆脉腂𦞴飃𦩂艢艥𦩑葓𦶧蘐𧈛媆䅿𡡀嬫𡢡嫤𡣘蚠蜨𣶏蠭𧐢娂"],["95a1","衮佅袇袿裦襥襍𥚃襔𧞅𧞄𨯵𨯙𨮜𨧹㺭蒣䛵䛏㟲訽訜𩑈彍鈫𤊄旔焩烄𡡅鵭貟賩𧷜妚矃姰䍮㛔踪躧𤰉輰轊䋴汘澻𢌡䢛潹溋𡟚鯩㚵𤤯邻邗啱䤆醻鐄𨩋䁢𨫼鐧𨰝𨰻蓥訫閙閧閗閖𨴴瑅㻂𤣿𤩂𤏪㻧𣈥随𨻧𨹦𨹥㻌𤧭𤩸𣿮琒瑫㻼靁𩂰"],["9640","桇䨝𩂓𥟟靝鍨𨦉𨰦𨬯𦎾銺嬑譩䤼珹𤈛鞛靱餸𠼦巁𨯅𤪲頟𩓚鋶𩗗釥䓀𨭐𤩧𨭤飜𨩅㼀鈪䤥萔餻饍𧬆㷽馛䭯馪驜𨭥𥣈檏騡嫾騯𩣱䮐𩥈馼䮽䮗鍽塲𡌂堢𤦸"],["96a1","𡓨硄𢜟𣶸棅㵽鑘㤧慐𢞁𢥫愇鱏鱓鱻鰵鰐魿鯏𩸭鮟𪇵𪃾鴡䲮𤄄鸘䲰鴌𪆴𪃭𪃳𩤯鶥蒽𦸒𦿟𦮂藼䔳𦶤𦺄𦷰萠藮𦸀𣟗𦁤秢𣖜𣙀䤭𤧞㵢鏛銾鍈𠊿碹鉷鑍俤㑀遤𥕝砽硔碶硋𡝗𣇉𤥁㚚佲濚濙瀞瀞吔𤆵垻壳垊鴖埗焴㒯𤆬燫𦱀𤾗嬨𡞵𨩉"],["9740","愌嫎娋䊼𤒈㜬䭻𨧼鎻鎸𡣖𠼝葲𦳀𡐓𤋺𢰦𤏁妔𣶷𦝁綨𦅛𦂤𤦹𤦋𨧺鋥珢㻩璴𨭣𡢟㻡𤪳櫘珳珻㻖𤨾𤪔𡟙𤩦𠎧𡐤𤧥瑈𤤖炥𤥶銄珦鍟𠓾錱𨫎𨨖鎆𨯧𥗕䤵𨪂煫"],["97a1","𤥃𠳿嚤𠘚𠯫𠲸唂秄𡟺緾𡛂𤩐𡡒䔮鐁㜊𨫀𤦭妰𡢿𡢃𧒄媡㛢𣵛㚰鉟婹𨪁𡡢鍴㳍𠪴䪖㦊僴㵩㵌𡎜煵䋻𨈘渏𩃤䓫浗𧹏灧沯㳖𣿭𣸭渂漌㵯𠏵畑㚼㓈䚀㻚䡱姄鉮䤾轁𨰜𦯀堒埈㛖𡑒烾𤍢𤩱𢿣𡊰𢎽梹楧𡎘𣓥𧯴𣛟𨪃𣟖𣏺𤲟樚𣚭𦲷萾䓟䓎"],["9840","𦴦𦵑𦲂𦿞漗𧄉茽𡜺菭𦲀𧁓𡟛妉媂𡞳婡婱𡤅𤇼㜭姯𡜼㛇熎鎐暚𤊥婮娫𤊓樫𣻹𧜶𤑛𤋊焝𤉙𨧡侰𦴨峂𤓎𧹍𤎽樌𤉖𡌄炦焳𤏩㶥泟勇𤩏繥姫崯㷳彜𤩝𡟟綤萦"],["98a1","咅𣫺𣌀𠈔坾𠣕𠘙㿥𡾞𪊶瀃𩅛嵰玏糓𨩙𩐠俈翧狍猐𧫴猸猹𥛶獁獈㺩𧬘遬燵𤣲珡臶㻊県㻑沢国琙琞琟㻢㻰㻴㻺瓓㼎㽓畂畭畲疍㽼痈痜㿀癍㿗癴㿜発𤽜熈嘣覀塩䀝睃䀹条䁅㗛瞘䁪䁯属瞾矋売砘点砜䂨砹硇硑硦葈𥔵礳栃礲䄃"],["9940","䄉禑禙辻稆込䅧窑䆲窼艹䇄竏竛䇏両筢筬筻簒簛䉠䉺类粜䊌粸䊔糭输烀𠳏総緔緐緽羮羴犟䎗耠耥笹耮耱联㷌垴炠肷胩䏭脌猪脎脒畠脔䐁㬹腖腙腚"],["99a1","䐓堺腼膄䐥膓䐭膥埯臁臤艔䒏芦艶苊苘苿䒰荗险榊萅烵葤惣蒈䔄蒾蓡蓸蔐蔸蕒䔻蕯蕰藠䕷虲蚒蚲蛯际螋䘆䘗袮裿褤襇覑𧥧訩訸誔誴豑賔賲贜䞘塟跃䟭仮踺嗘坔蹱嗵躰䠷軎転軤軭軲辷迁迊迌逳駄䢭飠鈓䤞鈨鉘鉫銱銮銿"],["9a40","鋣鋫鋳鋴鋽鍃鎄鎭䥅䥑麿鐗匁鐝鐭鐾䥪鑔鑹锭関䦧间阳䧥枠䨤靀䨵鞲韂噔䫤惨颹䬙飱塄餎餙冴餜餷饂饝饢䭰駅䮝騼鬏窃魩鮁鯝鯱鯴䱭鰠㝯𡯂鵉鰺"],["9aa1","黾噐鶓鶽鷀鷼银辶鹻麬麱麽黆铜黢黱黸竈齄𠂔𠊷𠎠椚铃妬𠓗塀铁㞹𠗕𠘕𠙶𡚺块煳𠫂𠫍𠮿呪吆𠯋咞𠯻𠰻𠱓𠱥𠱼惧𠲍噺𠲵𠳝𠳭𠵯𠶲𠷈楕鰯螥𠸄𠸎𠻗𠾐𠼭𠹳尠𠾼帋𡁜𡁏𡁶朞𡁻𡂈𡂖㙇𡂿𡃓𡄯𡄻卤蒭𡋣𡍵𡌶讁𡕷𡘙𡟃𡟇乸炻𡠭𡥪"],["9b40","𡨭𡩅𡰪𡱰𡲬𡻈拃𡻕𡼕熘桕𢁅槩㛈𢉼𢏗𢏺𢜪𢡱𢥏苽𢥧𢦓𢫕覥𢫨辠𢬎鞸𢬿顇骽𢱌"],["9b62","𢲈𢲷𥯨𢴈𢴒𢶷𢶕𢹂𢽴𢿌𣀳𣁦𣌟𣏞徱晈暿𧩹𣕧𣗳爁𤦺矗𣘚𣜖纇𠍆墵朎"],["9ba1","椘𣪧𧙗𥿢𣸑𣺹𧗾𢂚䣐䪸𤄙𨪚𤋮𤌍𤀻𤌴𤎖𤩅𠗊凒𠘑妟𡺨㮾𣳿𤐄𤓖垈𤙴㦛𤜯𨗨𩧉㝢𢇃譞𨭎駖𤠒𤣻𤨕爉𤫀𠱸奥𤺥𤾆𠝹軚𥀬劏圿煱𥊙𥐙𣽊𤪧喼𥑆𥑮𦭒釔㑳𥔿𧘲𥕞䜘𥕢𥕦𥟇𤤿𥡝偦㓻𣏌惞𥤃䝼𨥈𥪮𥮉𥰆𡶐垡煑澶𦄂𧰒遖𦆲𤾚譢𦐂𦑊"],["9c40","嵛𦯷輶𦒄𡤜諪𤧶𦒈𣿯𦔒䯀𦖿𦚵𢜛鑥𥟡憕娧晉侻嚹𤔡𦛼乪𤤴陖涏𦲽㘘襷𦞙𦡮𦐑𦡞營𦣇筂𩃀𠨑𦤦鄄𦤹穅鷰𦧺騦𦨭㙟𦑩𠀡禃𦨴𦭛崬𣔙菏𦮝䛐𦲤画补𦶮墶"],["9ca1","㜜𢖍𧁋𧇍㱔𧊀𧊅銁𢅺𧊋錰𧋦𤧐氹钟𧑐𠻸蠧裵𢤦𨑳𡞱溸𤨪𡠠㦤㚹尐秣䔿暶𩲭𩢤襃𧟌𧡘囖䃟𡘊㦡𣜯𨃨𡏅熭荦𧧝𩆨婧䲷𧂯𨦫𧧽𧨊𧬋𧵦𤅺筃祾𨀉澵𪋟樃𨌘厢𦸇鎿栶靝𨅯𨀣𦦵𡏭𣈯𨁈嶅𨰰𨂃圕頣𨥉嶫𤦈斾槕叒𤪥𣾁㰑朶𨂐𨃴𨄮𡾡𨅏"],["9d40","𨆉𨆯𨈚𨌆𨌯𨎊㗊𨑨𨚪䣺揦𨥖砈鉕𨦸䏲𨧧䏟𨧨𨭆𨯔姸𨰉輋𨿅𩃬筑𩄐𩄼㷷𩅞𤫊运犏嚋𩓧𩗩𩖰𩖸𩜲𩣑𩥉𩥪𩧃𩨨𩬎𩵚𩶛纟𩻸𩼣䲤镇𪊓熢𪋿䶑递𪗋䶜𠲜达嗁"],["9da1","辺𢒰边𤪓䔉繿潖檱仪㓤𨬬𧢝㜺躀𡟵𨀤𨭬𨮙𧨾𦚯㷫𧙕𣲷𥘵𥥖亚𥺁𦉘嚿𠹭踎孭𣺈𤲞揞拐𡟶𡡻攰嘭𥱊吚𥌑㷆𩶘䱽嘢嘞罉𥻘奵𣵀蝰东𠿪𠵉𣚺脗鵞贘瘻鱅癎瞹鍅吲腈苷嘥脲萘肽嗪祢噃吖𠺝㗎嘅嗱曱𨋢㘭甴嗰喺咗啲𠱁𠲖廐𥅈𠹶𢱢"],["9e40","𠺢麫絚嗞𡁵抝靭咔賍燶酶揼掹揾啩𢭃鱲𢺳冚㓟𠶧冧呍唞唓癦踭𦢊疱肶蠄螆裇膶萜𡃁䓬猄𤜆宐茋𦢓噻𢛴𧴯𤆣𧵳𦻐𧊶酰𡇙鈈𣳼𪚩𠺬𠻹牦𡲢䝎𤿂𧿹𠿫䃺"],["9ea1","鱝攟𢶠䣳𤟠𩵼𠿬𠸊恢𧖣𠿭"],["9ead","𦁈𡆇熣纎鵐业丄㕷嬍沲卧㚬㧜卽㚥𤘘墚𤭮舭呋垪𥪕𠥹"],["9ec5","㩒𢑥獴𩺬䴉鯭𣳾𩼰䱛𤾩𩖞𩿞葜𣶶𧊲𦞳𣜠挮紥𣻷𣸬㨪逈勌㹴㙺䗩𠒎癀嫰𠺶硺𧼮墧䂿噼鮋嵴癔𪐴麅䳡痹㟻愙𣃚𤏲"],["9ef5","噝𡊩垧𤥣𩸆刴𧂮㖭汊鵼"],["9f40","籖鬹埞𡝬屓擓𩓐𦌵𧅤蚭𠴨𦴢𤫢𠵱"],["9f4f","凾𡼏嶎霃𡷑麁遌笟鬂峑箣扨挵髿篏鬪籾鬮籂粆鰕篼鬉鼗鰛𤤾齚啳寃俽麘俲剠㸆勑坧偖妷帒韈鶫轜呩鞴饀鞺匬愰"],["9fa1","椬叚鰊鴂䰻陁榀傦畆𡝭駚剳"],["9fae","酙隁酜"],["9fb2","酑𨺗捿𦴣櫊嘑醎畺抅𠏼獏籰𥰡𣳽"],["9fc1","𤤙盖鮝个𠳔莾衂"],["9fc9","届槀僭坺刟巵从氱𠇲伹咜哚劚趂㗾弌㗳"],["9fdb","歒酼龥鮗頮颴骺麨麄煺笔"],["9fe7","毺蠘罸"],["9feb","嘠𪙊蹷齓"],["9ff0","跔蹏鸜踁抂𨍽踨蹵竓𤩷稾磘泪詧瘇"],["a040","𨩚鼦泎蟖痃𪊲硓咢贌狢獱謭猂瓱賫𤪻蘯徺袠䒷"],["a055","𡠻𦸅"],["a058","詾𢔛"],["a05b","惽癧髗鵄鍮鮏蟵"],["a063","蠏賷猬霡鮰㗖犲䰇籑饊𦅙慙䰄麖慽"],["a073","坟慯抦戹拎㩜懢厪𣏵捤栂㗒"],["a0a1","嵗𨯂迚𨸹"],["a0a6","僙𡵆礆匲阸𠼻䁥"],["a0ae","矾"],["a0b0","糂𥼚糚稭聦聣絍甅瓲覔舚朌聢𧒆聛瓰脃眤覉𦟌畓𦻑螩蟎臈螌詉貭譃眫瓸蓚㘵榲趦"],["a0d4","覩瑨涹蟁𤀑瓧㷛煶悤憜㳑煢恷"],["a0e2","罱𨬭牐惩䭾删㰘𣳇𥻗𧙖𥔱𡥄𡋾𩤃𦷜𧂭峁𦆭𨨏𣙷𠃮𦡆𤼎䕢嬟𦍌齐麦𦉫"],["a3c0","␀",31,"␡"],["c6a1","①",9,"⑴",9,"ⅰ",9,"丶丿亅亠冂冖冫勹匸卩厶夊宀巛⼳广廴彐彡攴无疒癶辵隶¨ˆヽヾゝゞ〃仝々〆〇ー［］✽ぁ",23],["c740","す",58,"ァアィイ"],["c7a1","ゥ",81,"А",5,"ЁЖ",4],["c840","Л",26,"ёж",25,"⇧↸↹㇏𠃌乚𠂊刂䒑"],["c8a1","龰冈龱𧘇"],["c8cd","￢￤＇＂㈱№℡゛゜⺀⺄⺆⺇⺈⺊⺌⺍⺕⺜⺝⺥⺧⺪⺬⺮⺶⺼⺾⻆⻊⻌⻍⻏⻖⻗⻞⻣"],["c8f5","ʃɐɛɔɵœøŋʊɪ"],["f9fe","￭"],["fa40","𠕇鋛𠗟𣿅蕌䊵珯况㙉𤥂𨧤鍄𡧛苮𣳈砼杄拟𤤳𨦪𠊠𦮳𡌅侫𢓭倈𦴩𧪄𣘀𤪱𢔓倩𠍾徤𠎀𠍇滛𠐟偽儁㑺儎顬㝃萖𤦤𠒇兠𣎴兪𠯿𢃼𠋥𢔰𠖎𣈳𡦃宂蝽𠖳𣲙冲冸"],["faa1","鴴凉减凑㳜凓𤪦决凢卂凭菍椾𣜭彻刋刦刼劵剗劔効勅簕蕂勠蘍𦬓包𨫞啉滙𣾀𠥔𣿬匳卄𠯢泋𡜦栛珕恊㺪㣌𡛨燝䒢卭却𨚫卾卿𡖖𡘓矦厓𨪛厠厫厮玧𥝲㽙玜叁叅汉义埾叙㪫𠮏叠𣿫𢶣叶𠱷吓灹唫晗浛呭𦭓𠵴啝咏咤䞦𡜍𠻝㶴𠵍"],["fb40","𨦼𢚘啇䳭启琗喆喩嘅𡣗𤀺䕒𤐵暳𡂴嘷曍𣊊暤暭噍噏磱囱鞇叾圀囯园𨭦㘣𡉏坆𤆥汮炋坂㚱𦱾埦𡐖堃𡑔𤍣堦𤯵塜墪㕡壠壜𡈼壻寿坃𪅐𤉸鏓㖡够梦㛃湙"],["fba1","𡘾娤啓𡚒蔅姉𠵎𦲁𦴪𡟜姙𡟻𡞲𦶦浱𡠨𡛕姹𦹅媫婣㛦𤦩婷㜈媖瑥嫓𦾡𢕔㶅𡤑㜲𡚸広勐孶斈孼𧨎䀄䡝𠈄寕慠𡨴𥧌𠖥寳宝䴐尅𡭄尓珎尔𡲥𦬨屉䣝岅峩峯嶋𡷹𡸷崐崘嵆𡺤岺巗苼㠭𤤁𢁉𢅳芇㠶㯂帮檊幵幺𤒼𠳓厦亷廐厨𡝱帉廴𨒂"],["fc40","廹廻㢠廼栾鐛弍𠇁弢㫞䢮𡌺强𦢈𢏐彘𢑱彣鞽𦹮彲鍀𨨶徧嶶㵟𥉐𡽪𧃸𢙨釖𠊞𨨩怱暅𡡷㥣㷇㘹垐𢞴祱㹀悞悤悳𤦂𤦏𧩓璤僡媠慤萤慂慈𦻒憁凴𠙖憇宪𣾷"],["fca1","𢡟懓𨮝𩥝懐㤲𢦀𢣁怣慜攞掋𠄘担𡝰拕𢸍捬𤧟㨗搸揸𡎎𡟼撐澊𢸶頔𤂌𥜝擡擥鑻㩦携㩗敍漖𤨨𤨣斅敭敟𣁾斵𤥀䬷旑䃘𡠩无旣忟𣐀昘𣇷𣇸晄𣆤𣆥晋𠹵晧𥇦晳晴𡸽𣈱𨗴𣇈𥌓矅𢣷馤朂𤎜𤨡㬫槺𣟂杞杧杢𤇍𩃭柗䓩栢湐鈼栁𣏦𦶠桝"],["fd40","𣑯槡樋𨫟楳棃𣗍椁椀㴲㨁𣘼㮀枬楡𨩊䋼椶榘㮡𠏉荣傐槹𣙙𢄪橅𣜃檝㯳枱櫈𩆜㰍欝𠤣惞欵歴𢟍溵𣫛𠎵𡥘㝀吡𣭚毡𣻼毜氷𢒋𤣱𦭑汚舦汹𣶼䓅𣶽𤆤𤤌𤤀"],["fda1","𣳉㛥㳫𠴲鮃𣇹𢒑羏样𦴥𦶡𦷫涖浜湼漄𤥿𤂅𦹲蔳𦽴凇沜渝萮𨬡港𣸯瑓𣾂秌湏媑𣁋濸㜍澝𣸰滺𡒗𤀽䕕鏰潄潜㵎潴𩅰㴻澟𤅄濓𤂑𤅕𤀹𣿰𣾴𤄿凟𤅖𤅗𤅀𦇝灋灾炧炁烌烕烖烟䄄㷨熴熖𤉷焫煅媈煊煮岜𤍥煏鍢𤋁焬𤑚𤨧𤨢熺𨯨炽爎"],["fe40","鑂爕夑鑃爤鍁𥘅爮牀𤥴梽牕牗㹕𣁄栍漽犂猪猫𤠣𨠫䣭𨠄猨献珏玪𠰺𦨮珉瑉𤇢𡛧𤨤昣㛅𤦷𤦍𤧻珷琕椃𤨦琹𠗃㻗瑜𢢭瑠𨺲瑇珤瑶莹瑬㜰瑴鏱樬璂䥓𤪌"],["fea1","𤅟𤩹𨮏孆𨰃𡢞瓈𡦈甎瓩甞𨻙𡩋寗𨺬鎅畍畊畧畮𤾂㼄𤴓疎瑝疞疴瘂瘬癑癏癯癶𦏵皐臯㟸𦤑𦤎皡皥皷盌𦾟葢𥂝𥅽𡸜眞眦着撯𥈠睘𣊬瞯𨥤𨥨𡛁矴砉𡍶𤨒棊碯磇磓隥礮𥗠磗礴碱𧘌辸袄𨬫𦂃𢘜禆褀椂禀𥡗禝𧬹礼禩渪𧄦㺨秆𩄍秔"]]},655:function(e,t,r){"use strict";var i=r(293).Buffer;e.exports=function(e){var t=undefined;e.supportsNodeEncodingsExtension=!(i.from||new i(0)instanceof Uint8Array);e.extendNodeEncodings=function extendNodeEncodings(){if(t)return;t={};if(!e.supportsNodeEncodingsExtension){console.error("ACTION NEEDED: require('iconv-lite').extendNodeEncodings() is not supported in your version of Node");console.error("See more info at https://github.com/ashtuchkin/iconv-lite/wiki/Node-v4-compatibility");return}var n={hex:true,utf8:true,"utf-8":true,ascii:true,binary:true,base64:true,ucs2:true,"ucs-2":true,utf16le:true,"utf-16le":true};i.isNativeEncoding=function(e){return e&&n[e.toLowerCase()]};var a=r(293).SlowBuffer;t.SlowBufferToString=a.prototype.toString;a.prototype.toString=function(r,n,a){r=String(r||"utf8").toLowerCase();if(i.isNativeEncoding(r))return t.SlowBufferToString.call(this,r,n,a);if(typeof n=="undefined")n=0;if(typeof a=="undefined")a=this.length;return e.decode(this.slice(n,a),r)};t.SlowBufferWrite=a.prototype.write;a.prototype.write=function(r,n,a,o){if(isFinite(n)){if(!isFinite(a)){o=a;a=undefined}}else{var c=o;o=n;n=a;a=c}n=+n||0;var s=this.length-n;if(!a){a=s}else{a=+a;if(a>s){a=s}}o=String(o||"utf8").toLowerCase();if(i.isNativeEncoding(o))return t.SlowBufferWrite.call(this,r,n,a,o);if(r.length>0&&(a<0||n<0))throw new RangeError("attempt to write beyond buffer bounds");var f=e.encode(r,o);if(f.length<a)a=f.length;f.copy(this,n,0,a);return a};t.BufferIsEncoding=i.isEncoding;i.isEncoding=function(t){return i.isNativeEncoding(t)||e.encodingExists(t)};t.BufferByteLength=i.byteLength;i.byteLength=a.byteLength=function(r,n){n=String(n||"utf8").toLowerCase();if(i.isNativeEncoding(n))return t.BufferByteLength.call(this,r,n);return e.encode(r,n).length};t.BufferToString=i.prototype.toString;i.prototype.toString=function(r,n,a){r=String(r||"utf8").toLowerCase();if(i.isNativeEncoding(r))return t.BufferToString.call(this,r,n,a);if(typeof n=="undefined")n=0;if(typeof a=="undefined")a=this.length;return e.decode(this.slice(n,a),r)};t.BufferWrite=i.prototype.write;i.prototype.write=function(r,n,a,o){var c=n,s=a,f=o;if(isFinite(n)){if(!isFinite(a)){o=a;a=undefined}}else{var p=o;o=n;n=a;a=p}o=String(o||"utf8").toLowerCase();if(i.isNativeEncoding(o))return t.BufferWrite.call(this,r,c,s,f);n=+n||0;var u=this.length-n;if(!a){a=u}else{a=+a;if(a>u){a=u}}if(r.length>0&&(a<0||n<0))throw new RangeError("attempt to write beyond buffer bounds");var h=e.encode(r,o);if(h.length<a)a=h.length;h.copy(this,n,0,a);return a};if(e.supportsStreams){var o=r(413).Readable;t.ReadableSetEncoding=o.prototype.setEncoding;o.prototype.setEncoding=function setEncoding(t,r){this._readableState.decoder=e.getDecoder(t,r);this._readableState.encoding=t};o.prototype.collect=e._collect}};e.undoExtendNodeEncodings=function undoExtendNodeEncodings(){if(!e.supportsNodeEncodingsExtension)return;if(!t)throw new Error("require('iconv-lite').undoExtendNodeEncodings(): Nothing to undo; extendNodeEncodings() is not called.");delete i.isNativeEncoding;var n=r(293).SlowBuffer;n.prototype.toString=t.SlowBufferToString;n.prototype.write=t.SlowBufferWrite;i.isEncoding=t.BufferIsEncoding;i.byteLength=t.BufferByteLength;i.prototype.toString=t.BufferToString;i.prototype.write=t.BufferWrite;if(e.supportsStreams){var a=r(413).Readable;a.prototype.setEncoding=t.ReadableSetEncoding;delete a.prototype.collect}t=undefined}}},669:function(e){e.exports=__webpack_require__("jK02")},693:function(e){e.exports=[["0","\0",128],["a1","｡",62],["8140","　、。，．・：；？！゛゜´｀¨＾￣＿ヽヾゝゞ〃仝々〆〇ー―‐／＼～∥｜…‥‘’“”（）〔〕［］｛｝〈",9,"＋－±×"],["8180","÷＝≠＜＞≦≧∞∴♂♀°′″℃￥＄￠￡％＃＆＊＠§☆★○●◎◇◆□■△▲▽▼※〒→←↑↓〓"],["81b8","∈∋⊆⊇⊂⊃∪∩"],["81c8","∧∨￢⇒⇔∀∃"],["81da","∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬"],["81f0","Å‰♯♭♪†‡¶"],["81fc","◯"],["824f","０",9],["8260","Ａ",25],["8281","ａ",25],["829f","ぁ",82],["8340","ァ",62],["8380","ム",22],["839f","Α",16,"Σ",6],["83bf","α",16,"σ",6],["8440","А",5,"ЁЖ",25],["8470","а",5,"ёж",7],["8480","о",17],["849f","─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂"],["8740","①",19,"Ⅰ",9],["875f","㍉㌔㌢㍍㌘㌧㌃㌶㍑㍗㌍㌦㌣㌫㍊㌻㎜㎝㎞㎎㎏㏄㎡"],["877e","㍻"],["8780","〝〟№㏍℡㊤",4,"㈱㈲㈹㍾㍽㍼≒≡∫∮∑√⊥∠∟⊿∵∩∪"],["889f","亜唖娃阿哀愛挨姶逢葵茜穐悪握渥旭葦芦鯵梓圧斡扱宛姐虻飴絢綾鮎或粟袷安庵按暗案闇鞍杏以伊位依偉囲夷委威尉惟意慰易椅為畏異移維緯胃萎衣謂違遺医井亥域育郁磯一壱溢逸稲茨芋鰯允印咽員因姻引飲淫胤蔭"],["8940","院陰隠韻吋右宇烏羽迂雨卯鵜窺丑碓臼渦嘘唄欝蔚鰻姥厩浦瓜閏噂云運雲荏餌叡営嬰影映曳栄永泳洩瑛盈穎頴英衛詠鋭液疫益駅悦謁越閲榎厭円"],["8980","園堰奄宴延怨掩援沿演炎焔煙燕猿縁艶苑薗遠鉛鴛塩於汚甥凹央奥往応押旺横欧殴王翁襖鴬鴎黄岡沖荻億屋憶臆桶牡乙俺卸恩温穏音下化仮何伽価佳加可嘉夏嫁家寡科暇果架歌河火珂禍禾稼箇花苛茄荷華菓蝦課嘩貨迦過霞蚊俄峨我牙画臥芽蛾賀雅餓駕介会解回塊壊廻快怪悔恢懐戒拐改"],["8a40","魁晦械海灰界皆絵芥蟹開階貝凱劾外咳害崖慨概涯碍蓋街該鎧骸浬馨蛙垣柿蛎鈎劃嚇各廓拡撹格核殻獲確穫覚角赫較郭閣隔革学岳楽額顎掛笠樫"],["8a80","橿梶鰍潟割喝恰括活渇滑葛褐轄且鰹叶椛樺鞄株兜竃蒲釜鎌噛鴨栢茅萱粥刈苅瓦乾侃冠寒刊勘勧巻喚堪姦完官寛干幹患感慣憾換敢柑桓棺款歓汗漢澗潅環甘監看竿管簡緩缶翰肝艦莞観諌貫還鑑間閑関陥韓館舘丸含岸巌玩癌眼岩翫贋雁頑顔願企伎危喜器基奇嬉寄岐希幾忌揮机旗既期棋棄"],["8b40","機帰毅気汽畿祈季稀紀徽規記貴起軌輝飢騎鬼亀偽儀妓宜戯技擬欺犠疑祇義蟻誼議掬菊鞠吉吃喫桔橘詰砧杵黍却客脚虐逆丘久仇休及吸宮弓急救"],["8b80","朽求汲泣灸球究窮笈級糾給旧牛去居巨拒拠挙渠虚許距鋸漁禦魚亨享京供侠僑兇競共凶協匡卿叫喬境峡強彊怯恐恭挟教橋況狂狭矯胸脅興蕎郷鏡響饗驚仰凝尭暁業局曲極玉桐粁僅勤均巾錦斤欣欽琴禁禽筋緊芹菌衿襟謹近金吟銀九倶句区狗玖矩苦躯駆駈駒具愚虞喰空偶寓遇隅串櫛釧屑屈"],["8c40","掘窟沓靴轡窪熊隈粂栗繰桑鍬勲君薫訓群軍郡卦袈祁係傾刑兄啓圭珪型契形径恵慶慧憩掲携敬景桂渓畦稽系経継繋罫茎荊蛍計詣警軽頚鶏芸迎鯨"],["8c80","劇戟撃激隙桁傑欠決潔穴結血訣月件倹倦健兼券剣喧圏堅嫌建憲懸拳捲検権牽犬献研硯絹県肩見謙賢軒遣鍵険顕験鹸元原厳幻弦減源玄現絃舷言諺限乎個古呼固姑孤己庫弧戸故枯湖狐糊袴股胡菰虎誇跨鈷雇顧鼓五互伍午呉吾娯後御悟梧檎瑚碁語誤護醐乞鯉交佼侯候倖光公功効勾厚口向"],["8d40","后喉坑垢好孔孝宏工巧巷幸広庚康弘恒慌抗拘控攻昂晃更杭校梗構江洪浩港溝甲皇硬稿糠紅紘絞綱耕考肯肱腔膏航荒行衡講貢購郊酵鉱砿鋼閤降"],["8d80","項香高鴻剛劫号合壕拷濠豪轟麹克刻告国穀酷鵠黒獄漉腰甑忽惚骨狛込此頃今困坤墾婚恨懇昏昆根梱混痕紺艮魂些佐叉唆嵯左差査沙瑳砂詐鎖裟坐座挫債催再最哉塞妻宰彩才採栽歳済災采犀砕砦祭斎細菜裁載際剤在材罪財冴坂阪堺榊肴咲崎埼碕鷺作削咋搾昨朔柵窄策索錯桜鮭笹匙冊刷"],["8e40","察拶撮擦札殺薩雑皐鯖捌錆鮫皿晒三傘参山惨撒散桟燦珊産算纂蚕讃賛酸餐斬暫残仕仔伺使刺司史嗣四士始姉姿子屍市師志思指支孜斯施旨枝止"],["8e80","死氏獅祉私糸紙紫肢脂至視詞詩試誌諮資賜雌飼歯事似侍児字寺慈持時次滋治爾璽痔磁示而耳自蒔辞汐鹿式識鴫竺軸宍雫七叱執失嫉室悉湿漆疾質実蔀篠偲柴芝屡蕊縞舎写射捨赦斜煮社紗者謝車遮蛇邪借勺尺杓灼爵酌釈錫若寂弱惹主取守手朱殊狩珠種腫趣酒首儒受呪寿授樹綬需囚収周"],["8f40","宗就州修愁拾洲秀秋終繍習臭舟蒐衆襲讐蹴輯週酋酬集醜什住充十従戎柔汁渋獣縦重銃叔夙宿淑祝縮粛塾熟出術述俊峻春瞬竣舜駿准循旬楯殉淳"],["8f80","準潤盾純巡遵醇順処初所暑曙渚庶緒署書薯藷諸助叙女序徐恕鋤除傷償勝匠升召哨商唱嘗奨妾娼宵将小少尚庄床廠彰承抄招掌捷昇昌昭晶松梢樟樵沼消渉湘焼焦照症省硝礁祥称章笑粧紹肖菖蒋蕉衝裳訟証詔詳象賞醤鉦鍾鐘障鞘上丈丞乗冗剰城場壌嬢常情擾条杖浄状畳穣蒸譲醸錠嘱埴飾"],["9040","拭植殖燭織職色触食蝕辱尻伸信侵唇娠寝審心慎振新晋森榛浸深申疹真神秦紳臣芯薪親診身辛進針震人仁刃塵壬尋甚尽腎訊迅陣靭笥諏須酢図厨"],["9080","逗吹垂帥推水炊睡粋翠衰遂酔錐錘随瑞髄崇嵩数枢趨雛据杉椙菅頗雀裾澄摺寸世瀬畝是凄制勢姓征性成政整星晴棲栖正清牲生盛精聖声製西誠誓請逝醒青静斉税脆隻席惜戚斥昔析石積籍績脊責赤跡蹟碩切拙接摂折設窃節説雪絶舌蝉仙先千占宣専尖川戦扇撰栓栴泉浅洗染潜煎煽旋穿箭線"],["9140","繊羨腺舛船薦詮賎践選遷銭銑閃鮮前善漸然全禅繕膳糎噌塑岨措曾曽楚狙疏疎礎祖租粗素組蘇訴阻遡鼠僧創双叢倉喪壮奏爽宋層匝惣想捜掃挿掻"],["9180","操早曹巣槍槽漕燥争痩相窓糟総綜聡草荘葬蒼藻装走送遭鎗霜騒像増憎臓蔵贈造促側則即息捉束測足速俗属賊族続卒袖其揃存孫尊損村遜他多太汰詑唾堕妥惰打柁舵楕陀駄騨体堆対耐岱帯待怠態戴替泰滞胎腿苔袋貸退逮隊黛鯛代台大第醍題鷹滝瀧卓啄宅托択拓沢濯琢託鐸濁諾茸凧蛸只"],["9240","叩但達辰奪脱巽竪辿棚谷狸鱈樽誰丹単嘆坦担探旦歎淡湛炭短端箪綻耽胆蛋誕鍛団壇弾断暖檀段男談値知地弛恥智池痴稚置致蜘遅馳築畜竹筑蓄"],["9280","逐秩窒茶嫡着中仲宙忠抽昼柱注虫衷註酎鋳駐樗瀦猪苧著貯丁兆凋喋寵帖帳庁弔張彫徴懲挑暢朝潮牒町眺聴脹腸蝶調諜超跳銚長頂鳥勅捗直朕沈珍賃鎮陳津墜椎槌追鎚痛通塚栂掴槻佃漬柘辻蔦綴鍔椿潰坪壷嬬紬爪吊釣鶴亭低停偵剃貞呈堤定帝底庭廷弟悌抵挺提梯汀碇禎程締艇訂諦蹄逓"],["9340","邸鄭釘鼎泥摘擢敵滴的笛適鏑溺哲徹撤轍迭鉄典填天展店添纏甜貼転顛点伝殿澱田電兎吐堵塗妬屠徒斗杜渡登菟賭途都鍍砥砺努度土奴怒倒党冬"],["9380","凍刀唐塔塘套宕島嶋悼投搭東桃梼棟盗淘湯涛灯燈当痘祷等答筒糖統到董蕩藤討謄豆踏逃透鐙陶頭騰闘働動同堂導憧撞洞瞳童胴萄道銅峠鴇匿得徳涜特督禿篤毒独読栃橡凸突椴届鳶苫寅酉瀞噸屯惇敦沌豚遁頓呑曇鈍奈那内乍凪薙謎灘捺鍋楢馴縄畷南楠軟難汝二尼弐迩匂賑肉虹廿日乳入"],["9440","如尿韮任妊忍認濡禰祢寧葱猫熱年念捻撚燃粘乃廼之埜嚢悩濃納能脳膿農覗蚤巴把播覇杷波派琶破婆罵芭馬俳廃拝排敗杯盃牌背肺輩配倍培媒梅"],["9480","楳煤狽買売賠陪這蝿秤矧萩伯剥博拍柏泊白箔粕舶薄迫曝漠爆縛莫駁麦函箱硲箸肇筈櫨幡肌畑畠八鉢溌発醗髪伐罰抜筏閥鳩噺塙蛤隼伴判半反叛帆搬斑板氾汎版犯班畔繁般藩販範釆煩頒飯挽晩番盤磐蕃蛮匪卑否妃庇彼悲扉批披斐比泌疲皮碑秘緋罷肥被誹費避非飛樋簸備尾微枇毘琵眉美"],["9540","鼻柊稗匹疋髭彦膝菱肘弼必畢筆逼桧姫媛紐百謬俵彪標氷漂瓢票表評豹廟描病秒苗錨鋲蒜蛭鰭品彬斌浜瀕貧賓頻敏瓶不付埠夫婦富冨布府怖扶敷"],["9580","斧普浮父符腐膚芙譜負賦赴阜附侮撫武舞葡蕪部封楓風葺蕗伏副復幅服福腹複覆淵弗払沸仏物鮒分吻噴墳憤扮焚奮粉糞紛雰文聞丙併兵塀幣平弊柄並蔽閉陛米頁僻壁癖碧別瞥蔑箆偏変片篇編辺返遍便勉娩弁鞭保舗鋪圃捕歩甫補輔穂募墓慕戊暮母簿菩倣俸包呆報奉宝峰峯崩庖抱捧放方朋"],["9640","法泡烹砲縫胞芳萌蓬蜂褒訪豊邦鋒飽鳳鵬乏亡傍剖坊妨帽忘忙房暴望某棒冒紡肪膨謀貌貿鉾防吠頬北僕卜墨撲朴牧睦穆釦勃没殆堀幌奔本翻凡盆"],["9680","摩磨魔麻埋妹昧枚毎哩槙幕膜枕鮪柾鱒桝亦俣又抹末沫迄侭繭麿万慢満漫蔓味未魅巳箕岬密蜜湊蓑稔脈妙粍民眠務夢無牟矛霧鵡椋婿娘冥名命明盟迷銘鳴姪牝滅免棉綿緬面麺摸模茂妄孟毛猛盲網耗蒙儲木黙目杢勿餅尤戻籾貰問悶紋門匁也冶夜爺耶野弥矢厄役約薬訳躍靖柳薮鑓愉愈油癒"],["9740","諭輸唯佑優勇友宥幽悠憂揖有柚湧涌猶猷由祐裕誘遊邑郵雄融夕予余与誉輿預傭幼妖容庸揚揺擁曜楊様洋溶熔用窯羊耀葉蓉要謡踊遥陽養慾抑欲"],["9780","沃浴翌翼淀羅螺裸来莱頼雷洛絡落酪乱卵嵐欄濫藍蘭覧利吏履李梨理璃痢裏裡里離陸律率立葎掠略劉流溜琉留硫粒隆竜龍侶慮旅虜了亮僚両凌寮料梁涼猟療瞭稜糧良諒遼量陵領力緑倫厘林淋燐琳臨輪隣鱗麟瑠塁涙累類令伶例冷励嶺怜玲礼苓鈴隷零霊麗齢暦歴列劣烈裂廉恋憐漣煉簾練聯"],["9840","蓮連錬呂魯櫓炉賂路露労婁廊弄朗楼榔浪漏牢狼篭老聾蝋郎六麓禄肋録論倭和話歪賄脇惑枠鷲亙亘鰐詫藁蕨椀湾碗腕"],["989f","弌丐丕个丱丶丼丿乂乖乘亂亅豫亊舒弍于亞亟亠亢亰亳亶从仍仄仆仂仗仞仭仟价伉佚估佛佝佗佇佶侈侏侘佻佩佰侑佯來侖儘俔俟俎俘俛俑俚俐俤俥倚倨倔倪倥倅伜俶倡倩倬俾俯們倆偃假會偕偐偈做偖偬偸傀傚傅傴傲"],["9940","僉僊傳僂僖僞僥僭僣僮價僵儉儁儂儖儕儔儚儡儺儷儼儻儿兀兒兌兔兢竸兩兪兮冀冂囘册冉冏冑冓冕冖冤冦冢冩冪冫决冱冲冰况冽凅凉凛几處凩凭"],["9980","凰凵凾刄刋刔刎刧刪刮刳刹剏剄剋剌剞剔剪剴剩剳剿剽劍劔劒剱劈劑辨辧劬劭劼劵勁勍勗勞勣勦飭勠勳勵勸勹匆匈甸匍匐匏匕匚匣匯匱匳匸區卆卅丗卉卍凖卞卩卮夘卻卷厂厖厠厦厥厮厰厶參簒雙叟曼燮叮叨叭叺吁吽呀听吭吼吮吶吩吝呎咏呵咎呟呱呷呰咒呻咀呶咄咐咆哇咢咸咥咬哄哈咨"],["9a40","咫哂咤咾咼哘哥哦唏唔哽哮哭哺哢唹啀啣啌售啜啅啖啗唸唳啝喙喀咯喊喟啻啾喘喞單啼喃喩喇喨嗚嗅嗟嗄嗜嗤嗔嘔嗷嘖嗾嗽嘛嗹噎噐營嘴嘶嘲嘸"],["9a80","噫噤嘯噬噪嚆嚀嚊嚠嚔嚏嚥嚮嚶嚴囂嚼囁囃囀囈囎囑囓囗囮囹圀囿圄圉圈國圍圓團圖嗇圜圦圷圸坎圻址坏坩埀垈坡坿垉垓垠垳垤垪垰埃埆埔埒埓堊埖埣堋堙堝塲堡塢塋塰毀塒堽塹墅墹墟墫墺壞墻墸墮壅壓壑壗壙壘壥壜壤壟壯壺壹壻壼壽夂夊夐夛梦夥夬夭夲夸夾竒奕奐奎奚奘奢奠奧奬奩"],["9b40","奸妁妝佞侫妣妲姆姨姜妍姙姚娥娟娑娜娉娚婀婬婉娵娶婢婪媚媼媾嫋嫂媽嫣嫗嫦嫩嫖嫺嫻嬌嬋嬖嬲嫐嬪嬶嬾孃孅孀孑孕孚孛孥孩孰孳孵學斈孺宀"],["9b80","它宦宸寃寇寉寔寐寤實寢寞寥寫寰寶寳尅將專對尓尠尢尨尸尹屁屆屎屓屐屏孱屬屮乢屶屹岌岑岔妛岫岻岶岼岷峅岾峇峙峩峽峺峭嶌峪崋崕崗嵜崟崛崑崔崢崚崙崘嵌嵒嵎嵋嵬嵳嵶嶇嶄嶂嶢嶝嶬嶮嶽嶐嶷嶼巉巍巓巒巖巛巫已巵帋帚帙帑帛帶帷幄幃幀幎幗幔幟幢幤幇幵并幺麼广庠廁廂廈廐廏"],["9c40","廖廣廝廚廛廢廡廨廩廬廱廳廰廴廸廾弃弉彝彜弋弑弖弩弭弸彁彈彌彎弯彑彖彗彙彡彭彳彷徃徂彿徊很徑徇從徙徘徠徨徭徼忖忻忤忸忱忝悳忿怡恠"],["9c80","怙怐怩怎怱怛怕怫怦怏怺恚恁恪恷恟恊恆恍恣恃恤恂恬恫恙悁悍惧悃悚悄悛悖悗悒悧悋惡悸惠惓悴忰悽惆悵惘慍愕愆惶惷愀惴惺愃愡惻惱愍愎慇愾愨愧慊愿愼愬愴愽慂慄慳慷慘慙慚慫慴慯慥慱慟慝慓慵憙憖憇憬憔憚憊憑憫憮懌懊應懷懈懃懆憺懋罹懍懦懣懶懺懴懿懽懼懾戀戈戉戍戌戔戛"],["9d40","戞戡截戮戰戲戳扁扎扞扣扛扠扨扼抂抉找抒抓抖拔抃抔拗拑抻拏拿拆擔拈拜拌拊拂拇抛拉挌拮拱挧挂挈拯拵捐挾捍搜捏掖掎掀掫捶掣掏掉掟掵捫"],["9d80","捩掾揩揀揆揣揉插揶揄搖搴搆搓搦搶攝搗搨搏摧摯摶摎攪撕撓撥撩撈撼據擒擅擇撻擘擂擱擧舉擠擡抬擣擯攬擶擴擲擺攀擽攘攜攅攤攣攫攴攵攷收攸畋效敖敕敍敘敞敝敲數斂斃變斛斟斫斷旃旆旁旄旌旒旛旙无旡旱杲昊昃旻杳昵昶昴昜晏晄晉晁晞晝晤晧晨晟晢晰暃暈暎暉暄暘暝曁暹曉暾暼"],["9e40","曄暸曖曚曠昿曦曩曰曵曷朏朖朞朦朧霸朮朿朶杁朸朷杆杞杠杙杣杤枉杰枩杼杪枌枋枦枡枅枷柯枴柬枳柩枸柤柞柝柢柮枹柎柆柧檜栞框栩桀桍栲桎"],["9e80","梳栫桙档桷桿梟梏梭梔條梛梃檮梹桴梵梠梺椏梍桾椁棊椈棘椢椦棡椌棍棔棧棕椶椒椄棗棣椥棹棠棯椨椪椚椣椡棆楹楷楜楸楫楔楾楮椹楴椽楙椰楡楞楝榁楪榲榮槐榿槁槓榾槎寨槊槝榻槃榧樮榑榠榜榕榴槞槨樂樛槿權槹槲槧樅榱樞槭樔槫樊樒櫁樣樓橄樌橲樶橸橇橢橙橦橈樸樢檐檍檠檄檢檣"],["9f40","檗蘗檻櫃櫂檸檳檬櫞櫑櫟檪櫚櫪櫻欅蘖櫺欒欖鬱欟欸欷盜欹飮歇歃歉歐歙歔歛歟歡歸歹歿殀殄殃殍殘殕殞殤殪殫殯殲殱殳殷殼毆毋毓毟毬毫毳毯"],["9f80","麾氈氓气氛氤氣汞汕汢汪沂沍沚沁沛汾汨汳沒沐泄泱泓沽泗泅泝沮沱沾沺泛泯泙泪洟衍洶洫洽洸洙洵洳洒洌浣涓浤浚浹浙涎涕濤涅淹渕渊涵淇淦涸淆淬淞淌淨淒淅淺淙淤淕淪淮渭湮渮渙湲湟渾渣湫渫湶湍渟湃渺湎渤滿渝游溂溪溘滉溷滓溽溯滄溲滔滕溏溥滂溟潁漑灌滬滸滾漿滲漱滯漲滌"],["e040","漾漓滷澆潺潸澁澀潯潛濳潭澂潼潘澎澑濂潦澳澣澡澤澹濆澪濟濕濬濔濘濱濮濛瀉瀋濺瀑瀁瀏濾瀛瀚潴瀝瀘瀟瀰瀾瀲灑灣炙炒炯烱炬炸炳炮烟烋烝"],["e080","烙焉烽焜焙煥煕熈煦煢煌煖煬熏燻熄熕熨熬燗熹熾燒燉燔燎燠燬燧燵燼燹燿爍爐爛爨爭爬爰爲爻爼爿牀牆牋牘牴牾犂犁犇犒犖犢犧犹犲狃狆狄狎狒狢狠狡狹狷倏猗猊猜猖猝猴猯猩猥猾獎獏默獗獪獨獰獸獵獻獺珈玳珎玻珀珥珮珞璢琅瑯琥珸琲琺瑕琿瑟瑙瑁瑜瑩瑰瑣瑪瑶瑾璋璞璧瓊瓏瓔珱"],["e140","瓠瓣瓧瓩瓮瓲瓰瓱瓸瓷甄甃甅甌甎甍甕甓甞甦甬甼畄畍畊畉畛畆畚畩畤畧畫畭畸當疆疇畴疊疉疂疔疚疝疥疣痂疳痃疵疽疸疼疱痍痊痒痙痣痞痾痿"],["e180","痼瘁痰痺痲痳瘋瘍瘉瘟瘧瘠瘡瘢瘤瘴瘰瘻癇癈癆癜癘癡癢癨癩癪癧癬癰癲癶癸發皀皃皈皋皎皖皓皙皚皰皴皸皹皺盂盍盖盒盞盡盥盧盪蘯盻眈眇眄眩眤眞眥眦眛眷眸睇睚睨睫睛睥睿睾睹瞎瞋瞑瞠瞞瞰瞶瞹瞿瞼瞽瞻矇矍矗矚矜矣矮矼砌砒礦砠礪硅碎硴碆硼碚碌碣碵碪碯磑磆磋磔碾碼磅磊磬"],["e240","磧磚磽磴礇礒礑礙礬礫祀祠祗祟祚祕祓祺祿禊禝禧齋禪禮禳禹禺秉秕秧秬秡秣稈稍稘稙稠稟禀稱稻稾稷穃穗穉穡穢穩龝穰穹穽窈窗窕窘窖窩竈窰"],["e280","窶竅竄窿邃竇竊竍竏竕竓站竚竝竡竢竦竭竰笂笏笊笆笳笘笙笞笵笨笶筐筺笄筍笋筌筅筵筥筴筧筰筱筬筮箝箘箟箍箜箚箋箒箏筝箙篋篁篌篏箴篆篝篩簑簔篦篥籠簀簇簓篳篷簗簍篶簣簧簪簟簷簫簽籌籃籔籏籀籐籘籟籤籖籥籬籵粃粐粤粭粢粫粡粨粳粲粱粮粹粽糀糅糂糘糒糜糢鬻糯糲糴糶糺紆"],["e340","紂紜紕紊絅絋紮紲紿紵絆絳絖絎絲絨絮絏絣經綉絛綏絽綛綺綮綣綵緇綽綫總綢綯緜綸綟綰緘緝緤緞緻緲緡縅縊縣縡縒縱縟縉縋縢繆繦縻縵縹繃縷"],["e380","縲縺繧繝繖繞繙繚繹繪繩繼繻纃緕繽辮繿纈纉續纒纐纓纔纖纎纛纜缸缺罅罌罍罎罐网罕罔罘罟罠罨罩罧罸羂羆羃羈羇羌羔羞羝羚羣羯羲羹羮羶羸譱翅翆翊翕翔翡翦翩翳翹飜耆耄耋耒耘耙耜耡耨耿耻聊聆聒聘聚聟聢聨聳聲聰聶聹聽聿肄肆肅肛肓肚肭冐肬胛胥胙胝胄胚胖脉胯胱脛脩脣脯腋"],["e440","隋腆脾腓腑胼腱腮腥腦腴膃膈膊膀膂膠膕膤膣腟膓膩膰膵膾膸膽臀臂膺臉臍臑臙臘臈臚臟臠臧臺臻臾舁舂舅與舊舍舐舖舩舫舸舳艀艙艘艝艚艟艤"],["e480","艢艨艪艫舮艱艷艸艾芍芒芫芟芻芬苡苣苟苒苴苳苺莓范苻苹苞茆苜茉苙茵茴茖茲茱荀茹荐荅茯茫茗茘莅莚莪莟莢莖茣莎莇莊荼莵荳荵莠莉莨菴萓菫菎菽萃菘萋菁菷萇菠菲萍萢萠莽萸蔆菻葭萪萼蕚蒄葷葫蒭葮蒂葩葆萬葯葹萵蓊葢蒹蒿蒟蓙蓍蒻蓚蓐蓁蓆蓖蒡蔡蓿蓴蔗蔘蔬蔟蔕蔔蓼蕀蕣蕘蕈"],["e540","蕁蘂蕋蕕薀薤薈薑薊薨蕭薔薛藪薇薜蕷蕾薐藉薺藏薹藐藕藝藥藜藹蘊蘓蘋藾藺蘆蘢蘚蘰蘿虍乕虔號虧虱蚓蚣蚩蚪蚋蚌蚶蚯蛄蛆蚰蛉蠣蚫蛔蛞蛩蛬"],["e580","蛟蛛蛯蜒蜆蜈蜀蜃蛻蜑蜉蜍蛹蜊蜴蜿蜷蜻蜥蜩蜚蝠蝟蝸蝌蝎蝴蝗蝨蝮蝙蝓蝣蝪蠅螢螟螂螯蟋螽蟀蟐雖螫蟄螳蟇蟆螻蟯蟲蟠蠏蠍蟾蟶蟷蠎蟒蠑蠖蠕蠢蠡蠱蠶蠹蠧蠻衄衂衒衙衞衢衫袁衾袞衵衽袵衲袂袗袒袮袙袢袍袤袰袿袱裃裄裔裘裙裝裹褂裼裴裨裲褄褌褊褓襃褞褥褪褫襁襄褻褶褸襌褝襠襞"],["e640","襦襤襭襪襯襴襷襾覃覈覊覓覘覡覩覦覬覯覲覺覽覿觀觚觜觝觧觴觸訃訖訐訌訛訝訥訶詁詛詒詆詈詼詭詬詢誅誂誄誨誡誑誥誦誚誣諄諍諂諚諫諳諧"],["e680","諤諱謔諠諢諷諞諛謌謇謚諡謖謐謗謠謳鞫謦謫謾謨譁譌譏譎證譖譛譚譫譟譬譯譴譽讀讌讎讒讓讖讙讚谺豁谿豈豌豎豐豕豢豬豸豺貂貉貅貊貍貎貔豼貘戝貭貪貽貲貳貮貶賈賁賤賣賚賽賺賻贄贅贊贇贏贍贐齎贓賍贔贖赧赭赱赳趁趙跂趾趺跏跚跖跌跛跋跪跫跟跣跼踈踉跿踝踞踐踟蹂踵踰踴蹊"],["e740","蹇蹉蹌蹐蹈蹙蹤蹠踪蹣蹕蹶蹲蹼躁躇躅躄躋躊躓躑躔躙躪躡躬躰軆躱躾軅軈軋軛軣軼軻軫軾輊輅輕輒輙輓輜輟輛輌輦輳輻輹轅轂輾轌轉轆轎轗轜"],["e780","轢轣轤辜辟辣辭辯辷迚迥迢迪迯邇迴逅迹迺逑逕逡逍逞逖逋逧逶逵逹迸遏遐遑遒逎遉逾遖遘遞遨遯遶隨遲邂遽邁邀邊邉邏邨邯邱邵郢郤扈郛鄂鄒鄙鄲鄰酊酖酘酣酥酩酳酲醋醉醂醢醫醯醪醵醴醺釀釁釉釋釐釖釟釡釛釼釵釶鈞釿鈔鈬鈕鈑鉞鉗鉅鉉鉤鉈銕鈿鉋鉐銜銖銓銛鉚鋏銹銷鋩錏鋺鍄錮"],["e840","錙錢錚錣錺錵錻鍜鍠鍼鍮鍖鎰鎬鎭鎔鎹鏖鏗鏨鏥鏘鏃鏝鏐鏈鏤鐚鐔鐓鐃鐇鐐鐶鐫鐵鐡鐺鑁鑒鑄鑛鑠鑢鑞鑪鈩鑰鑵鑷鑽鑚鑼鑾钁鑿閂閇閊閔閖閘閙"],["e880","閠閨閧閭閼閻閹閾闊濶闃闍闌闕闔闖關闡闥闢阡阨阮阯陂陌陏陋陷陜陞陝陟陦陲陬隍隘隕隗險隧隱隲隰隴隶隸隹雎雋雉雍襍雜霍雕雹霄霆霈霓霎霑霏霖霙霤霪霰霹霽霾靄靆靈靂靉靜靠靤靦靨勒靫靱靹鞅靼鞁靺鞆鞋鞏鞐鞜鞨鞦鞣鞳鞴韃韆韈韋韜韭齏韲竟韶韵頏頌頸頤頡頷頽顆顏顋顫顯顰"],["e940","顱顴顳颪颯颱颶飄飃飆飩飫餃餉餒餔餘餡餝餞餤餠餬餮餽餾饂饉饅饐饋饑饒饌饕馗馘馥馭馮馼駟駛駝駘駑駭駮駱駲駻駸騁騏騅駢騙騫騷驅驂驀驃"],["e980","騾驕驍驛驗驟驢驥驤驩驫驪骭骰骼髀髏髑髓體髞髟髢髣髦髯髫髮髴髱髷髻鬆鬘鬚鬟鬢鬣鬥鬧鬨鬩鬪鬮鬯鬲魄魃魏魍魎魑魘魴鮓鮃鮑鮖鮗鮟鮠鮨鮴鯀鯊鮹鯆鯏鯑鯒鯣鯢鯤鯔鯡鰺鯲鯱鯰鰕鰔鰉鰓鰌鰆鰈鰒鰊鰄鰮鰛鰥鰤鰡鰰鱇鰲鱆鰾鱚鱠鱧鱶鱸鳧鳬鳰鴉鴈鳫鴃鴆鴪鴦鶯鴣鴟鵄鴕鴒鵁鴿鴾鵆鵈"],["ea40","鵝鵞鵤鵑鵐鵙鵲鶉鶇鶫鵯鵺鶚鶤鶩鶲鷄鷁鶻鶸鶺鷆鷏鷂鷙鷓鷸鷦鷭鷯鷽鸚鸛鸞鹵鹹鹽麁麈麋麌麒麕麑麝麥麩麸麪麭靡黌黎黏黐黔黜點黝黠黥黨黯"],["ea80","黴黶黷黹黻黼黽鼇鼈皷鼕鼡鼬鼾齊齒齔齣齟齠齡齦齧齬齪齷齲齶龕龜龠堯槇遙瑤凜熙"],["ed40","纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏"],["ed80","塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱"],["ee40","犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙"],["ee80","蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"],["eeef","ⅰ",9,"￢￤＇＂"],["f040","",62],["f080","",124],["f140","",62],["f180","",124],["f240","",62],["f280","",124],["f340","",62],["f380","",124],["f440","",62],["f480","",124],["f540","",62],["f580","",124],["f640","",62],["f680","",124],["f740","",62],["f780","",124],["f840","",62],["f880","",124],["f940",""],["fa40","ⅰ",9,"Ⅰ",9,"￢￤＇＂㈱№℡∵纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊"],["fa80","兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯"],["fb40","涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神"],["fb80","祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙"],["fc40","髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"]]},767:function(e){"use strict";e.exports=bytes;e.exports.format=format;e.exports.parse=parse;var t=/\B(?=(\d{3})+(?!\d))/g;var r=/(?:\.0*|(\.[^0]+)0+)$/;var i={b:1,kb:1<<10,mb:1<<20,gb:1<<30,tb:Math.pow(1024,4),pb:Math.pow(1024,5)};var n=/^((-|\+)?(\d+(?:\.\d+)?)) *(kb|mb|gb|tb|pb)$/i;function bytes(e,t){if(typeof e==="string"){return parse(e)}if(typeof e==="number"){return format(e,t)}return null}function format(e,n){if(!Number.isFinite(e)){return null}var a=Math.abs(e);var o=n&&n.thousandsSeparator||"";var c=n&&n.unitSeparator||"";var s=n&&n.decimalPlaces!==undefined?n.decimalPlaces:2;var f=Boolean(n&&n.fixedDecimals);var p=n&&n.unit||"";if(!p||!i[p.toLowerCase()]){if(a>=i.pb){p="PB"}else if(a>=i.tb){p="TB"}else if(a>=i.gb){p="GB"}else if(a>=i.mb){p="MB"}else if(a>=i.kb){p="KB"}else{p="B"}}var u=e/i[p.toLowerCase()];var h=u.toFixed(s);if(!f){h=h.replace(r,"$1")}if(o){h=h.replace(t,o)}return h+c+p}function parse(e){if(typeof e==="number"&&!isNaN(e)){return e}if(typeof e!=="string"){return null}var t=n.exec(e);var r;var a="b";if(!t){r=parseInt(e,10);a="b"}else{r=parseFloat(t[1]);a=t[4].toLowerCase()}return Math.floor(i[a]*r)}},791:function(e){e.exports=[["0","\0",127,"€"],["8140","丂丄丅丆丏丒丗丟丠両丣並丩丮丯丱丳丵丷丼乀乁乂乄乆乊乑乕乗乚乛乢乣乤乥乧乨乪",5,"乲乴",9,"乿",6,"亇亊"],["8180","亐亖亗亙亜亝亞亣亪亯亰亱亴亶亷亸亹亼亽亾仈仌仏仐仒仚仛仜仠仢仦仧仩仭仮仯仱仴仸仹仺仼仾伀伂",6,"伋伌伒",4,"伜伝伡伣伨伩伬伭伮伱伳伵伷伹伻伾",4,"佄佅佇",5,"佒佔佖佡佢佦佨佪佫佭佮佱佲併佷佸佹佺佽侀侁侂侅來侇侊侌侎侐侒侓侕侖侘侙侚侜侞侟価侢"],["8240","侤侫侭侰",4,"侶",8,"俀俁係俆俇俈俉俋俌俍俒",4,"俙俛俠俢俤俥俧俫俬俰俲俴俵俶俷俹俻俼俽俿",11],["8280","個倎倐們倓倕倖倗倛倝倞倠倢倣値倧倫倯",10,"倻倽倿偀偁偂偄偅偆偉偊偋偍偐",4,"偖偗偘偙偛偝",7,"偦",5,"偭",8,"偸偹偺偼偽傁傂傃傄傆傇傉傊傋傌傎",20,"傤傦傪傫傭",4,"傳",6,"傼"],["8340","傽",17,"僐",5,"僗僘僙僛",10,"僨僩僪僫僯僰僱僲僴僶",4,"僼",9,"儈"],["8380","儉儊儌",5,"儓",13,"儢",28,"兂兇兊兌兎兏児兒兓兗兘兙兛兝",4,"兣兤兦內兩兪兯兲兺兾兿冃冄円冇冊冋冎冏冐冑冓冔冘冚冝冞冟冡冣冦",4,"冭冮冴冸冹冺冾冿凁凂凃凅凈凊凍凎凐凒",5],["8440","凘凙凚凜凞凟凢凣凥",5,"凬凮凱凲凴凷凾刄刅刉刋刌刏刐刓刔刕刜刞刟刡刢刣別刦刧刪刬刯刱刲刴刵刼刾剄",5,"剋剎剏剒剓剕剗剘"],["8480","剙剚剛剝剟剠剢剣剤剦剨剫剬剭剮剰剱剳",9,"剾劀劃",4,"劉",6,"劑劒劔",6,"劜劤劥劦劧劮劯劰労",9,"勀勁勂勄勅勆勈勊勌勍勎勏勑勓勔動勗務",5,"勠勡勢勣勥",10,"勱",7,"勻勼勽匁匂匃匄匇匉匊匋匌匎"],["8540","匑匒匓匔匘匛匜匞匟匢匤匥匧匨匩匫匬匭匯",9,"匼匽區卂卄卆卋卌卍卐協単卙卛卝卥卨卪卬卭卲卶卹卻卼卽卾厀厁厃厇厈厊厎厏"],["8580","厐",4,"厖厗厙厛厜厞厠厡厤厧厪厫厬厭厯",6,"厷厸厹厺厼厽厾叀參",4,"収叏叐叒叓叕叚叜叝叞叡叢叧叴叺叾叿吀吂吅吇吋吔吘吙吚吜吢吤吥吪吰吳吶吷吺吽吿呁呂呄呅呇呉呌呍呎呏呑呚呝",4,"呣呥呧呩",7,"呴呹呺呾呿咁咃咅咇咈咉咊咍咑咓咗咘咜咞咟咠咡"],["8640","咢咥咮咰咲咵咶咷咹咺咼咾哃哅哊哋哖哘哛哠",4,"哫哬哯哰哱哴",5,"哻哾唀唂唃唄唅唈唊",4,"唒唓唕",5,"唜唝唞唟唡唥唦"],["8680","唨唩唫唭唲唴唵唶唸唹唺唻唽啀啂啅啇啈啋",4,"啑啒啓啔啗",4,"啝啞啟啠啢啣啨啩啫啯",5,"啹啺啽啿喅喆喌喍喎喐喒喓喕喖喗喚喛喞喠",6,"喨",8,"喲喴営喸喺喼喿",4,"嗆嗇嗈嗊嗋嗎嗏嗐嗕嗗",4,"嗞嗠嗢嗧嗩嗭嗮嗰嗱嗴嗶嗸",4,"嗿嘂嘃嘄嘅"],["8740","嘆嘇嘊嘋嘍嘐",7,"嘙嘚嘜嘝嘠嘡嘢嘥嘦嘨嘩嘪嘫嘮嘯嘰嘳嘵嘷嘸嘺嘼嘽嘾噀",11,"噏",4,"噕噖噚噛噝",4],["8780","噣噥噦噧噭噮噯噰噲噳噴噵噷噸噹噺噽",7,"嚇",6,"嚐嚑嚒嚔",14,"嚤",10,"嚰",6,"嚸嚹嚺嚻嚽",12,"囋",8,"囕囖囘囙囜団囥",5,"囬囮囯囲図囶囷囸囻囼圀圁圂圅圇國",6],["8840","園",9,"圝圞圠圡圢圤圥圦圧圫圱圲圴",4,"圼圽圿坁坃坄坅坆坈坉坋坒",4,"坘坙坢坣坥坧坬坮坰坱坲坴坵坸坹坺坽坾坿垀"],["8880","垁垇垈垉垊垍",4,"垔",6,"垜垝垞垟垥垨垪垬垯垰垱垳垵垶垷垹",8,"埄",6,"埌埍埐埑埓埖埗埛埜埞埡埢埣埥",7,"埮埰埱埲埳埵埶執埻埼埾埿堁堃堄堅堈堉堊堌堎堏堐堒堓堔堖堗堘堚堛堜堝堟堢堣堥",4,"堫",4,"報堲堳場堶",7],["8940","堾",5,"塅",6,"塎塏塐塒塓塕塖塗塙",4,"塟",5,"塦",4,"塭",16,"塿墂墄墆墇墈墊墋墌"],["8980","墍",4,"墔",4,"墛墜墝墠",7,"墪",17,"墽墾墿壀壂壃壄壆",10,"壒壓壔壖",13,"壥",5,"壭壯壱売壴壵壷壸壺",7,"夃夅夆夈",4,"夎夐夑夒夓夗夘夛夝夞夠夡夢夣夦夨夬夰夲夳夵夶夻"],["8a40","夽夾夿奀奃奅奆奊奌奍奐奒奓奙奛",4,"奡奣奤奦",12,"奵奷奺奻奼奾奿妀妅妉妋妌妎妏妐妑妔妕妘妚妛妜妝妟妠妡妢妦"],["8a80","妧妬妭妰妱妳",5,"妺妼妽妿",6,"姇姈姉姌姍姎姏姕姖姙姛姞",4,"姤姦姧姩姪姫姭",11,"姺姼姽姾娀娂娊娋娍娎娏娐娒娔娕娖娗娙娚娛娝娞娡娢娤娦娧娨娪",6,"娳娵娷",4,"娽娾娿婁",4,"婇婈婋",9,"婖婗婘婙婛",5],["8b40","婡婣婤婥婦婨婩婫",8,"婸婹婻婼婽婾媀",17,"媓",6,"媜",13,"媫媬"],["8b80","媭",4,"媴媶媷媹",4,"媿嫀嫃",5,"嫊嫋嫍",4,"嫓嫕嫗嫙嫚嫛嫝嫞嫟嫢嫤嫥嫧嫨嫪嫬",4,"嫲",22,"嬊",11,"嬘",25,"嬳嬵嬶嬸",7,"孁",6],["8c40","孈",7,"孒孖孞孠孡孧孨孫孭孮孯孲孴孶孷學孹孻孼孾孿宂宆宊宍宎宐宑宒宔宖実宧宨宩宬宭宮宯宱宲宷宺宻宼寀寁寃寈寉寊寋寍寎寏"],["8c80","寑寔",8,"寠寢寣實寧審",4,"寯寱",6,"寽対尀専尃尅將專尋尌對導尐尒尓尗尙尛尞尟尠尡尣尦尨尩尪尫尭尮尯尰尲尳尵尶尷屃屄屆屇屌屍屒屓屔屖屗屘屚屛屜屝屟屢層屧",6,"屰屲",6,"屻屼屽屾岀岃",4,"岉岊岋岎岏岒岓岕岝",4,"岤",4],["8d40","岪岮岯岰岲岴岶岹岺岻岼岾峀峂峃峅",5,"峌",5,"峓",5,"峚",6,"峢峣峧峩峫峬峮峯峱",9,"峼",4],["8d80","崁崄崅崈",5,"崏",4,"崕崗崘崙崚崜崝崟",4,"崥崨崪崫崬崯",4,"崵",7,"崿",7,"嵈嵉嵍",10,"嵙嵚嵜嵞",10,"嵪嵭嵮嵰嵱嵲嵳嵵",12,"嶃",21,"嶚嶛嶜嶞嶟嶠"],["8e40","嶡",21,"嶸",12,"巆",6,"巎",12,"巜巟巠巣巤巪巬巭"],["8e80","巰巵巶巸",4,"巿帀帄帇帉帊帋帍帎帒帓帗帞",7,"帨",4,"帯帰帲",4,"帹帺帾帿幀幁幃幆",5,"幍",6,"幖",4,"幜幝幟幠幣",14,"幵幷幹幾庁庂広庅庈庉庌庍庎庒庘庛庝庡庢庣庤庨",4,"庮",4,"庴庺庻庼庽庿",6],["8f40","廆廇廈廋",5,"廔廕廗廘廙廚廜",11,"廩廫",8,"廵廸廹廻廼廽弅弆弇弉弌弍弎弐弒弔弖弙弚弜弝弞弡弢弣弤"],["8f80","弨弫弬弮弰弲",6,"弻弽弾弿彁",14,"彑彔彙彚彛彜彞彟彠彣彥彧彨彫彮彯彲彴彵彶彸彺彽彾彿徃徆徍徎徏徑従徔徖徚徛徝從徟徠徢",5,"復徫徬徯",5,"徶徸徹徺徻徾",4,"忇忈忊忋忎忓忔忕忚忛応忞忟忢忣忥忦忨忩忬忯忰忲忳忴忶忷忹忺忼怇"],["9040","怈怉怋怌怐怑怓怗怘怚怞怟怢怣怤怬怭怮怰",4,"怶",4,"怽怾恀恄",6,"恌恎恏恑恓恔恖恗恘恛恜恞恟恠恡恥恦恮恱恲恴恵恷恾悀"],["9080","悁悂悅悆悇悈悊悋悎悏悐悑悓悕悗悘悙悜悞悡悢悤悥悧悩悪悮悰悳悵悶悷悹悺悽",7,"惇惈惉惌",4,"惒惓惔惖惗惙惛惞惡",4,"惪惱惲惵惷惸惻",4,"愂愃愄愅愇愊愋愌愐",4,"愖愗愘愙愛愜愝愞愡愢愥愨愩愪愬",18,"慀",6],["9140","慇慉態慍慏慐慒慓慔慖",6,"慞慟慠慡慣慤慥慦慩",6,"慱慲慳慴慶慸",18,"憌憍憏",4,"憕"],["9180","憖",6,"憞",8,"憪憫憭",9,"憸",5,"憿懀懁懃",4,"應懌",4,"懓懕",16,"懧",13,"懶",8,"戀",5,"戇戉戓戔戙戜戝戞戠戣戦戧戨戩戫戭戯戰戱戲戵戶戸",4,"扂扄扅扆扊"],["9240","扏扐払扖扗扙扚扜",6,"扤扥扨扱扲扴扵扷扸扺扻扽抁抂抃抅抆抇抈抋",5,"抔抙抜抝択抣抦抧抩抪抭抮抯抰抲抳抴抶抷抸抺抾拀拁"],["9280","拃拋拏拑拕拝拞拠拡拤拪拫拰拲拵拸拹拺拻挀挃挄挅挆挊挋挌挍挏挐挒挓挔挕挗挘挙挜挦挧挩挬挭挮挰挱挳",5,"挻挼挾挿捀捁捄捇捈捊捑捒捓捔捖",7,"捠捤捥捦捨捪捫捬捯捰捲捳捴捵捸捹捼捽捾捿掁掃掄掅掆掋掍掑掓掔掕掗掙",6,"採掤掦掫掯掱掲掵掶掹掻掽掿揀"],["9340","揁揂揃揅揇揈揊揋揌揑揓揔揕揗",6,"揟揢揤",4,"揫揬揮揯揰揱揳揵揷揹揺揻揼揾搃搄搆",4,"損搎搑搒搕",5,"搝搟搢搣搤"],["9380","搥搧搨搩搫搮",5,"搵",4,"搻搼搾摀摂摃摉摋",6,"摓摕摖摗摙",4,"摟",7,"摨摪摫摬摮",9,"摻",6,"撃撆撈",8,"撓撔撗撘撚撛撜撝撟",4,"撥撦撧撨撪撫撯撱撲撳撴撶撹撻撽撾撿擁擃擄擆",6,"擏擑擓擔擕擖擙據"],["9440","擛擜擝擟擠擡擣擥擧",24,"攁",7,"攊",7,"攓",4,"攙",8],["9480","攢攣攤攦",4,"攬攭攰攱攲攳攷攺攼攽敀",4,"敆敇敊敋敍敎敐敒敓敔敗敘敚敜敟敠敡敤敥敧敨敩敪敭敮敯敱敳敵敶數",14,"斈斉斊斍斎斏斒斔斕斖斘斚斝斞斠斢斣斦斨斪斬斮斱",7,"斺斻斾斿旀旂旇旈旉旊旍旐旑旓旔旕旘",7,"旡旣旤旪旫"],["9540","旲旳旴旵旸旹旻",4,"昁昄昅昇昈昉昋昍昐昑昒昖昗昘昚昛昜昞昡昢昣昤昦昩昪昫昬昮昰昲昳昷",4,"昽昿晀時晄",6,"晍晎晐晑晘"],["9580","晙晛晜晝晞晠晢晣晥晧晩",4,"晱晲晳晵晸晹晻晼晽晿暀暁暃暅暆暈暉暊暋暍暎暏暐暒暓暔暕暘",4,"暞",8,"暩",4,"暯",4,"暵暶暷暸暺暻暼暽暿",25,"曚曞",7,"曧曨曪",5,"曱曵曶書曺曻曽朁朂會"],["9640","朄朅朆朇朌朎朏朑朒朓朖朘朙朚朜朞朠",5,"朧朩朮朰朲朳朶朷朸朹朻朼朾朿杁杄杅杇杊杋杍杒杔杕杗",4,"杝杢杣杤杦杧杫杬杮東杴杶"],["9680","杸杹杺杻杽枀枂枃枅枆枈枊枌枍枎枏枑枒枓枔枖枙枛枟枠枡枤枦枩枬枮枱枲枴枹",7,"柂柅",9,"柕柖柗柛柟柡柣柤柦柧柨柪柫柭柮柲柵",7,"柾栁栂栃栄栆栍栐栒栔栕栘",4,"栞栟栠栢",6,"栫",6,"栴栵栶栺栻栿桇桋桍桏桒桖",5],["9740","桜桝桞桟桪桬",7,"桵桸",8,"梂梄梇",7,"梐梑梒梔梕梖梘",9,"梣梤梥梩梪梫梬梮梱梲梴梶梷梸"],["9780","梹",6,"棁棃",5,"棊棌棎棏棐棑棓棔棖棗棙棛",4,"棡棢棤",9,"棯棲棳棴棶棷棸棻棽棾棿椀椂椃椄椆",4,"椌椏椑椓",11,"椡椢椣椥",7,"椮椯椱椲椳椵椶椷椸椺椻椼椾楀楁楃",16,"楕楖楘楙楛楜楟"],["9840","楡楢楤楥楧楨楩楪楬業楯楰楲",4,"楺楻楽楾楿榁榃榅榊榋榌榎",5,"榖榗榙榚榝",9,"榩榪榬榮榯榰榲榳榵榶榸榹榺榼榽"],["9880","榾榿槀槂",7,"構槍槏槑槒槓槕",5,"槜槝槞槡",11,"槮槯槰槱槳",9,"槾樀",9,"樋",11,"標",5,"樠樢",5,"権樫樬樭樮樰樲樳樴樶",6,"樿",4,"橅橆橈",7,"橑",6,"橚"],["9940","橜",4,"橢橣橤橦",10,"橲",6,"橺橻橽橾橿檁檂檃檅",8,"檏檒",4,"檘",7,"檡",5],["9980","檧檨檪檭",114,"欥欦欨",6],["9a40","欯欰欱欳欴欵欶欸欻欼欽欿歀歁歂歄歅歈歊歋歍",11,"歚",7,"歨歩歫",13,"歺歽歾歿殀殅殈"],["9a80","殌殎殏殐殑殔殕殗殘殙殜",4,"殢",7,"殫",7,"殶殸",6,"毀毃毄毆",4,"毌毎毐毑毘毚毜",4,"毢",7,"毬毭毮毰毱毲毴毶毷毸毺毻毼毾",6,"氈",4,"氎氒気氜氝氞氠氣氥氫氬氭氱氳氶氷氹氺氻氼氾氿汃汄汅汈汋",4,"汑汒汓汖汘"],["9b40","汙汚汢汣汥汦汧汫",4,"汱汳汵汷汸決汻汼汿沀沄沇沊沋沍沎沑沒沕沖沗沘沚沜沝沞沠沢沨沬沯沰沴沵沶沷沺泀況泂泃泆泇泈泋泍泎泏泑泒泘"],["9b80","泙泚泜泝泟泤泦泧泩泬泭泲泴泹泿洀洂洃洅洆洈洉洊洍洏洐洑洓洔洕洖洘洜洝洟",5,"洦洨洩洬洭洯洰洴洶洷洸洺洿浀浂浄浉浌浐浕浖浗浘浛浝浟浡浢浤浥浧浨浫浬浭浰浱浲浳浵浶浹浺浻浽",4,"涃涄涆涇涊涋涍涏涐涒涖",4,"涜涢涥涬涭涰涱涳涴涶涷涹",5,"淁淂淃淈淉淊"],["9c40","淍淎淏淐淒淓淔淕淗淚淛淜淟淢淣淥淧淨淩淪淭淯淰淲淴淵淶淸淺淽",7,"渆渇済渉渋渏渒渓渕渘渙減渜渞渟渢渦渧渨渪測渮渰渱渳渵"],["9c80","渶渷渹渻",7,"湅",7,"湏湐湑湒湕湗湙湚湜湝湞湠",10,"湬湭湯",14,"満溁溂溄溇溈溊",4,"溑",6,"溙溚溛溝溞溠溡溣溤溦溨溩溫溬溭溮溰溳溵溸溹溼溾溿滀滃滄滅滆滈滉滊滌滍滎滐滒滖滘滙滛滜滝滣滧滪",5],["9d40","滰滱滲滳滵滶滷滸滺",7,"漃漄漅漇漈漊",4,"漐漑漒漖",9,"漡漢漣漥漦漧漨漬漮漰漲漴漵漷",6,"漿潀潁潂"],["9d80","潃潄潅潈潉潊潌潎",9,"潙潚潛潝潟潠潡潣潤潥潧",5,"潯潰潱潳潵潶潷潹潻潽",6,"澅澆澇澊澋澏",12,"澝澞澟澠澢",4,"澨",10,"澴澵澷澸澺",5,"濁濃",5,"濊",6,"濓",10,"濟濢濣濤濥"],["9e40","濦",7,"濰",32,"瀒",7,"瀜",6,"瀤",6],["9e80","瀫",9,"瀶瀷瀸瀺",17,"灍灎灐",13,"灟",11,"灮灱灲灳灴灷灹灺灻災炁炂炃炄炆炇炈炋炌炍炏炐炑炓炗炘炚炛炞",12,"炰炲炴炵炶為炾炿烄烅烆烇烉烋",12,"烚"],["9f40","烜烝烞烠烡烢烣烥烪烮烰",6,"烸烺烻烼烾",10,"焋",4,"焑焒焔焗焛",10,"焧",7,"焲焳焴"],["9f80","焵焷",13,"煆煇煈煉煋煍煏",12,"煝煟",4,"煥煩",4,"煯煰煱煴煵煶煷煹煻煼煾",5,"熅",4,"熋熌熍熎熐熑熒熓熕熖熗熚",4,"熡",6,"熩熪熫熭",5,"熴熶熷熸熺",8,"燄",9,"燏",4],["a040","燖",9,"燡燢燣燤燦燨",5,"燯",9,"燺",11,"爇",19],["a080","爛爜爞",9,"爩爫爭爮爯爲爳爴爺爼爾牀",6,"牉牊牋牎牏牐牑牓牔牕牗牘牚牜牞牠牣牤牥牨牪牫牬牭牰牱牳牴牶牷牸牻牼牽犂犃犅",4,"犌犎犐犑犓",11,"犠",11,"犮犱犲犳犵犺",6,"狅狆狇狉狊狋狌狏狑狓狔狕狖狘狚狛"],["a1a1","　、。·ˉˇ¨〃々—～‖…‘’“”〔〕〈",7,"〖〗【】±×÷∶∧∨∑∏∪∩∈∷√⊥∥∠⌒⊙∫∮≡≌≈∽∝≠≮≯≤≥∞∵∴♂♀°′″℃＄¤￠￡‰§№☆★○●◎◇◆□■△▲※→←↑↓〓"],["a2a1","ⅰ",9],["a2b1","⒈",19,"⑴",19,"①",9],["a2e5","㈠",9],["a2f1","Ⅰ",11],["a3a1","！＂＃￥％",88,"￣"],["a4a1","ぁ",82],["a5a1","ァ",85],["a6a1","Α",16,"Σ",6],["a6c1","α",16,"σ",6],["a6e0","︵︶︹︺︿﹀︽︾﹁﹂﹃﹄"],["a6ee","︻︼︷︸︱"],["a6f4","︳︴"],["a7a1","А",5,"ЁЖ",25],["a7d1","а",5,"ёж",25],["a840","ˊˋ˙–―‥‵℅℉↖↗↘↙∕∟∣≒≦≧⊿═",35,"▁",6],["a880","█",7,"▓▔▕▼▽◢◣◤◥☉⊕〒〝〞"],["a8a1","āáǎàēéěèīíǐìōóǒòūúǔùǖǘǚǜüêɑ"],["a8bd","ńň"],["a8c0","ɡ"],["a8c5","ㄅ",36],["a940","〡",8,"㊣㎎㎏㎜㎝㎞㎡㏄㏎㏑㏒㏕︰￢￤"],["a959","℡㈱"],["a95c","‐"],["a960","ー゛゜ヽヾ〆ゝゞ﹉",9,"﹔﹕﹖﹗﹙",8],["a980","﹢",4,"﹨﹩﹪﹫"],["a996","〇"],["a9a4","─",75],["aa40","狜狝狟狢",5,"狪狫狵狶狹狽狾狿猀猂猄",5,"猋猌猍猏猐猑猒猔猘猙猚猟猠猣猤猦猧猨猭猯猰猲猳猵猶猺猻猼猽獀",8],["aa80","獉獊獋獌獎獏獑獓獔獕獖獘",7,"獡",10,"獮獰獱"],["ab40","獲",11,"獿",4,"玅玆玈玊玌玍玏玐玒玓玔玕玗玘玙玚玜玝玞玠玡玣",5,"玪玬玭玱玴玵玶玸玹玼玽玾玿珁珃",4],["ab80","珋珌珎珒",6,"珚珛珜珝珟珡珢珣珤珦珨珪珫珬珮珯珰珱珳",4],["ac40","珸",10,"琄琇琈琋琌琍琎琑",8,"琜",5,"琣琤琧琩琫琭琯琱琲琷",4,"琽琾琿瑀瑂",11],["ac80","瑎",6,"瑖瑘瑝瑠",12,"瑮瑯瑱",4,"瑸瑹瑺"],["ad40","瑻瑼瑽瑿璂璄璅璆璈璉璊璌璍璏璑",10,"璝璟",7,"璪",15,"璻",12],["ad80","瓈",9,"瓓",8,"瓝瓟瓡瓥瓧",6,"瓰瓱瓲"],["ae40","瓳瓵瓸",6,"甀甁甂甃甅",7,"甎甐甒甔甕甖甗甛甝甞甠",4,"甦甧甪甮甴甶甹甼甽甿畁畂畃畄畆畇畉畊畍畐畑畒畓畕畖畗畘"],["ae80","畝",7,"畧畨畩畫",6,"畳畵當畷畺",4,"疀疁疂疄疅疇"],["af40","疈疉疊疌疍疎疐疓疕疘疛疜疞疢疦",4,"疭疶疷疺疻疿痀痁痆痋痌痎痏痐痑痓痗痙痚痜痝痟痠痡痥痩痬痭痮痯痲痳痵痶痷痸痺痻痽痾瘂瘄瘆瘇"],["af80","瘈瘉瘋瘍瘎瘏瘑瘒瘓瘔瘖瘚瘜瘝瘞瘡瘣瘧瘨瘬瘮瘯瘱瘲瘶瘷瘹瘺瘻瘽癁療癄"],["b040","癅",6,"癎",5,"癕癗",4,"癝癟癠癡癢癤",6,"癬癭癮癰",7,"癹発發癿皀皁皃皅皉皊皌皍皏皐皒皔皕皗皘皚皛"],["b080","皜",7,"皥",8,"皯皰皳皵",9,"盀盁盃啊阿埃挨哎唉哀皑癌蔼矮艾碍爱隘鞍氨安俺按暗岸胺案肮昂盎凹敖熬翱袄傲奥懊澳芭捌扒叭吧笆八疤巴拔跋靶把耙坝霸罢爸白柏百摆佰败拜稗斑班搬扳般颁板版扮拌伴瓣半办绊邦帮梆榜膀绑棒磅蚌镑傍谤苞胞包褒剥"],["b140","盄盇盉盋盌盓盕盙盚盜盝盞盠",4,"盦",7,"盰盳盵盶盷盺盻盽盿眀眂眃眅眆眊県眎",10,"眛眜眝眞眡眣眤眥眧眪眫"],["b180","眬眮眰",4,"眹眻眽眾眿睂睄睅睆睈",7,"睒",7,"睜薄雹保堡饱宝抱报暴豹鲍爆杯碑悲卑北辈背贝钡倍狈备惫焙被奔苯本笨崩绷甭泵蹦迸逼鼻比鄙笔彼碧蓖蔽毕毙毖币庇痹闭敝弊必辟壁臂避陛鞭边编贬扁便变卞辨辩辫遍标彪膘表鳖憋别瘪彬斌濒滨宾摈兵冰柄丙秉饼炳"],["b240","睝睞睟睠睤睧睩睪睭",11,"睺睻睼瞁瞂瞃瞆",5,"瞏瞐瞓",11,"瞡瞣瞤瞦瞨瞫瞭瞮瞯瞱瞲瞴瞶",4],["b280","瞼瞾矀",12,"矎",8,"矘矙矚矝",4,"矤病并玻菠播拨钵波博勃搏铂箔伯帛舶脖膊渤泊驳捕卜哺补埠不布步簿部怖擦猜裁材才财睬踩采彩菜蔡餐参蚕残惭惨灿苍舱仓沧藏操糙槽曹草厕策侧册测层蹭插叉茬茶查碴搽察岔差诧拆柴豺搀掺蝉馋谗缠铲产阐颤昌猖"],["b340","矦矨矪矯矰矱矲矴矵矷矹矺矻矼砃",5,"砊砋砎砏砐砓砕砙砛砞砠砡砢砤砨砪砫砮砯砱砲砳砵砶砽砿硁硂硃硄硆硈硉硊硋硍硏硑硓硔硘硙硚"],["b380","硛硜硞",11,"硯",7,"硸硹硺硻硽",6,"场尝常长偿肠厂敞畅唱倡超抄钞朝嘲潮巢吵炒车扯撤掣彻澈郴臣辰尘晨忱沉陈趁衬撑称城橙成呈乘程惩澄诚承逞骋秤吃痴持匙池迟弛驰耻齿侈尺赤翅斥炽充冲虫崇宠抽酬畴踌稠愁筹仇绸瞅丑臭初出橱厨躇锄雏滁除楚"],["b440","碄碅碆碈碊碋碏碐碒碔碕碖碙碝碞碠碢碤碦碨",7,"碵碶碷碸確碻碼碽碿磀磂磃磄磆磇磈磌磍磎磏磑磒磓磖磗磘磚",9],["b480","磤磥磦磧磩磪磫磭",4,"磳磵磶磸磹磻",5,"礂礃礄礆",6,"础储矗搐触处揣川穿椽传船喘串疮窗幢床闯创吹炊捶锤垂春椿醇唇淳纯蠢戳绰疵茨磁雌辞慈瓷词此刺赐次聪葱囱匆从丛凑粗醋簇促蹿篡窜摧崔催脆瘁粹淬翠村存寸磋撮搓措挫错搭达答瘩打大呆歹傣戴带殆代贷袋待逮"],["b540","礍",5,"礔",9,"礟",4,"礥",14,"礵",4,"礽礿祂祃祄祅祇祊",8,"祔祕祘祙祡祣"],["b580","祤祦祩祪祫祬祮祰",6,"祹祻",4,"禂禃禆禇禈禉禋禌禍禎禐禑禒怠耽担丹单郸掸胆旦氮但惮淡诞弹蛋当挡党荡档刀捣蹈倒岛祷导到稻悼道盗德得的蹬灯登等瞪凳邓堤低滴迪敌笛狄涤翟嫡抵底地蒂第帝弟递缔颠掂滇碘点典靛垫电佃甸店惦奠淀殿碉叼雕凋刁掉吊钓调跌爹碟蝶迭谍叠"],["b640","禓",6,"禛",11,"禨",10,"禴",4,"禼禿秂秄秅秇秈秊秌秎秏秐秓秔秖秗秙",5,"秠秡秢秥秨秪"],["b680","秬秮秱",6,"秹秺秼秾秿稁稄稅稇稈稉稊稌稏",4,"稕稖稘稙稛稜丁盯叮钉顶鼎锭定订丢东冬董懂动栋侗恫冻洞兜抖斗陡豆逗痘都督毒犊独读堵睹赌杜镀肚度渡妒端短锻段断缎堆兑队对墩吨蹲敦顿囤钝盾遁掇哆多夺垛躲朵跺舵剁惰堕蛾峨鹅俄额讹娥恶厄扼遏鄂饿恩而儿耳尔饵洱二"],["b740","稝稟稡稢稤",14,"稴稵稶稸稺稾穀",5,"穇",9,"穒",4,"穘",16],["b780","穩",6,"穱穲穳穵穻穼穽穾窂窅窇窉窊窋窌窎窏窐窓窔窙窚窛窞窡窢贰发罚筏伐乏阀法珐藩帆番翻樊矾钒繁凡烦反返范贩犯饭泛坊芳方肪房防妨仿访纺放菲非啡飞肥匪诽吠肺废沸费芬酚吩氛分纷坟焚汾粉奋份忿愤粪丰封枫蜂峰锋风疯烽逢冯缝讽奉凤佛否夫敷肤孵扶拂辐幅氟符伏俘服"],["b840","窣窤窧窩窪窫窮",4,"窴",10,"竀",10,"竌",9,"竗竘竚竛竜竝竡竢竤竧",5,"竮竰竱竲竳"],["b880","竴",4,"竻竼竾笀笁笂笅笇笉笌笍笎笐笒笓笖笗笘笚笜笝笟笡笢笣笧笩笭浮涪福袱弗甫抚辅俯釜斧脯腑府腐赴副覆赋复傅付阜父腹负富讣附妇缚咐噶嘎该改概钙盖溉干甘杆柑竿肝赶感秆敢赣冈刚钢缸肛纲岗港杠篙皋高膏羔糕搞镐稿告哥歌搁戈鸽胳疙割革葛格蛤阁隔铬个各给根跟耕更庚羹"],["b940","笯笰笲笴笵笶笷笹笻笽笿",5,"筆筈筊筍筎筓筕筗筙筜筞筟筡筣",10,"筯筰筳筴筶筸筺筼筽筿箁箂箃箄箆",6,"箎箏"],["b980","箑箒箓箖箘箙箚箛箞箟箠箣箤箥箮箯箰箲箳箵箶箷箹",7,"篂篃範埂耿梗工攻功恭龚供躬公宫弓巩汞拱贡共钩勾沟苟狗垢构购够辜菇咕箍估沽孤姑鼓古蛊骨谷股故顾固雇刮瓜剐寡挂褂乖拐怪棺关官冠观管馆罐惯灌贯光广逛瑰规圭硅归龟闺轨鬼诡癸桂柜跪贵刽辊滚棍锅郭国果裹过哈"],["ba40","篅篈築篊篋篍篎篏篐篒篔",4,"篛篜篞篟篠篢篣篤篧篨篩篫篬篭篯篰篲",4,"篸篹篺篻篽篿",7,"簈簉簊簍簎簐",5,"簗簘簙"],["ba80","簚",4,"簠",5,"簨簩簫",12,"簹",5,"籂骸孩海氦亥害骇酣憨邯韩含涵寒函喊罕翰撼捍旱憾悍焊汗汉夯杭航壕嚎豪毫郝好耗号浩呵喝荷菏核禾和何合盒貉阂河涸赫褐鹤贺嘿黑痕很狠恨哼亨横衡恒轰哄烘虹鸿洪宏弘红喉侯猴吼厚候后呼乎忽瑚壶葫胡蝴狐糊湖"],["bb40","籃",9,"籎",36,"籵",5,"籾",9],["bb80","粈粊",6,"粓粔粖粙粚粛粠粡粣粦粧粨粩粫粬粭粯粰粴",4,"粺粻弧虎唬护互沪户花哗华猾滑画划化话槐徊怀淮坏欢环桓还缓换患唤痪豢焕涣宦幻荒慌黄磺蝗簧皇凰惶煌晃幌恍谎灰挥辉徽恢蛔回毁悔慧卉惠晦贿秽会烩汇讳诲绘荤昏婚魂浑混豁活伙火获或惑霍货祸击圾基机畸稽积箕"],["bc40","粿糀糂糃糄糆糉糋糎",6,"糘糚糛糝糞糡",6,"糩",5,"糰",7,"糹糺糼",13,"紋",5],["bc80","紑",14,"紡紣紤紥紦紨紩紪紬紭紮細",6,"肌饥迹激讥鸡姬绩缉吉极棘辑籍集及急疾汲即嫉级挤几脊己蓟技冀季伎祭剂悸济寄寂计记既忌际妓继纪嘉枷夹佳家加荚颊贾甲钾假稼价架驾嫁歼监坚尖笺间煎兼肩艰奸缄茧检柬碱硷拣捡简俭剪减荐槛鉴践贱见键箭件"],["bd40","紷",54,"絯",7],["bd80","絸",32,"健舰剑饯渐溅涧建僵姜将浆江疆蒋桨奖讲匠酱降蕉椒礁焦胶交郊浇骄娇嚼搅铰矫侥脚狡角饺缴绞剿教酵轿较叫窖揭接皆秸街阶截劫节桔杰捷睫竭洁结解姐戒藉芥界借介疥诫届巾筋斤金今津襟紧锦仅谨进靳晋禁近烬浸"],["be40","継",12,"綧",6,"綯",42],["be80","線",32,"尽劲荆兢茎睛晶鲸京惊精粳经井警景颈静境敬镜径痉靖竟竞净炯窘揪究纠玖韭久灸九酒厩救旧臼舅咎就疚鞠拘狙疽居驹菊局咀矩举沮聚拒据巨具距踞锯俱句惧炬剧捐鹃娟倦眷卷绢撅攫抉掘倔爵觉决诀绝均菌钧军君峻"],["bf40","緻",62],["bf80","縺縼",4,"繂",4,"繈",21,"俊竣浚郡骏喀咖卡咯开揩楷凯慨刊堪勘坎砍看康慷糠扛抗亢炕考拷烤靠坷苛柯棵磕颗科壳咳可渴克刻客课肯啃垦恳坑吭空恐孔控抠口扣寇枯哭窟苦酷库裤夸垮挎跨胯块筷侩快宽款匡筐狂框矿眶旷况亏盔岿窥葵奎魁傀"],["c040","繞",35,"纃",23,"纜纝纞"],["c080","纮纴纻纼绖绤绬绹缊缐缞缷缹缻",6,"罃罆",9,"罒罓馈愧溃坤昆捆困括扩廓阔垃拉喇蜡腊辣啦莱来赖蓝婪栏拦篮阑兰澜谰揽览懒缆烂滥琅榔狼廊郎朗浪捞劳牢老佬姥酪烙涝勒乐雷镭蕾磊累儡垒擂肋类泪棱楞冷厘梨犁黎篱狸离漓理李里鲤礼莉荔吏栗丽厉励砾历利傈例俐"],["c140","罖罙罛罜罝罞罠罣",4,"罫罬罭罯罰罳罵罶罷罸罺罻罼罽罿羀羂",7,"羋羍羏",4,"羕",4,"羛羜羠羢羣羥羦羨",6,"羱"],["c180","羳",4,"羺羻羾翀翂翃翄翆翇翈翉翋翍翏",4,"翖翗翙",5,"翢翣痢立粒沥隶力璃哩俩联莲连镰廉怜涟帘敛脸链恋炼练粮凉梁粱良两辆量晾亮谅撩聊僚疗燎寥辽潦了撂镣廖料列裂烈劣猎琳林磷霖临邻鳞淋凛赁吝拎玲菱零龄铃伶羚凌灵陵岭领另令溜琉榴硫馏留刘瘤流柳六龙聋咙笼窿"],["c240","翤翧翨翪翫翬翭翯翲翴",6,"翽翾翿耂耇耈耉耊耎耏耑耓耚耛耝耞耟耡耣耤耫",5,"耲耴耹耺耼耾聀聁聄聅聇聈聉聎聏聐聑聓聕聖聗"],["c280","聙聛",13,"聫",5,"聲",11,"隆垄拢陇楼娄搂篓漏陋芦卢颅庐炉掳卤虏鲁麓碌露路赂鹿潞禄录陆戮驴吕铝侣旅履屡缕虑氯律率滤绿峦挛孪滦卵乱掠略抡轮伦仑沦纶论萝螺罗逻锣箩骡裸落洛骆络妈麻玛码蚂马骂嘛吗埋买麦卖迈脉瞒馒蛮满蔓曼慢漫"],["c340","聾肁肂肅肈肊肍",5,"肔肕肗肙肞肣肦肧肨肬肰肳肵肶肸肹肻胅胇",4,"胏",6,"胘胟胠胢胣胦胮胵胷胹胻胾胿脀脁脃脄脅脇脈脋"],["c380","脌脕脗脙脛脜脝脟",12,"脭脮脰脳脴脵脷脹",4,"脿谩芒茫盲氓忙莽猫茅锚毛矛铆卯茂冒帽貌贸么玫枚梅酶霉煤没眉媒镁每美昧寐妹媚门闷们萌蒙檬盟锰猛梦孟眯醚靡糜迷谜弥米秘觅泌蜜密幂棉眠绵冕免勉娩缅面苗描瞄藐秒渺庙妙蔑灭民抿皿敏悯闽明螟鸣铭名命谬摸"],["c440","腀",5,"腇腉腍腎腏腒腖腗腘腛",4,"腡腢腣腤腦腨腪腫腬腯腲腳腵腶腷腸膁膃",4,"膉膋膌膍膎膐膒",5,"膙膚膞",4,"膤膥"],["c480","膧膩膫",7,"膴",5,"膼膽膾膿臄臅臇臈臉臋臍",6,"摹蘑模膜磨摩魔抹末莫墨默沫漠寞陌谋牟某拇牡亩姆母墓暮幕募慕木目睦牧穆拿哪呐钠那娜纳氖乃奶耐奈南男难囊挠脑恼闹淖呢馁内嫩能妮霓倪泥尼拟你匿腻逆溺蔫拈年碾撵捻念娘酿鸟尿捏聂孽啮镊镍涅您柠狞凝宁"],["c540","臔",14,"臤臥臦臨臩臫臮",4,"臵",5,"臽臿舃與",4,"舎舏舑舓舕",5,"舝舠舤舥舦舧舩舮舲舺舼舽舿"],["c580","艀艁艂艃艅艆艈艊艌艍艎艐",7,"艙艛艜艝艞艠",7,"艩拧泞牛扭钮纽脓浓农弄奴努怒女暖虐疟挪懦糯诺哦欧鸥殴藕呕偶沤啪趴爬帕怕琶拍排牌徘湃派攀潘盘磐盼畔判叛乓庞旁耪胖抛咆刨炮袍跑泡呸胚培裴赔陪配佩沛喷盆砰抨烹澎彭蓬棚硼篷膨朋鹏捧碰坯砒霹批披劈琵毗"],["c640","艪艫艬艭艱艵艶艷艸艻艼芀芁芃芅芆芇芉芌芐芓芔芕芖芚芛芞芠芢芣芧芲芵芶芺芻芼芿苀苂苃苅苆苉苐苖苙苚苝苢苧苨苩苪苬苭苮苰苲苳苵苶苸"],["c680","苺苼",4,"茊茋茍茐茒茓茖茘茙茝",9,"茩茪茮茰茲茷茻茽啤脾疲皮匹痞僻屁譬篇偏片骗飘漂瓢票撇瞥拼频贫品聘乒坪苹萍平凭瓶评屏坡泼颇婆破魄迫粕剖扑铺仆莆葡菩蒲埔朴圃普浦谱曝瀑期欺栖戚妻七凄漆柒沏其棋奇歧畦崎脐齐旗祈祁骑起岂乞企启契砌器气迄弃汽泣讫掐"],["c740","茾茿荁荂荄荅荈荊",4,"荓荕",4,"荝荢荰",6,"荹荺荾",6,"莇莈莊莋莌莍莏莐莑莔莕莖莗莙莚莝莟莡",6,"莬莭莮"],["c780","莯莵莻莾莿菂菃菄菆菈菉菋菍菎菐菑菒菓菕菗菙菚菛菞菢菣菤菦菧菨菫菬菭恰洽牵扦钎铅千迁签仟谦乾黔钱钳前潜遣浅谴堑嵌欠歉枪呛腔羌墙蔷强抢橇锹敲悄桥瞧乔侨巧鞘撬翘峭俏窍切茄且怯窃钦侵亲秦琴勤芹擒禽寝沁青轻氢倾卿清擎晴氰情顷请庆琼穷秋丘邱球求囚酋泅趋区蛆曲躯屈驱渠"],["c840","菮華菳",4,"菺菻菼菾菿萀萂萅萇萈萉萊萐萒",5,"萙萚萛萞",5,"萩",7,"萲",5,"萹萺萻萾",7,"葇葈葉"],["c880","葊",6,"葒",4,"葘葝葞葟葠葢葤",4,"葪葮葯葰葲葴葷葹葻葼取娶龋趣去圈颧权醛泉全痊拳犬券劝缺炔瘸却鹊榷确雀裙群然燃冉染瓤壤攘嚷让饶扰绕惹热壬仁人忍韧任认刃妊纫扔仍日戎茸蓉荣融熔溶容绒冗揉柔肉茹蠕儒孺如辱乳汝入褥软阮蕊瑞锐闰润若弱撒洒萨腮鳃塞赛三叁"],["c940","葽",4,"蒃蒄蒅蒆蒊蒍蒏",7,"蒘蒚蒛蒝蒞蒟蒠蒢",12,"蒰蒱蒳蒵蒶蒷蒻蒼蒾蓀蓂蓃蓅蓆蓇蓈蓋蓌蓎蓏蓒蓔蓕蓗"],["c980","蓘",4,"蓞蓡蓢蓤蓧",4,"蓭蓮蓯蓱",10,"蓽蓾蔀蔁蔂伞散桑嗓丧搔骚扫嫂瑟色涩森僧莎砂杀刹沙纱傻啥煞筛晒珊苫杉山删煽衫闪陕擅赡膳善汕扇缮墒伤商赏晌上尚裳梢捎稍烧芍勺韶少哨邵绍奢赊蛇舌舍赦摄射慑涉社设砷申呻伸身深娠绅神沈审婶甚肾慎渗声生甥牲升绳"],["ca40","蔃",8,"蔍蔎蔏蔐蔒蔔蔕蔖蔘蔙蔛蔜蔝蔞蔠蔢",8,"蔭",9,"蔾",4,"蕄蕅蕆蕇蕋",10],["ca80","蕗蕘蕚蕛蕜蕝蕟",4,"蕥蕦蕧蕩",8,"蕳蕵蕶蕷蕸蕼蕽蕿薀薁省盛剩胜圣师失狮施湿诗尸虱十石拾时什食蚀实识史矢使屎驶始式示士世柿事拭誓逝势是嗜噬适仕侍释饰氏市恃室视试收手首守寿授售受瘦兽蔬枢梳殊抒输叔舒淑疏书赎孰熟薯暑曙署蜀黍鼠属术述树束戍竖墅庶数漱"],["cb40","薂薃薆薈",6,"薐",10,"薝",6,"薥薦薧薩薫薬薭薱",5,"薸薺",6,"藂",6,"藊",4,"藑藒"],["cb80","藔藖",5,"藝",6,"藥藦藧藨藪",14,"恕刷耍摔衰甩帅栓拴霜双爽谁水睡税吮瞬顺舜说硕朔烁斯撕嘶思私司丝死肆寺嗣四伺似饲巳松耸怂颂送宋讼诵搜艘擞嗽苏酥俗素速粟僳塑溯宿诉肃酸蒜算虽隋随绥髓碎岁穗遂隧祟孙损笋蓑梭唆缩琐索锁所塌他它她塔"],["cc40","藹藺藼藽藾蘀",4,"蘆",10,"蘒蘓蘔蘕蘗",15,"蘨蘪",13,"蘹蘺蘻蘽蘾蘿虀"],["cc80","虁",11,"虒虓處",4,"虛虜虝號虠虡虣",7,"獭挞蹋踏胎苔抬台泰酞太态汰坍摊贪瘫滩坛檀痰潭谭谈坦毯袒碳探叹炭汤塘搪堂棠膛唐糖倘躺淌趟烫掏涛滔绦萄桃逃淘陶讨套特藤腾疼誊梯剔踢锑提题蹄啼体替嚏惕涕剃屉天添填田甜恬舔腆挑条迢眺跳贴铁帖厅听烃"],["cd40","虭虯虰虲",6,"蚃",6,"蚎",4,"蚔蚖",5,"蚞",4,"蚥蚦蚫蚭蚮蚲蚳蚷蚸蚹蚻",4,"蛁蛂蛃蛅蛈蛌蛍蛒蛓蛕蛖蛗蛚蛜"],["cd80","蛝蛠蛡蛢蛣蛥蛦蛧蛨蛪蛫蛬蛯蛵蛶蛷蛺蛻蛼蛽蛿蜁蜄蜅蜆蜋蜌蜎蜏蜐蜑蜔蜖汀廷停亭庭挺艇通桐酮瞳同铜彤童桶捅筒统痛偷投头透凸秃突图徒途涂屠土吐兔湍团推颓腿蜕褪退吞屯臀拖托脱鸵陀驮驼椭妥拓唾挖哇蛙洼娃瓦袜歪外豌弯湾玩顽丸烷完碗挽晚皖惋宛婉万腕汪王亡枉网往旺望忘妄威"],["ce40","蜙蜛蜝蜟蜠蜤蜦蜧蜨蜪蜫蜬蜭蜯蜰蜲蜳蜵蜶蜸蜹蜺蜼蜽蝀",6,"蝊蝋蝍蝏蝐蝑蝒蝔蝕蝖蝘蝚",5,"蝡蝢蝦",7,"蝯蝱蝲蝳蝵"],["ce80","蝷蝸蝹蝺蝿螀螁螄螆螇螉螊螌螎",4,"螔螕螖螘",6,"螠",4,"巍微危韦违桅围唯惟为潍维苇萎委伟伪尾纬未蔚味畏胃喂魏位渭谓尉慰卫瘟温蚊文闻纹吻稳紊问嗡翁瓮挝蜗涡窝我斡卧握沃巫呜钨乌污诬屋无芜梧吾吴毋武五捂午舞伍侮坞戊雾晤物勿务悟误昔熙析西硒矽晰嘻吸锡牺"],["cf40","螥螦螧螩螪螮螰螱螲螴螶螷螸螹螻螼螾螿蟁",4,"蟇蟈蟉蟌",4,"蟔",6,"蟜蟝蟞蟟蟡蟢蟣蟤蟦蟧蟨蟩蟫蟬蟭蟯",9],["cf80","蟺蟻蟼蟽蟿蠀蠁蠂蠄",5,"蠋",7,"蠔蠗蠘蠙蠚蠜",4,"蠣稀息希悉膝夕惜熄烯溪汐犀檄袭席习媳喜铣洗系隙戏细瞎虾匣霞辖暇峡侠狭下厦夏吓掀锨先仙鲜纤咸贤衔舷闲涎弦嫌显险现献县腺馅羡宪陷限线相厢镶香箱襄湘乡翔祥详想响享项巷橡像向象萧硝霄削哮嚣销消宵淆晓"],["d040","蠤",13,"蠳",5,"蠺蠻蠽蠾蠿衁衂衃衆",5,"衎",5,"衕衖衘衚",6,"衦衧衪衭衯衱衳衴衵衶衸衹衺"],["d080","衻衼袀袃袆袇袉袊袌袎袏袐袑袓袔袕袗",4,"袝",4,"袣袥",5,"小孝校肖啸笑效楔些歇蝎鞋协挟携邪斜胁谐写械卸蟹懈泄泻谢屑薪芯锌欣辛新忻心信衅星腥猩惺兴刑型形邢行醒幸杏性姓兄凶胸匈汹雄熊休修羞朽嗅锈秀袖绣墟戌需虚嘘须徐许蓄酗叙旭序畜恤絮婿绪续轩喧宣悬旋玄"],["d140","袬袮袯袰袲",4,"袸袹袺袻袽袾袿裀裃裄裇裈裊裋裌裍裏裐裑裓裖裗裚",4,"裠裡裦裧裩",6,"裲裵裶裷裺裻製裿褀褁褃",5],["d180","褉褋",4,"褑褔",4,"褜",4,"褢褣褤褦褧褨褩褬褭褮褯褱褲褳褵褷选癣眩绚靴薛学穴雪血勋熏循旬询寻驯巡殉汛训讯逊迅压押鸦鸭呀丫芽牙蚜崖衙涯雅哑亚讶焉咽阉烟淹盐严研蜒岩延言颜阎炎沿奄掩眼衍演艳堰燕厌砚雁唁彦焰宴谚验殃央鸯秧杨扬佯疡羊洋阳氧仰痒养样漾邀腰妖瑶"],["d240","褸",8,"襂襃襅",24,"襠",5,"襧",19,"襼"],["d280","襽襾覀覂覄覅覇",26,"摇尧遥窑谣姚咬舀药要耀椰噎耶爷野冶也页掖业叶曳腋夜液一壹医揖铱依伊衣颐夷遗移仪胰疑沂宜姨彝椅蚁倚已乙矣以艺抑易邑屹亿役臆逸肄疫亦裔意毅忆义益溢诣议谊译异翼翌绎茵荫因殷音阴姻吟银淫寅饮尹引隐"],["d340","覢",30,"觃觍觓觔觕觗觘觙觛觝觟觠觡觢觤觧觨觩觪觬觭觮觰觱觲觴",6],["d380","觻",4,"訁",5,"計",21,"印英樱婴鹰应缨莹萤营荧蝇迎赢盈影颖硬映哟拥佣臃痈庸雍踊蛹咏泳涌永恿勇用幽优悠忧尤由邮铀犹油游酉有友右佑釉诱又幼迂淤于盂榆虞愚舆余俞逾鱼愉渝渔隅予娱雨与屿禹宇语羽玉域芋郁吁遇喻峪御愈欲狱育誉"],["d440","訞",31,"訿",8,"詉",21],["d480","詟",25,"詺",6,"浴寓裕预豫驭鸳渊冤元垣袁原援辕园员圆猿源缘远苑愿怨院曰约越跃钥岳粤月悦阅耘云郧匀陨允运蕴酝晕韵孕匝砸杂栽哉灾宰载再在咱攒暂赞赃脏葬遭糟凿藻枣早澡蚤躁噪造皂灶燥责择则泽贼怎增憎曾赠扎喳渣札轧"],["d540","誁",7,"誋",7,"誔",46],["d580","諃",32,"铡闸眨栅榨咋乍炸诈摘斋宅窄债寨瞻毡詹粘沾盏斩辗崭展蘸栈占战站湛绽樟章彰漳张掌涨杖丈帐账仗胀瘴障招昭找沼赵照罩兆肇召遮折哲蛰辙者锗蔗这浙珍斟真甄砧臻贞针侦枕疹诊震振镇阵蒸挣睁征狰争怔整拯正政"],["d640","諤",34,"謈",27],["d680","謤謥謧",30,"帧症郑证芝枝支吱蜘知肢脂汁之织职直植殖执值侄址指止趾只旨纸志挚掷至致置帜峙制智秩稚质炙痔滞治窒中盅忠钟衷终种肿重仲众舟周州洲诌粥轴肘帚咒皱宙昼骤珠株蛛朱猪诸诛逐竹烛煮拄瞩嘱主著柱助蛀贮铸筑"],["d740","譆",31,"譧",4,"譭",25],["d780","讇",24,"讬讱讻诇诐诪谉谞住注祝驻抓爪拽专砖转撰赚篆桩庄装妆撞壮状椎锥追赘坠缀谆准捉拙卓桌琢茁酌啄着灼浊兹咨资姿滋淄孜紫仔籽滓子自渍字鬃棕踪宗综总纵邹走奏揍租足卒族祖诅阻组钻纂嘴醉最罪尊遵昨左佐柞做作坐座"],["d840","谸",8,"豂豃豄豅豈豊豋豍",7,"豖豗豘豙豛",5,"豣",6,"豬",6,"豴豵豶豷豻",6,"貃貄貆貇"],["d880","貈貋貍",6,"貕貖貗貙",20,"亍丌兀丐廿卅丕亘丞鬲孬噩丨禺丿匕乇夭爻卮氐囟胤馗毓睾鼗丶亟鼐乜乩亓芈孛啬嘏仄厍厝厣厥厮靥赝匚叵匦匮匾赜卦卣刂刈刎刭刳刿剀剌剞剡剜蒯剽劂劁劐劓冂罔亻仃仉仂仨仡仫仞伛仳伢佤仵伥伧伉伫佞佧攸佚佝"],["d940","貮",62],["d980","賭",32,"佟佗伲伽佶佴侑侉侃侏佾佻侪佼侬侔俦俨俪俅俚俣俜俑俟俸倩偌俳倬倏倮倭俾倜倌倥倨偾偃偕偈偎偬偻傥傧傩傺僖儆僭僬僦僮儇儋仝氽佘佥俎龠汆籴兮巽黉馘冁夔勹匍訇匐凫夙兕亠兖亳衮袤亵脔裒禀嬴蠃羸冫冱冽冼"],["da40","贎",14,"贠赑赒赗赟赥赨赩赪赬赮赯赱赲赸",8,"趂趃趆趇趈趉趌",4,"趒趓趕",9,"趠趡"],["da80","趢趤",12,"趲趶趷趹趻趽跀跁跂跅跇跈跉跊跍跐跒跓跔凇冖冢冥讠讦讧讪讴讵讷诂诃诋诏诎诒诓诔诖诘诙诜诟诠诤诨诩诮诰诳诶诹诼诿谀谂谄谇谌谏谑谒谔谕谖谙谛谘谝谟谠谡谥谧谪谫谮谯谲谳谵谶卩卺阝阢阡阱阪阽阼陂陉陔陟陧陬陲陴隈隍隗隰邗邛邝邙邬邡邴邳邶邺"],["db40","跕跘跙跜跠跡跢跥跦跧跩跭跮跰跱跲跴跶跼跾",6,"踆踇踈踋踍踎踐踑踒踓踕",7,"踠踡踤",4,"踫踭踰踲踳踴踶踷踸踻踼踾"],["db80","踿蹃蹅蹆蹌",4,"蹓",5,"蹚",11,"蹧蹨蹪蹫蹮蹱邸邰郏郅邾郐郄郇郓郦郢郜郗郛郫郯郾鄄鄢鄞鄣鄱鄯鄹酃酆刍奂劢劬劭劾哿勐勖勰叟燮矍廴凵凼鬯厶弁畚巯坌垩垡塾墼壅壑圩圬圪圳圹圮圯坜圻坂坩垅坫垆坼坻坨坭坶坳垭垤垌垲埏垧垴垓垠埕埘埚埙埒垸埴埯埸埤埝"],["dc40","蹳蹵蹷",4,"蹽蹾躀躂躃躄躆躈",6,"躑躒躓躕",6,"躝躟",11,"躭躮躰躱躳",6,"躻",7],["dc80","軃",10,"軏",21,"堋堍埽埭堀堞堙塄堠塥塬墁墉墚墀馨鼙懿艹艽艿芏芊芨芄芎芑芗芙芫芸芾芰苈苊苣芘芷芮苋苌苁芩芴芡芪芟苄苎芤苡茉苷苤茏茇苜苴苒苘茌苻苓茑茚茆茔茕苠苕茜荑荛荜茈莒茼茴茱莛荞茯荏荇荃荟荀茗荠茭茺茳荦荥"],["dd40","軥",62],["dd80","輤",32,"荨茛荩荬荪荭荮莰荸莳莴莠莪莓莜莅荼莶莩荽莸荻莘莞莨莺莼菁萁菥菘堇萘萋菝菽菖萜萸萑萆菔菟萏萃菸菹菪菅菀萦菰菡葜葑葚葙葳蒇蒈葺蒉葸萼葆葩葶蒌蒎萱葭蓁蓍蓐蓦蒽蓓蓊蒿蒺蓠蒡蒹蒴蒗蓥蓣蔌甍蔸蓰蔹蔟蔺"],["de40","轅",32,"轪辀辌辒辝辠辡辢辤辥辦辧辪辬辭辮辯農辳辴辵辷辸辺辻込辿迀迃迆"],["de80","迉",4,"迏迒迖迗迚迠迡迣迧迬迯迱迲迴迵迶迺迻迼迾迿逇逈逌逎逓逕逘蕖蔻蓿蓼蕙蕈蕨蕤蕞蕺瞢蕃蕲蕻薤薨薇薏蕹薮薜薅薹薷薰藓藁藜藿蘧蘅蘩蘖蘼廾弈夼奁耷奕奚奘匏尢尥尬尴扌扪抟抻拊拚拗拮挢拶挹捋捃掭揶捱捺掎掴捭掬掊捩掮掼揲揸揠揿揄揞揎摒揆掾摅摁搋搛搠搌搦搡摞撄摭撖"],["df40","這逜連逤逥逧",5,"逰",4,"逷逹逺逽逿遀遃遅遆遈",4,"過達違遖遙遚遜",5,"遤遦遧適遪遫遬遯",4,"遶",6,"遾邁"],["df80","還邅邆邇邉邊邌",4,"邒邔邖邘邚邜邞邟邠邤邥邧邨邩邫邭邲邷邼邽邿郀摺撷撸撙撺擀擐擗擤擢攉攥攮弋忒甙弑卟叱叽叩叨叻吒吖吆呋呒呓呔呖呃吡呗呙吣吲咂咔呷呱呤咚咛咄呶呦咝哐咭哂咴哒咧咦哓哔呲咣哕咻咿哌哙哚哜咩咪咤哝哏哞唛哧唠哽唔哳唢唣唏唑唧唪啧喏喵啉啭啁啕唿啐唼"],["e040","郂郃郆郈郉郋郌郍郒郔郕郖郘郙郚郞郟郠郣郤郥郩郪郬郮郰郱郲郳郵郶郷郹郺郻郼郿鄀鄁鄃鄅",19,"鄚鄛鄜"],["e080","鄝鄟鄠鄡鄤",10,"鄰鄲",6,"鄺",8,"酄唷啖啵啶啷唳唰啜喋嗒喃喱喹喈喁喟啾嗖喑啻嗟喽喾喔喙嗪嗷嗉嘟嗑嗫嗬嗔嗦嗝嗄嗯嗥嗲嗳嗌嗍嗨嗵嗤辔嘞嘈嘌嘁嘤嘣嗾嘀嘧嘭噘嘹噗嘬噍噢噙噜噌噔嚆噤噱噫噻噼嚅嚓嚯囔囗囝囡囵囫囹囿圄圊圉圜帏帙帔帑帱帻帼"],["e140","酅酇酈酑酓酔酕酖酘酙酛酜酟酠酦酧酨酫酭酳酺酻酼醀",4,"醆醈醊醎醏醓",6,"醜",5,"醤",5,"醫醬醰醱醲醳醶醷醸醹醻"],["e180","醼",10,"釈釋釐釒",9,"針",8,"帷幄幔幛幞幡岌屺岍岐岖岈岘岙岑岚岜岵岢岽岬岫岱岣峁岷峄峒峤峋峥崂崃崧崦崮崤崞崆崛嵘崾崴崽嵬嵛嵯嵝嵫嵋嵊嵩嵴嶂嶙嶝豳嶷巅彳彷徂徇徉後徕徙徜徨徭徵徼衢彡犭犰犴犷犸狃狁狎狍狒狨狯狩狲狴狷猁狳猃狺"],["e240","釦",62],["e280","鈥",32,"狻猗猓猡猊猞猝猕猢猹猥猬猸猱獐獍獗獠獬獯獾舛夥飧夤夂饣饧",5,"饴饷饽馀馄馇馊馍馐馑馓馔馕庀庑庋庖庥庠庹庵庾庳赓廒廑廛廨廪膺忄忉忖忏怃忮怄忡忤忾怅怆忪忭忸怙怵怦怛怏怍怩怫怊怿怡恸恹恻恺恂"],["e340","鉆",45,"鉵",16],["e380","銆",7,"銏",24,"恪恽悖悚悭悝悃悒悌悛惬悻悱惝惘惆惚悴愠愦愕愣惴愀愎愫慊慵憬憔憧憷懔懵忝隳闩闫闱闳闵闶闼闾阃阄阆阈阊阋阌阍阏阒阕阖阗阙阚丬爿戕氵汔汜汊沣沅沐沔沌汨汩汴汶沆沩泐泔沭泷泸泱泗沲泠泖泺泫泮沱泓泯泾"],["e440","銨",5,"銯",24,"鋉",31],["e480","鋩",32,"洹洧洌浃浈洇洄洙洎洫浍洮洵洚浏浒浔洳涑浯涞涠浞涓涔浜浠浼浣渚淇淅淞渎涿淠渑淦淝淙渖涫渌涮渫湮湎湫溲湟溆湓湔渲渥湄滟溱溘滠漭滢溥溧溽溻溷滗溴滏溏滂溟潢潆潇漤漕滹漯漶潋潴漪漉漩澉澍澌潸潲潼潺濑"],["e540","錊",51,"錿",10],["e580","鍊",31,"鍫濉澧澹澶濂濡濮濞濠濯瀚瀣瀛瀹瀵灏灞宀宄宕宓宥宸甯骞搴寤寮褰寰蹇謇辶迓迕迥迮迤迩迦迳迨逅逄逋逦逑逍逖逡逵逶逭逯遄遑遒遐遨遘遢遛暹遴遽邂邈邃邋彐彗彖彘尻咫屐屙孱屣屦羼弪弩弭艴弼鬻屮妁妃妍妩妪妣"],["e640","鍬",34,"鎐",27],["e680","鎬",29,"鏋鏌鏍妗姊妫妞妤姒妲妯姗妾娅娆姝娈姣姘姹娌娉娲娴娑娣娓婀婧婊婕娼婢婵胬媪媛婷婺媾嫫媲嫒嫔媸嫠嫣嫱嫖嫦嫘嫜嬉嬗嬖嬲嬷孀尕尜孚孥孳孑孓孢驵驷驸驺驿驽骀骁骅骈骊骐骒骓骖骘骛骜骝骟骠骢骣骥骧纟纡纣纥纨纩"],["e740","鏎",7,"鏗",54],["e780","鐎",32,"纭纰纾绀绁绂绉绋绌绐绔绗绛绠绡绨绫绮绯绱绲缍绶绺绻绾缁缂缃缇缈缋缌缏缑缒缗缙缜缛缟缡",6,"缪缫缬缭缯",4,"缵幺畿巛甾邕玎玑玮玢玟珏珂珑玷玳珀珉珈珥珙顼琊珩珧珞玺珲琏琪瑛琦琥琨琰琮琬"],["e840","鐯",14,"鐿",43,"鑬鑭鑮鑯"],["e880","鑰",20,"钑钖钘铇铏铓铔铚铦铻锜锠琛琚瑁瑜瑗瑕瑙瑷瑭瑾璜璎璀璁璇璋璞璨璩璐璧瓒璺韪韫韬杌杓杞杈杩枥枇杪杳枘枧杵枨枞枭枋杷杼柰栉柘栊柩枰栌柙枵柚枳柝栀柃枸柢栎柁柽栲栳桠桡桎桢桄桤梃栝桕桦桁桧桀栾桊桉栩梵梏桴桷梓桫棂楮棼椟椠棹"],["e940","锧锳锽镃镈镋镕镚镠镮镴镵長",7,"門",42],["e980","閫",32,"椤棰椋椁楗棣椐楱椹楠楂楝榄楫榀榘楸椴槌榇榈槎榉楦楣楹榛榧榻榫榭槔榱槁槊槟榕槠榍槿樯槭樗樘橥槲橄樾檠橐橛樵檎橹樽樨橘橼檑檐檩檗檫猷獒殁殂殇殄殒殓殍殚殛殡殪轫轭轱轲轳轵轶轸轷轹轺轼轾辁辂辄辇辋"],["ea40","闌",27,"闬闿阇阓阘阛阞阠阣",6,"阫阬阭阯阰阷阸阹阺阾陁陃陊陎陏陑陒陓陖陗"],["ea80","陘陙陚陜陝陞陠陣陥陦陫陭",4,"陳陸",12,"隇隉隊辍辎辏辘辚軎戋戗戛戟戢戡戥戤戬臧瓯瓴瓿甏甑甓攴旮旯旰昊昙杲昃昕昀炅曷昝昴昱昶昵耆晟晔晁晏晖晡晗晷暄暌暧暝暾曛曜曦曩贲贳贶贻贽赀赅赆赈赉赇赍赕赙觇觊觋觌觎觏觐觑牮犟牝牦牯牾牿犄犋犍犏犒挈挲掰"],["eb40","隌階隑隒隓隕隖隚際隝",9,"隨",7,"隱隲隴隵隷隸隺隻隿雂雃雈雊雋雐雑雓雔雖",9,"雡",6,"雫"],["eb80","雬雭雮雰雱雲雴雵雸雺電雼雽雿霂霃霅霊霋霌霐霑霒霔霕霗",4,"霝霟霠搿擘耄毪毳毽毵毹氅氇氆氍氕氘氙氚氡氩氤氪氲攵敕敫牍牒牖爰虢刖肟肜肓肼朊肽肱肫肭肴肷胧胨胩胪胛胂胄胙胍胗朐胝胫胱胴胭脍脎胲胼朕脒豚脶脞脬脘脲腈腌腓腴腙腚腱腠腩腼腽腭腧塍媵膈膂膑滕膣膪臌朦臊膻"],["ec40","霡",8,"霫霬霮霯霱霳",4,"霺霻霼霽霿",18,"靔靕靗靘靚靜靝靟靣靤靦靧靨靪",7],["ec80","靲靵靷",4,"靽",7,"鞆",4,"鞌鞎鞏鞐鞓鞕鞖鞗鞙",4,"臁膦欤欷欹歃歆歙飑飒飓飕飙飚殳彀毂觳斐齑斓於旆旄旃旌旎旒旖炀炜炖炝炻烀炷炫炱烨烊焐焓焖焯焱煳煜煨煅煲煊煸煺熘熳熵熨熠燠燔燧燹爝爨灬焘煦熹戾戽扃扈扉礻祀祆祉祛祜祓祚祢祗祠祯祧祺禅禊禚禧禳忑忐"],["ed40","鞞鞟鞡鞢鞤",6,"鞬鞮鞰鞱鞳鞵",46],["ed80","韤韥韨韮",4,"韴韷",23,"怼恝恚恧恁恙恣悫愆愍慝憩憝懋懑戆肀聿沓泶淼矶矸砀砉砗砘砑斫砭砜砝砹砺砻砟砼砥砬砣砩硎硭硖硗砦硐硇硌硪碛碓碚碇碜碡碣碲碹碥磔磙磉磬磲礅磴礓礤礞礴龛黹黻黼盱眄眍盹眇眈眚眢眙眭眦眵眸睐睑睇睃睚睨"],["ee40","頏",62],["ee80","顎",32,"睢睥睿瞍睽瞀瞌瞑瞟瞠瞰瞵瞽町畀畎畋畈畛畲畹疃罘罡罟詈罨罴罱罹羁罾盍盥蠲钅钆钇钋钊钌钍钏钐钔钗钕钚钛钜钣钤钫钪钭钬钯钰钲钴钶",4,"钼钽钿铄铈",6,"铐铑铒铕铖铗铙铘铛铞铟铠铢铤铥铧铨铪"],["ef40","顯",5,"颋颎颒颕颙颣風",37,"飏飐飔飖飗飛飜飝飠",4],["ef80","飥飦飩",30,"铩铫铮铯铳铴铵铷铹铼铽铿锃锂锆锇锉锊锍锎锏锒",4,"锘锛锝锞锟锢锪锫锩锬锱锲锴锶锷锸锼锾锿镂锵镄镅镆镉镌镎镏镒镓镔镖镗镘镙镛镞镟镝镡镢镤",8,"镯镱镲镳锺矧矬雉秕秭秣秫稆嵇稃稂稞稔"],["f040","餈",4,"餎餏餑",28,"餯",26],["f080","饊",9,"饖",12,"饤饦饳饸饹饻饾馂馃馉稹稷穑黏馥穰皈皎皓皙皤瓞瓠甬鸠鸢鸨",4,"鸲鸱鸶鸸鸷鸹鸺鸾鹁鹂鹄鹆鹇鹈鹉鹋鹌鹎鹑鹕鹗鹚鹛鹜鹞鹣鹦",6,"鹱鹭鹳疒疔疖疠疝疬疣疳疴疸痄疱疰痃痂痖痍痣痨痦痤痫痧瘃痱痼痿瘐瘀瘅瘌瘗瘊瘥瘘瘕瘙"],["f140","馌馎馚",10,"馦馧馩",47],["f180","駙",32,"瘛瘼瘢瘠癀瘭瘰瘿瘵癃瘾瘳癍癞癔癜癖癫癯翊竦穸穹窀窆窈窕窦窠窬窨窭窳衤衩衲衽衿袂袢裆袷袼裉裢裎裣裥裱褚裼裨裾裰褡褙褓褛褊褴褫褶襁襦襻疋胥皲皴矜耒耔耖耜耠耢耥耦耧耩耨耱耋耵聃聆聍聒聩聱覃顸颀颃"],["f240","駺",62],["f280","騹",32,"颉颌颍颏颔颚颛颞颟颡颢颥颦虍虔虬虮虿虺虼虻蚨蚍蚋蚬蚝蚧蚣蚪蚓蚩蚶蛄蚵蛎蚰蚺蚱蚯蛉蛏蚴蛩蛱蛲蛭蛳蛐蜓蛞蛴蛟蛘蛑蜃蜇蛸蜈蜊蜍蜉蜣蜻蜞蜥蜮蜚蜾蝈蜴蜱蜩蜷蜿螂蜢蝽蝾蝻蝠蝰蝌蝮螋蝓蝣蝼蝤蝙蝥螓螯螨蟒"],["f340","驚",17,"驲骃骉骍骎骔骕骙骦骩",6,"骲骳骴骵骹骻骽骾骿髃髄髆",4,"髍髎髏髐髒體髕髖髗髙髚髛髜"],["f380","髝髞髠髢髣髤髥髧髨髩髪髬髮髰",8,"髺髼",6,"鬄鬅鬆蟆螈螅螭螗螃螫蟥螬螵螳蟋蟓螽蟑蟀蟊蟛蟪蟠蟮蠖蠓蟾蠊蠛蠡蠹蠼缶罂罄罅舐竺竽笈笃笄笕笊笫笏筇笸笪笙笮笱笠笥笤笳笾笞筘筚筅筵筌筝筠筮筻筢筲筱箐箦箧箸箬箝箨箅箪箜箢箫箴篑篁篌篝篚篥篦篪簌篾篼簏簖簋"],["f440","鬇鬉",5,"鬐鬑鬒鬔",10,"鬠鬡鬢鬤",10,"鬰鬱鬳",7,"鬽鬾鬿魀魆魊魋魌魎魐魒魓魕",5],["f480","魛",32,"簟簪簦簸籁籀臾舁舂舄臬衄舡舢舣舭舯舨舫舸舻舳舴舾艄艉艋艏艚艟艨衾袅袈裘裟襞羝羟羧羯羰羲籼敉粑粝粜粞粢粲粼粽糁糇糌糍糈糅糗糨艮暨羿翎翕翥翡翦翩翮翳糸絷綦綮繇纛麸麴赳趄趔趑趱赧赭豇豉酊酐酎酏酤"],["f540","魼",62],["f580","鮻",32,"酢酡酰酩酯酽酾酲酴酹醌醅醐醍醑醢醣醪醭醮醯醵醴醺豕鹾趸跫踅蹙蹩趵趿趼趺跄跖跗跚跞跎跏跛跆跬跷跸跣跹跻跤踉跽踔踝踟踬踮踣踯踺蹀踹踵踽踱蹉蹁蹂蹑蹒蹊蹰蹶蹼蹯蹴躅躏躔躐躜躞豸貂貊貅貘貔斛觖觞觚觜"],["f640","鯜",62],["f680","鰛",32,"觥觫觯訾謦靓雩雳雯霆霁霈霏霎霪霭霰霾龀龃龅",5,"龌黾鼋鼍隹隼隽雎雒瞿雠銎銮鋈錾鍪鏊鎏鐾鑫鱿鲂鲅鲆鲇鲈稣鲋鲎鲐鲑鲒鲔鲕鲚鲛鲞",5,"鲥",4,"鲫鲭鲮鲰",7,"鲺鲻鲼鲽鳄鳅鳆鳇鳊鳋"],["f740","鰼",62],["f780","鱻鱽鱾鲀鲃鲄鲉鲊鲌鲏鲓鲖鲗鲘鲙鲝鲪鲬鲯鲹鲾",4,"鳈鳉鳑鳒鳚鳛鳠鳡鳌",4,"鳓鳔鳕鳗鳘鳙鳜鳝鳟鳢靼鞅鞑鞒鞔鞯鞫鞣鞲鞴骱骰骷鹘骶骺骼髁髀髅髂髋髌髑魅魃魇魉魈魍魑飨餍餮饕饔髟髡髦髯髫髻髭髹鬈鬏鬓鬟鬣麽麾縻麂麇麈麋麒鏖麝麟黛黜黝黠黟黢黩黧黥黪黯鼢鼬鼯鼹鼷鼽鼾齄"],["f840","鳣",62],["f880","鴢",32],["f940","鵃",62],["f980","鶂",32],["fa40","鶣",62],["fa80","鷢",32],["fb40","鸃",27,"鸤鸧鸮鸰鸴鸻鸼鹀鹍鹐鹒鹓鹔鹖鹙鹝鹟鹠鹡鹢鹥鹮鹯鹲鹴",9,"麀"],["fb80","麁麃麄麅麆麉麊麌",5,"麔",8,"麞麠",5,"麧麨麩麪"],["fc40","麫",8,"麵麶麷麹麺麼麿",4,"黅黆黇黈黊黋黌黐黒黓黕黖黗黙黚點黡黣黤黦黨黫黬黭黮黰",8,"黺黽黿",6],["fc80","鼆",4,"鼌鼏鼑鼒鼔鼕鼖鼘鼚",5,"鼡鼣",8,"鼭鼮鼰鼱"],["fd40","鼲",4,"鼸鼺鼼鼿",4,"齅",10,"齒",38],["fd80","齹",5,"龁龂龍",11,"龜龝龞龡",4,"郎凉秊裏隣"],["fe40","兀嗀﨎﨏﨑﨓﨔礼﨟蘒﨡﨣﨤﨧﨨﨩"]]},802:function(e,t,r){"use strict";var i=r(986).Buffer;var n=r(165),a=e.exports;a.encodings=null;a.defaultCharUnicode="�";a.defaultCharSingleByte="?";a.encode=function encode(e,t,r){e=""+(e||"");var n=a.getEncoder(t,r);var o=n.write(e);var c=n.end();return c&&c.length>0?i.concat([o,c]):o};a.decode=function decode(e,t,r){if(typeof e==="string"){if(!a.skipDecodeWarning){console.error("Iconv-lite warning: decode()-ing strings is deprecated. Refer to https://github.com/ashtuchkin/iconv-lite/wiki/Use-Buffers-when-decoding");a.skipDecodeWarning=true}e=i.from(""+(e||""),"binary")}var n=a.getDecoder(t,r);var o=n.write(e);var c=n.end();return c?o+c:o};a.encodingExists=function encodingExists(e){try{a.getCodec(e);return true}catch(e){return false}};a.toEncoding=a.encode;a.fromEncoding=a.decode;a._codecDataCache={};a.getCodec=function getCodec(e){if(!a.encodings)a.encodings=r(467);var t=a._canonicalizeEncoding(e);var i={};while(true){var n=a._codecDataCache[t];if(n)return n;var o=a.encodings[t];switch(typeof o){case"string":t=o;break;case"object":for(var c in o)i[c]=o[c];if(!i.encodingName)i.encodingName=t;t=o.type;break;case"function":if(!i.encodingName)i.encodingName=t;n=new o(i,a);a._codecDataCache[i.encodingName]=n;return n;default:throw new Error("Encoding not recognized: '"+e+"' (searched as: '"+t+"')")}}};a._canonicalizeEncoding=function(e){return(""+e).toLowerCase().replace(/:\d{4}$|[^0-9a-z]/g,"")};a.getEncoder=function getEncoder(e,t){var r=a.getCodec(e),i=new r.encoder(t,r);if(r.bomAware&&t&&t.addBOM)i=new n.PrependBOM(i,t);return i};a.getDecoder=function getDecoder(e,t){var r=a.getCodec(e),i=new r.decoder(t,r);if(r.bomAware&&!(t&&t.stripBOM===false))i=new n.StripBOM(i,t);return i};var o=typeof process!=="undefined"&&process.versions&&process.versions.node;if(o){var c=o.split(".").map(Number);if(c[0]>0||c[1]>=10){r(189)(a)}r(655)(a)}if(false){}},811:function(e,t,r){"use strict";var i=r(986).Buffer;t.utf7=Utf7Codec;t.unicode11utf7="utf7";function Utf7Codec(e,t){this.iconv=t}Utf7Codec.prototype.encoder=Utf7Encoder;Utf7Codec.prototype.decoder=Utf7Decoder;Utf7Codec.prototype.bomAware=true;var n=/[^A-Za-z0-9'\(\),-\.\/:\? \n\r\t]+/g;function Utf7Encoder(e,t){this.iconv=t.iconv}Utf7Encoder.prototype.write=function(e){return i.from(e.replace(n,function(e){return"+"+(e==="+"?"":this.iconv.encode(e,"utf16-be").toString("base64").replace(/=+$/,""))+"-"}.bind(this)))};Utf7Encoder.prototype.end=function(){};function Utf7Decoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=""}var a=/[A-Za-z0-9\/+]/;var o=[];for(var c=0;c<256;c++)o[c]=a.test(String.fromCharCode(c));var s="+".charCodeAt(0),f="-".charCodeAt(0),p="&".charCodeAt(0);Utf7Decoder.prototype.write=function(e){var t="",r=0,n=this.inBase64,a=this.base64Accum;for(var c=0;c<e.length;c++){if(!n){if(e[c]==s){t+=this.iconv.decode(e.slice(r,c),"ascii");r=c+1;n=true}}else{if(!o[e[c]]){if(c==r&&e[c]==f){t+="+"}else{var p=a+e.slice(r,c).toString();t+=this.iconv.decode(i.from(p,"base64"),"utf16-be")}if(e[c]!=f)c--;r=c+1;n=false;a=""}}}if(!n){t+=this.iconv.decode(e.slice(r),"ascii")}else{var p=a+e.slice(r).toString();var u=p.length-p.length%8;a=p.slice(u);p=p.slice(0,u);t+=this.iconv.decode(i.from(p,"base64"),"utf16-be")}this.inBase64=n;this.base64Accum=a;return t};Utf7Decoder.prototype.end=function(){var e="";if(this.inBase64&&this.base64Accum.length>0)e=this.iconv.decode(i.from(this.base64Accum,"base64"),"utf16-be");this.inBase64=false;this.base64Accum="";return e};t.utf7imap=Utf7IMAPCodec;function Utf7IMAPCodec(e,t){this.iconv=t}Utf7IMAPCodec.prototype.encoder=Utf7IMAPEncoder;Utf7IMAPCodec.prototype.decoder=Utf7IMAPDecoder;Utf7IMAPCodec.prototype.bomAware=true;function Utf7IMAPEncoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=i.alloc(6);this.base64AccumIdx=0}Utf7IMAPEncoder.prototype.write=function(e){var t=this.inBase64,r=this.base64Accum,n=this.base64AccumIdx,a=i.alloc(e.length*5+10),o=0;for(var c=0;c<e.length;c++){var s=e.charCodeAt(c);if(32<=s&&s<=126){if(t){if(n>0){o+=a.write(r.slice(0,n).toString("base64").replace(/\//g,",").replace(/=+$/,""),o);n=0}a[o++]=f;t=false}if(!t){a[o++]=s;if(s===p)a[o++]=f}}else{if(!t){a[o++]=p;t=true}if(t){r[n++]=s>>8;r[n++]=s&255;if(n==r.length){o+=a.write(r.toString("base64").replace(/\//g,","),o);n=0}}}}this.inBase64=t;this.base64AccumIdx=n;return a.slice(0,o)};Utf7IMAPEncoder.prototype.end=function(){var e=i.alloc(10),t=0;if(this.inBase64){if(this.base64AccumIdx>0){t+=e.write(this.base64Accum.slice(0,this.base64AccumIdx).toString("base64").replace(/\//g,",").replace(/=+$/,""),t);this.base64AccumIdx=0}e[t++]=f;this.inBase64=false}return e.slice(0,t)};function Utf7IMAPDecoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=""}var u=o.slice();u[",".charCodeAt(0)]=true;Utf7IMAPDecoder.prototype.write=function(e){var t="",r=0,n=this.inBase64,a=this.base64Accum;for(var o=0;o<e.length;o++){if(!n){if(e[o]==p){t+=this.iconv.decode(e.slice(r,o),"ascii");r=o+1;n=true}}else{if(!u[e[o]]){if(o==r&&e[o]==f){t+="&"}else{var c=a+e.slice(r,o).toString().replace(/,/g,"/");t+=this.iconv.decode(i.from(c,"base64"),"utf16-be")}if(e[o]!=f)o--;r=o+1;n=false;a=""}}}if(!n){t+=this.iconv.decode(e.slice(r),"ascii")}else{var c=a+e.slice(r).toString().replace(/,/g,"/");var s=c.length-c.length%8;a=c.slice(s);c=c.slice(0,s);t+=this.iconv.decode(i.from(c,"base64"),"utf16-be")}this.inBase64=n;this.base64Accum=a;return t};Utf7IMAPDecoder.prototype.end=function(){var e="";if(this.inBase64&&this.base64Accum.length>0)e=this.iconv.decode(i.from(this.base64Accum,"base64"),"utf16-be");this.inBase64=false;this.base64Accum="";return e}},828:function(e,t,r){"use strict";var i=r(767);var n=r(416);var a=r(802);var o=r(424);e.exports=getRawBody;var c=/^Encoding not recognized: /;function getDecoder(e){if(!e)return null;try{return a.getDecoder(e)}catch(t){if(!c.test(t.message))throw t;throw n(415,"specified encoding unsupported",{encoding:e,type:"encoding.unsupported"})}}function getRawBody(e,t,r){var n=r;var a=t||{};if(t===true||typeof t==="string"){a={encoding:t}}if(typeof t==="function"){n=t;a={}}if(n!==undefined&&typeof n!=="function"){throw new TypeError("argument callback must be a function")}if(!n&&!global.Promise){throw new TypeError("argument callback is required")}var o=a.encoding!==true?a.encoding:"utf-8";var c=i.parse(a.limit);var s=a.length!=null&&!isNaN(a.length)?parseInt(a.length,10):null;if(n){return readStream(e,o,s,c,n)}return new Promise(function executor(t,r){readStream(e,o,s,c,function onRead(e,i){if(e)return r(e);t(i)})})}function halt(e){o(e);if(typeof e.pause==="function"){e.pause()}}function readStream(e,t,r,i,a){var o=false;var c=true;if(i!==null&&r!==null&&r>i){return done(n(413,"request entity too large",{expected:r,length:r,limit:i,type:"entity.too.large"}))}var s=e._readableState;if(e._decoder||s&&(s.encoding||s.decoder)){return done(n(500,"stream encoding should not be set",{type:"stream.encoding.set"}))}var f=0;var p;try{p=getDecoder(t)}catch(e){return done(e)}var u=p?"":[];e.on("aborted",onAborted);e.on("close",cleanup);e.on("data",onData);e.on("end",onEnd);e.on("error",onEnd);c=false;function done(){var t=new Array(arguments.length);for(var r=0;r<t.length;r++){t[r]=arguments[r]}o=true;if(c){process.nextTick(invokeCallback)}else{invokeCallback()}function invokeCallback(){cleanup();if(t[0]){halt(e)}a.apply(null,t)}}function onAborted(){if(o)return;done(n(400,"request aborted",{code:"ECONNABORTED",expected:r,length:r,received:f,type:"request.aborted"}))}function onData(e){if(o)return;f+=e.length;if(i!==null&&f>i){done(n(413,"request entity too large",{limit:i,received:f,type:"entity.too.large"}))}else if(p){u+=p.write(e)}else{u.push(e)}}function onEnd(e){if(o)return;if(e)return done(e);if(r!==null&&f!==r){done(n(400,"request size did not match content length",{expected:r,length:r,received:f,type:"request.size.invalid"}))}else{var t=p?u+(p.end()||""):Buffer.concat(u);done(null,t)}}function cleanup(){u=null;e.removeListener("aborted",onAborted);e.removeListener("data",onData);e.removeListener("end",onEnd);e.removeListener("error",onEnd);e.removeListener("close",cleanup)}}},839:function(e,t,r){"use strict";var i=r(272);e.exports=status;status.STATUS_CODES=i;status.codes=populateStatusesMap(status,i);status.redirect={300:true,301:true,302:true,303:true,305:true,307:true,308:true};status.empty={204:true,205:true,304:true};status.retry={502:true,503:true,504:true};function populateStatusesMap(e,t){var r=[];Object.keys(t).forEach(function forEachCode(i){var n=t[i];var a=Number(i);e[a]=n;e[n]=a;e[n.toLowerCase()]=a;r.push(a)});return r}function status(e){if(typeof e==="number"){if(!status[e])throw new Error("invalid status code: "+e);return e}if(typeof e!=="string"){throw new TypeError("code must be a number or string")}var t=parseInt(e,10);if(!isNaN(t)){if(!status[t])throw new Error("invalid status code: "+t);return t}t=status[e.toLowerCase()];if(!t)throw new Error('invalid status message: "'+e+'"');return t}},910:function(e){e.exports={uChars:[128,165,169,178,184,216,226,235,238,244,248,251,253,258,276,284,300,325,329,334,364,463,465,467,469,471,473,475,477,506,594,610,712,716,730,930,938,962,970,1026,1104,1106,8209,8215,8218,8222,8231,8241,8244,8246,8252,8365,8452,8454,8458,8471,8482,8556,8570,8596,8602,8713,8720,8722,8726,8731,8737,8740,8742,8748,8751,8760,8766,8777,8781,8787,8802,8808,8816,8854,8858,8870,8896,8979,9322,9372,9548,9588,9616,9622,9634,9652,9662,9672,9676,9680,9702,9735,9738,9793,9795,11906,11909,11913,11917,11928,11944,11947,11951,11956,11960,11964,11979,12284,12292,12312,12319,12330,12351,12436,12447,12535,12543,12586,12842,12850,12964,13200,13215,13218,13253,13263,13267,13270,13384,13428,13727,13839,13851,14617,14703,14801,14816,14964,15183,15471,15585,16471,16736,17208,17325,17330,17374,17623,17997,18018,18212,18218,18301,18318,18760,18811,18814,18820,18823,18844,18848,18872,19576,19620,19738,19887,40870,59244,59336,59367,59413,59417,59423,59431,59437,59443,59452,59460,59478,59493,63789,63866,63894,63976,63986,64016,64018,64021,64025,64034,64037,64042,65074,65093,65107,65112,65127,65132,65375,65510,65536],gbChars:[0,36,38,45,50,81,89,95,96,100,103,104,105,109,126,133,148,172,175,179,208,306,307,308,309,310,311,312,313,341,428,443,544,545,558,741,742,749,750,805,819,820,7922,7924,7925,7927,7934,7943,7944,7945,7950,8062,8148,8149,8152,8164,8174,8236,8240,8262,8264,8374,8380,8381,8384,8388,8390,8392,8393,8394,8396,8401,8406,8416,8419,8424,8437,8439,8445,8482,8485,8496,8521,8603,8936,8946,9046,9050,9063,9066,9076,9092,9100,9108,9111,9113,9131,9162,9164,9218,9219,11329,11331,11334,11336,11346,11361,11363,11366,11370,11372,11375,11389,11682,11686,11687,11692,11694,11714,11716,11723,11725,11730,11736,11982,11989,12102,12336,12348,12350,12384,12393,12395,12397,12510,12553,12851,12962,12973,13738,13823,13919,13933,14080,14298,14585,14698,15583,15847,16318,16434,16438,16481,16729,17102,17122,17315,17320,17402,17418,17859,17909,17911,17915,17916,17936,17939,17961,18664,18703,18814,18962,19043,33469,33470,33471,33484,33485,33490,33497,33501,33505,33513,33520,33536,33550,37845,37921,37948,38029,38038,38064,38065,38066,38069,38075,38076,38078,39108,39109,39113,39114,39115,39116,39265,39394,189e3]}},945:function(e,t,r){"use strict";var i=r(986).Buffer;t.utf16be=Utf16BECodec;function Utf16BECodec(){}Utf16BECodec.prototype.encoder=Utf16BEEncoder;Utf16BECodec.prototype.decoder=Utf16BEDecoder;Utf16BECodec.prototype.bomAware=true;function Utf16BEEncoder(){}Utf16BEEncoder.prototype.write=function(e){var t=i.from(e,"ucs2");for(var r=0;r<t.length;r+=2){var n=t[r];t[r]=t[r+1];t[r+1]=n}return t};Utf16BEEncoder.prototype.end=function(){};function Utf16BEDecoder(){this.overflowByte=-1}Utf16BEDecoder.prototype.write=function(e){if(e.length==0)return"";var t=i.alloc(e.length+1),r=0,n=0;if(this.overflowByte!==-1){t[0]=e[0];t[1]=this.overflowByte;r=1;n=2}for(;r<e.length-1;r+=2,n+=2){t[n]=e[r+1];t[n+1]=e[r]}this.overflowByte=r==e.length-1?e[e.length-1]:-1;return t.slice(0,n).toString("ucs2")};Utf16BEDecoder.prototype.end=function(){};t.utf16=Utf16Codec;function Utf16Codec(e,t){this.iconv=t}Utf16Codec.prototype.encoder=Utf16Encoder;Utf16Codec.prototype.decoder=Utf16Decoder;function Utf16Encoder(e,t){e=e||{};if(e.addBOM===undefined)e.addBOM=true;this.encoder=t.iconv.getEncoder("utf-16le",e)}Utf16Encoder.prototype.write=function(e){return this.encoder.write(e)};Utf16Encoder.prototype.end=function(){return this.encoder.end()};function Utf16Decoder(e,t){this.decoder=null;this.initialBytes=[];this.initialBytesLen=0;this.options=e||{};this.iconv=t.iconv}Utf16Decoder.prototype.write=function(e){if(!this.decoder){this.initialBytes.push(e);this.initialBytesLen+=e.length;if(this.initialBytesLen<16)return"";var e=i.concat(this.initialBytes),t=detectEncoding(e,this.options.defaultEncoding);this.decoder=this.iconv.getDecoder(t,this.options);this.initialBytes.length=this.initialBytesLen=0}return this.decoder.write(e)};Utf16Decoder.prototype.end=function(){if(!this.decoder){var e=i.concat(this.initialBytes),t=detectEncoding(e,this.options.defaultEncoding);this.decoder=this.iconv.getDecoder(t,this.options);var r=this.decoder.write(e),n=this.decoder.end();return n?r+n:r}return this.decoder.end()};function detectEncoding(e,t){var r=t||"utf-16le";if(e.length>=2){if(e[0]==254&&e[1]==255)r="utf-16be";else if(e[0]==255&&e[1]==254)r="utf-16le";else{var i=0,n=0,a=Math.min(e.length-e.length%2,64);for(var o=0;o<a;o+=2){if(e[o]===0&&e[o+1]!==0)n++;if(e[o]!==0&&e[o+1]===0)i++}if(n>i)r="utf-16be";else if(n<i)r="utf-16le"}}return r}},986:function(e,t,r){"use strict";var i=r(293);var n=i.Buffer;var a={};var o;for(o in i){if(!i.hasOwnProperty(o))continue;if(o==="SlowBuffer"||o==="Buffer")continue;a[o]=i[o]}var c=a.Buffer={};for(o in n){if(!n.hasOwnProperty(o))continue;if(o==="allocUnsafe"||o==="allocUnsafeSlow")continue;c[o]=n[o]}a.Buffer.prototype=n.prototype;if(!c.from||c.from===Uint8Array.from){c.from=function(e,t,r){if(typeof e==="number"){throw new TypeError('The "value" argument must not be of type number. Received type '+typeof e)}if(e&&typeof e.length==="undefined"){throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type "+typeof e)}return n(e,t,r)}}if(!c.alloc){c.alloc=function(e,t,r){if(typeof e!=="number"){throw new TypeError('The "size" argument must be of type number. Received type '+typeof e)}if(e<0||e>=2*(1<<30)){throw new RangeError('The value "'+e+'" is invalid for option "size"')}var i=n(e);if(!t||t.length===0){i.fill(0)}else if(typeof r==="string"){i.fill(t,r)}else{i.fill(t)}return i}}if(!a.kStringMaxLength){try{a.kStringMaxLength=process.binding("buffer").kStringMaxLength}catch(e){}}if(!a.constants){a.constants={MAX_LENGTH:a.kMaxLength};if(a.kStringMaxLength){a.constants.MAX_STRING_LENGTH=a.kStringMaxLength}}e.exports=a},999:function(e){"use strict";e.exports=callSiteToString;function callSiteFileLocation(e){var t;var r="";if(e.isNative()){r="native"}else if(e.isEval()){t=e.getScriptNameOrSourceURL();if(!t){r=e.getEvalOrigin()}}else{t=e.getFileName()}if(t){r+=t;var i=e.getLineNumber();if(i!=null){r+=":"+i;var n=e.getColumnNumber();if(n){r+=":"+n}}}return r||"unknown source"}function callSiteToString(e){var t=true;var r=callSiteFileLocation(e);var i=e.getFunctionName();var n=e.isConstructor();var a=!(e.isToplevel()||n);var o="";if(a){var c=e.getMethodName();var s=getConstructorName(e);if(i){if(s&&i.indexOf(s)!==0){o+=s+"."}o+=i;if(c&&i.lastIndexOf("."+c)!==i.length-c.length-1){o+=" [as "+c+"]"}}else{o+=s+"."+(c||"<anonymous>")}}else if(n){o+="new "+(i||"<anonymous>")}else if(i){o+=i}else{t=false;o+=r}if(t){o+=" ("+r+")"}return o}function getConstructorName(e){var t=e.receiver;return t.constructor&&t.constructor.name||null}}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "ClL1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Crypto = __webpack_require__("PJMN");

const B64 = __webpack_require__("M8F5");
const Boom = __webpack_require__("otTC");
const Bourne = __webpack_require__("5kZ8");
const Cryptiles = __webpack_require__("ieHi");
const Hoek = __webpack_require__("XZo7");


const internals = {};


exports.defaults = {
    encryption: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1,
        minPasswordlength: 32
    },

    integrity: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1,
        minPasswordlength: 32
    },

    ttl: 0,                                             // Milliseconds, 0 means forever
    timestampSkewSec: 60,                               // Seconds of permitted clock skew for incoming expirations
    localtimeOffsetMsec: 0                              // Local clock time offset express in a number of milliseconds (positive or negative)
};


// Algorithm configuration

exports.algorithms = {
    'aes-128-ctr': { keyBits: 128, ivBits: 128 },
    'aes-256-cbc': { keyBits: 256, ivBits: 128 },
    'sha256': { keyBits: 256 }
};


// MAC normalization format version

exports.macFormatVersion = '2';                         // Prevent comparison of mac values generated with different normalized string formats

exports.macPrefix = 'Fe26.' + exports.macFormatVersion;


// Generate a unique encryption key

/*
    const options =  {
        saltBits: 256,                                  // Ignored if salt is set
        salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
        algorithm: 'aes-128-ctr',
        iterations: 10000,
        iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg',          // Optional
        minPasswordlength: 32
    };
*/

exports.generateKey = async function (password, options) {

    if (!password) {
        throw new Boom('Empty password');
    }

    if (!options ||
        typeof options !== 'object') {

        throw new Boom('Bad options');
    }

    const algorithm = exports.algorithms[options.algorithm];
    if (!algorithm) {
        throw new Boom('Unknown algorithm: ' + options.algorithm);
    }

    const result = {};

    if (Buffer.isBuffer(password)) {
        if (password.length < algorithm.keyBits / 8) {
            throw new Boom('Key buffer (password) too small');
        }

        result.key = password;
        result.salt = '';
    }
    else {
        if (password.length < options.minPasswordlength) {
            throw new Boom('Password string too short (min ' + options.minPasswordlength + ' characters required)');
        }

        let salt = options.salt;
        if (!salt) {
            if (!options.saltBits) {
                throw new Boom('Missing salt and saltBits options');
            }

            const randomSalt = Cryptiles.randomBits(options.saltBits);
            salt = randomSalt.toString('hex');
        }

        const derivedKey = await internals.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, 'sha1');

        result.key = derivedKey;
        result.salt = salt;
    }

    if (options.iv) {
        result.iv = options.iv;
    }
    else if (algorithm.ivBits) {
        result.iv = Cryptiles.randomBits(algorithm.ivBits);
    }

    return result;
};


// Encrypt data
// options: see exports.generateKey()

exports.encrypt = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

    return { encrypted, key };
};


// Decrypt data
// options: see exports.generateKey()

exports.decrypt = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const decipher = Crypto.createDecipheriv(options.algorithm, key.key, key.iv);
    let dec = decipher.update(data, null, 'utf8');
    dec = dec + decipher.final('utf8');

    return dec;
};


// HMAC using a password
// options: see exports.generateKey()

exports.hmacWithPassword = async function (password, options, data) {

    const key = await exports.generateKey(password, options);
    const hmac = Crypto.createHmac(options.algorithm, key.key).update(data);
    const digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

    return {
        digest,
        salt: key.salt
    };
};


// Normalizes a password parameter into a { id, encryption, integrity } object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }

internals.normalizePassword = function (password) {

    if (password &&
        typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        return {
            id: password.id,
            encryption: password.secret || password.encryption,
            integrity: password.secret || password.integrity
        };
    }

    return {
        encryption: password,
        integrity: password
    };
};


// Encrypt and HMAC an object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }
// options: see exports.defaults

exports.seal = async function (object, password, options) {

    options = Object.assign({}, options);       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec || 0);                 // Measure now before any other processing

    // Serialize object

    const objectString = internals.stringify(object);

    // Obtain password

    let passwordId = '';
    password = internals.normalizePassword(password);
    if (password.id) {
        if (!/^\w+$/.test(password.id)) {
            throw new Boom('Invalid password id');
        }

        passwordId = password.id;
    }

    // Encrypt object string

    const { encrypted, key } = await exports.encrypt(password.encryption, options.encryption, objectString);

    // Base64url the encrypted value

    const encryptedB64 = B64.base64urlEncode(encrypted);
    const iv = B64.base64urlEncode(key.iv);
    const expiration = (options.ttl ? now + options.ttl : '');
    const macBaseString = exports.macPrefix + '*' + passwordId + '*' + key.salt + '*' + iv + '*' + encryptedB64 + '*' + expiration;

    // Mac the combined values

    const mac = await exports.hmacWithPassword(password.integrity, options.integrity, macBaseString);

    // Put it all together

    // prefix*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac
    // Allowed URI query name/value characters: *-. \d \w

    const sealed = macBaseString + '*' + mac.salt + '*' + mac.digest;
    return sealed;
};


// Decrypt and validate sealed string
// password: string, buffer or object with { id: secret } or { id: { encryption, integrity } }
// options: see exports.defaults

exports.unseal = async function (sealed, password, options) {

    options = Object.assign({}, options);                                       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec || 0);                // Measure now before any other processing

    // Break string into components

    const parts = sealed.split('*');
    if (parts.length !== 8) {
        throw new Boom('Incorrect number of sealed components');
    }

    const macPrefix = parts[0];
    const passwordId = parts[1];
    const encryptionSalt = parts[2];
    const encryptionIv = parts[3];
    const encryptedB64 = parts[4];
    const expiration = parts[5];
    const hmacSalt = parts[6];
    const hmac = parts[7];
    const macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' + encryptedB64 + '*' + expiration;

    // Check prefix

    if (macPrefix !== exports.macPrefix) {
        throw new Boom('Wrong mac prefix');
    }

    // Check expiration

    if (expiration) {
        if (!expiration.match(/^\d+$/)) {
            throw new Boom('Invalid expiration');
        }

        const exp = parseInt(expiration, 10);
        if (exp <= (now - (options.timestampSkewSec * 1000))) {
            throw new Boom('Expired seal');
        }
    }

    // Obtain password

    if (!password) {
        throw new Boom('Empty password');
    }

    if (typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        password = password[passwordId || 'default'];
        if (!password) {
            throw new Boom('Cannot find password: ' + passwordId);
        }
    }

    password = internals.normalizePassword(password);

    // Check hmac

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
    const mac = await exports.hmacWithPassword(password.integrity, macOptions, macBaseString);

    if (!Cryptiles.fixedTimeComparison(mac.digest, hmac)) {
        throw new Boom('Bad hmac value');
    }

    // Decrypt

    try {
        var encrypted = B64.base64urlDecode(encryptedB64, 'buffer');
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decryptOptions = Hoek.clone(options.encryption);
    decryptOptions.salt = encryptionSalt;

    try {
        decryptOptions.iv = B64.base64urlDecode(encryptionIv, 'buffer');
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decrypted = await exports.decrypt(password.encryption, decryptOptions, encrypted);

    // Parse JSON

    try {
        return Bourne.parse(decrypted);
    }
    catch (err) {
        throw new Boom('Failed parsing sealed object JSON: ' + err.message);
    }
};


internals.stringify = function (object) {

    try {
        return JSON.stringify(object);
    }
    catch (err) {
        throw new Boom('Failed to stringify object: ' + err.message);
    }
};


internals.pbkdf2 = function (...args) {

    return new Promise((resolve, reject) => {

        const next = (err, result) => {

            if (err) {
                return reject(Boom.boomify(err));
            }

            resolve(result);
        };

        args.push(next);
        Crypto.pbkdf2(...args);
    });
};


/***/ }),

/***/ "Cr4G":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.Bench = class {

    constructor() {

        this.ts = 0;
        this.reset();
    }

    reset() {

        this.ts = internals.Bench.now();
    }

    elapsed() {

        return internals.Bench.now() - this.ts;
    }

    static now() {

        const ts = process.hrtime();
        return (ts[0] * 1e3) + (ts[1] / 1e6);
    }
};


/***/ }),

/***/ "D5mk":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

module.exports = object => {
	const result = {};

	for (const [key, value] of Object.entries(object)) {
		result[key.toLowerCase()] = value;
	}

	return result;
};


/***/ }),

/***/ "DWQ6":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Stringify = __webpack_require__("Y7By");


const internals = {};


module.exports = class extends Error {

    constructor(args) {

        const msgs = args
            .filter((arg) => arg !== '')
            .map((arg) => {

                return typeof arg === 'string' ? arg : arg instanceof Error ? arg.message : Stringify(arg);
            });

        super(msgs.join(' ') || 'Unknown error');

        if (typeof Error.captureStackTrace === 'function') {            // $lab:coverage:ignore$
            Error.captureStackTrace(this, exports.assert);
        }
    }
};


/***/ }),

/***/ "E1OP":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {PassThrough} = __webpack_require__("msIP");

module.exports = options => {
	options = Object.assign({}, options);

	const {array} = options;
	let {encoding} = options;
	const buffer = encoding === 'buffer';
	let objectMode = false;

	if (array) {
		objectMode = !(encoding || buffer);
	} else {
		encoding = encoding || 'utf8';
	}

	if (buffer) {
		encoding = null;
	}

	let len = 0;
	const ret = [];
	const stream = new PassThrough({objectMode});

	if (encoding) {
		stream.setEncoding(encoding);
	}

	stream.on('data', chunk => {
		ret.push(chunk);

		if (objectMode) {
			len = ret.length;
		} else {
			len += chunk.length;
		}
	});

	stream.getBufferedValue = () => {
		if (array) {
			return ret;
		}

		return buffer ? Buffer.concat(ret, len) : ret.join('');
	};

	stream.getBufferedLength = () => len;

	return stream;
};


/***/ }),

/***/ "E8LI":
/***/ (function(module, exports, __webpack_require__) {

module.exports = {
  der: __webpack_require__("ZUdF"),
  pem: __webpack_require__("c1/D")
}


/***/ }),

/***/ "E9YA":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("0/Ix");
const Utils = __webpack_require__("f/5Z");


const internals = {
    needsProtoHack: new Set([Types.set, Types.map, Types.weakSet, Types.weakMap])
};


module.exports = internals.clone = function (obj, options = {}, _seen = null) {

    if (typeof obj !== 'object' ||
        obj === null) {

        return obj;
    }

    let clone = internals.clone;
    let seen = _seen;

    if (options.shallow) {
        if (options.shallow !== true) {
            return internals.cloneWithShallow(obj, options);
        }

        clone = (value) => value;
    }
    else {
        seen = seen || new Map();

        const lookup = seen.get(obj);
        if (lookup) {
            return lookup;
        }
    }

    // Built-in object types

    const baseProto = Types.getInternalProto(obj);
    if (baseProto === Types.buffer) {
        return Buffer && Buffer.from(obj);              // $lab:coverage:ignore$
    }

    if (baseProto === Types.date) {
        return new Date(obj.getTime());
    }

    if (baseProto === Types.regex) {
        return new RegExp(obj);
    }

    // Generic objects

    const newObj = internals.base(obj, baseProto, options);
    if (newObj === obj) {
        return obj;
    }

    if (seen) {
        seen.set(obj, newObj);                              // Set seen, since obj could recurse
    }

    if (baseProto === Types.set) {
        for (const value of obj) {
            newObj.add(clone(value, options, seen));
        }
    }
    else if (baseProto === Types.map) {
        for (const [key, value] of obj) {
            newObj.set(key, clone(value, options, seen));
        }
    }

    const keys = Utils.keys(obj, options);
    for (const key of keys) {
        if (key === '__proto__') {
            continue;
        }

        if (baseProto === Types.array &&
            key === 'length') {

            newObj.length = obj.length;
            continue;
        }

        const descriptor = Object.getOwnPropertyDescriptor(obj, key);
        if (descriptor) {
            if (descriptor.get ||
                descriptor.set) {

                Object.defineProperty(newObj, key, descriptor);
            }
            else if (descriptor.enumerable) {
                newObj[key] = clone(obj[key], options, seen);
            }
            else {
                Object.defineProperty(newObj, key, { enumerable: false, writable: true, configurable: true, value: clone(obj[key], options, seen) });
            }
        }
        else {
            Object.defineProperty(newObj, key, {
                enumerable: true,
                writable: true,
                configurable: true,
                value: clone(obj[key], options, seen)
            });
        }
    }

    return newObj;
};


internals.cloneWithShallow = function (source, options) {

    const keys = options.shallow;
    options = Object.assign({}, options);
    options.shallow = false;

    const storage = Utils.store(source, keys);    // Move shallow copy items to storage
    const copy = internals.clone(source, options);      // Deep copy the rest
    Utils.restore(copy, source, storage);         // Shallow copy the stored items and restore
    return copy;
};


internals.base = function (obj, baseProto, options) {

    if (baseProto === Types.array) {
        return [];
    }

    if (options.prototype === false) {                  // Defaults to true
        if (internals.needsProtoHack.has(baseProto)) {
            return new baseProto.constructor();
        }

        return {};
    }

    const proto = Object.getPrototypeOf(obj);
    if (proto &&
        proto.isImmutable) {

        return obj;
    }

    if (internals.needsProtoHack.has(baseProto)) {
        const newObj = new proto.constructor();
        if (proto !== baseProto) {
            Object.setPrototypeOf(newObj, proto);
        }

        return newObj;
    }

    return Object.create(proto);
};


/***/ }),

/***/ "EB1F":
/***/ (function(module, exports) {

module.exports = new Map([
  ['A128CBC-HS256', 256],
  ['A128GCM', 128],
  ['A192CBC-HS384', 384],
  ['A192GCM', 192],
  ['A256CBC-HS512', 512],
  ['A256GCM', 256]
])


/***/ }),

/***/ "ESNE":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("xG1e");


const internals = {};


module.exports = function (attribute) {

    // Allowed value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "

    Assert(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\]*$/.test(attribute), 'Bad attribute value (' + attribute + ')');

    return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');                             // Escape quotes and slash
};


/***/ }),

/***/ "Efly":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (string) {

    // Escape ^$.*+-?=!:|\/()[]{},

    return string.replace(/[\^\$\.\*\+\-\?\=\!\:\|\\\/\(\)\[\]\{\}\,]/g, '\\$&');
};


/***/ }),

/***/ "F/5w":
/***/ (function(module, exports) {

//TODO: handle reviver/dehydrate function like normal
//and handle indentation, like normal.
//if anyone needs this... please send pull request.

exports.stringify = function stringify (o) {
  if('undefined' == typeof o) return o

  if(o && Buffer.isBuffer(o))
    return JSON.stringify(':base64:' + o.toString('base64'))

  if(o && o.toJSON)
    o =  o.toJSON()

  if(o && 'object' === typeof o) {
    var s = ''
    var array = Array.isArray(o)
    s = array ? '[' : '{'
    var first = true

    for(var k in o) {
      var ignore = 'function' == typeof o[k] || (!array && 'undefined' === typeof o[k])
      if(Object.hasOwnProperty.call(o, k) && !ignore) {
        if(!first)
          s += ','
        first = false
        if (array) {
          if(o[k] == undefined)
            s += 'null'
          else
            s += stringify(o[k])
        } else if (o[k] !== void(0)) {
          s += stringify(k) + ':' + stringify(o[k])
        }
      }
    }

    s += array ? ']' : '}'

    return s
  } else if ('string' === typeof o) {
    return JSON.stringify(/^:/.test(o) ? ':' + o : o)
  } else if ('undefined' === typeof o) {
    return 'null';
  } else
    return JSON.stringify(o)
}

exports.parse = function (s) {
  return JSON.parse(s, function (key, value) {
    if('string' === typeof value) {
      if(/^:base64:/.test(value))
        return new Buffer(value.substring(8), 'base64')
      else
        return /^:/.test(value) ? value.substring(1) : value 
    }
    return value
  })
}


/***/ }),

/***/ "F/JS":
/***/ (function(module, exports, __webpack_require__) {

const { deprecate } = __webpack_require__("jK02")

const deprecation = deprecate(() => {}, '"P-256K" EC curve name is deprecated')

module.exports = {
  name: 'secp256k1',
  rename (value) {
    if (value !== 'secp256k1') {
      deprecation()
    }
    module.exports.name = value
  }
}


/***/ }),

/***/ "F4x3":
/***/ (function(module, exports) {

module.exports = (date) => Math.floor(date.getTime() / 1000)


/***/ }),

/***/ "FMKJ":
/***/ (function(module, exports) {

module.exports = require("zlib");

/***/ }),

/***/ "FUB/":
/***/ (function(module, exports, __webpack_require__) {

const { JWKKeySupport, JOSENotSupported } = __webpack_require__("yt7c")
const { KEY_MANAGEMENT_ENCRYPT, KEY_MANAGEMENT_DECRYPT } = __webpack_require__("ehsS")

const { JWA, JWK } = __webpack_require__("N+nT")

// sign, verify
__webpack_require__("IWF7")(JWA, JWK)
__webpack_require__("/sST")(JWA, JWK)
__webpack_require__("MoRj")(JWA, JWK)
__webpack_require__("hnhG")(JWA, JWK)
__webpack_require__("5fWB")(JWA, JWK)
__webpack_require__("w8yO")(JWA)

// encrypt, decrypt
__webpack_require__("d4WF")(JWA, JWK)
__webpack_require__("BJV5")(JWA, JWK)

// wrapKey, unwrapKey
__webpack_require__("hk9D")(JWA, JWK)
__webpack_require__("bUME")(JWA, JWK)
__webpack_require__("xfr8")(JWA, JWK)

// deriveKey
__webpack_require__("q2Us")(JWA, JWK)
__webpack_require__("C/Kw")(JWA, JWK)
__webpack_require__("n8pu")(JWA, JWK)

const check = (key, op, alg) => {
  const cache = `_${op}_${alg}`

  let label
  let keyOp
  if (op === 'keyManagementEncrypt') {
    label = 'key management (encryption)'
    keyOp = KEY_MANAGEMENT_ENCRYPT
  } else if (op === 'keyManagementDecrypt') {
    label = 'key management (decryption)'
    keyOp = KEY_MANAGEMENT_DECRYPT
  }

  if (cache in key) {
    if (key[cache]) {
      return
    }
    throw new JWKKeySupport(`the key does not support ${alg} ${label || op} algorithm`)
  }

  let value = true
  if (!JWA[op].has(alg)) {
    throw new JOSENotSupported(`unsupported ${label || op} alg: ${alg}`)
  } else if (!key.algorithms(keyOp).has(alg)) {
    value = false
  }

  Object.defineProperty(key, cache, { value, enumerable: false })

  if (!value) {
    return check(key, op, alg)
  }
}

module.exports = {
  check,
  sign: (alg, key, payload) => {
    check(key, 'sign', alg)
    return JWA.sign.get(alg)(key, payload)
  },
  verify: (alg, key, payload, signature) => {
    check(key, 'verify', alg)
    return JWA.verify.get(alg)(key, payload, signature)
  },
  keyManagementEncrypt: (alg, key, payload, opts) => {
    check(key, 'keyManagementEncrypt', alg)
    return JWA.keyManagementEncrypt.get(alg)(key, payload, opts)
  },
  keyManagementDecrypt: (alg, key, payload, opts) => {
    check(key, 'keyManagementDecrypt', alg)
    return JWA.keyManagementDecrypt.get(alg)(key, payload, opts)
  },
  encrypt: (alg, key, cleartext, opts) => {
    check(key, 'encrypt', alg)
    return JWA.encrypt.get(alg)(key, cleartext, opts)
  },
  decrypt: (alg, key, ciphertext, opts) => {
    check(key, 'decrypt', alg)
    return JWA.decrypt.get(alg)(key, ciphertext, opts)
  }
}


/***/ }),

/***/ "FURP":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Stringify = __webpack_require__("VHkT");


const internals = {};


module.exports = class extends Error {

    constructor(args) {

        const msgs = args
            .filter((arg) => arg !== '')
            .map((arg) => {

                return typeof arg === 'string' ? arg : arg instanceof Error ? arg.message : Stringify(arg);
            });

        super(msgs.join(' ') || 'Unknown error');

        if (typeof Error.captureStackTrace === 'function') {            // $lab:coverage:ignore$
            Error.captureStackTrace(this, exports.assert);
        }
    }
};


/***/ }),

/***/ "Fo+H":
/***/ (function(module, exports) {

module.exports = {
  sign: new Map(),
  verify: new Map(),
  keyManagementEncrypt: new Map(),
  keyManagementDecrypt: new Map(),
  encrypt: new Map(),
  decrypt: new Map()
}


/***/ }),

/***/ "Fp5f":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("zjbl");


const internals = {};


module.exports = function (obj, template, options) {

    return template.replace(/{([^}]+)}/g, ($0, chain) => {

        const value = Reach(obj, chain, options);
        return (value === undefined || value === null ? '' : value);
    });
};


/***/ }),

/***/ "Fssn":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("q4ve");
const Clone = __webpack_require__("W5Ll");
const Utils = __webpack_require__("jvMF");


const internals = {};


module.exports = internals.merge = function (target, source, options) {

    Assert(target && typeof target === 'object', 'Invalid target value: must be an object');
    Assert(source === null || source === undefined || typeof source === 'object', 'Invalid source value: must be null, undefined, or an object');

    if (!source) {
        return target;
    }

    options = Object.assign({ nullOverride: true, mergeArrays: true }, options);

    if (Array.isArray(source)) {
        Assert(Array.isArray(target), 'Cannot merge array onto an object');
        if (!options.mergeArrays) {
            target.length = 0;                                                          // Must not change target assignment
        }

        for (let i = 0; i < source.length; ++i) {
            target.push(Clone(source[i], { symbols: options.symbols }));
        }

        return target;
    }

    const keys = Utils.keys(source, options);
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (key === '__proto__' ||
            !Object.prototype.propertyIsEnumerable.call(source, key)) {

            continue;
        }

        const value = source[key];
        if (value &&
            typeof value === 'object') {

            if (!target[key] ||
                typeof target[key] !== 'object' ||
                (Array.isArray(target[key]) !== Array.isArray(value)) ||
                value instanceof Date ||
                (Buffer && Buffer.isBuffer(value)) ||               // $lab:coverage:ignore$
                value instanceof RegExp) {

                target[key] = Clone(value, { symbols: options.symbols });
            }
            else {
                internals.merge(target[key], value, options);
            }
        }
        else {
            if (value !== null &&
                value !== undefined) {                              // Explicit to preserve empty strings

                target[key] = value;
            }
            else if (options.nullOverride) {
                target[key] = value;
            }
        }
    }

    return target;
};


/***/ }),

/***/ "GFHV":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable no-restricted-syntax, no-param-reassign, no-continue */

const isPlainObject = __webpack_require__("5j3D");

function merge(target, ...sources) {
  for (const source of sources) {
    if (!isPlainObject(source)) {
      continue;
    }
    for (const [key, value] of Object.entries(source)) {
      /* istanbul ignore if */
      if (key === '__proto__' || key === 'constructor') {
        continue;
      }
      if (isPlainObject(target[key]) && isPlainObject(value)) {
        target[key] = merge(target[key], value);
      } else if (typeof value !== 'undefined') {
        target[key] = value;
      }
    }
  }

  return target;
}

module.exports = merge;


/***/ }),

/***/ "GX0O":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);

    

    /* harmony default export */ __webpack_exports__["default"] = (function (ctx) {
      return Promise.all([])
    });
  

/***/ }),

/***/ "GhER":
/***/ (function(module, exports, __webpack_require__) {

const { deprecate } = __webpack_require__("jK02")

const { createPublicKey, createPrivateKey, createSecretKey, KeyObject } = __webpack_require__("1ALl")
const base64url = __webpack_require__("Xab3")
const isObject = __webpack_require__("kF1/")
const { jwkToPem } = __webpack_require__("gXwc")
const errors = __webpack_require__("yt7c")

const RSAKey = __webpack_require__("RoCg")
const ECKey = __webpack_require__("3HlQ")
const OKPKey = __webpack_require__("vC2k")
const OctKey = __webpack_require__("BBt9")

const importable = new Set(['string', 'buffer', 'object'])

const mergedParameters = (target = {}, source = {}) => {
  return {
    alg: source.alg,
    key_ops: source.key_ops,
    kid: source.kid,
    use: source.use,
    x5c: source.x5c,
    x5t: source.x5t,
    'x5t#S256': source['x5t#S256'],
    ...target
  }
}

const openSSHpublicKey = /^[a-zA-Z0-9-]+ AAAA(?:[0-9A-Za-z+/])+(?:==|=)?(?: .*)?$/

const asKey = (key, parameters, { calculateMissingRSAPrimes = false } = {}) => {
  let privateKey, publicKey, secret

  if (!importable.has(typeof key)) {
    throw new TypeError('key argument must be a string, buffer or an object')
  }

  if (parameters !== undefined && !isObject(parameters)) {
    throw new TypeError('parameters argument must be a plain object when provided')
  }

  if (key instanceof KeyObject) {
    switch (key.type) {
      case 'private':
        privateKey = key
        break
      case 'public':
        publicKey = key
        break
      case 'secret':
        secret = key
        break
    }
  } else if (typeof key === 'object' && key && 'kty' in key && key.kty === 'oct') { // symmetric key <Object>
    try {
      secret = createSecretKey(base64url.decodeToBuffer(key.k))
    } catch (err) {
      if (!('k' in key)) {
        secret = { type: 'secret' }
      }
    }
    parameters = mergedParameters(parameters, key)
  } else if (typeof key === 'object' && key && 'kty' in key) { // assume JWK formatted asymmetric key <Object>
    ({ calculateMissingRSAPrimes = false } = parameters || { calculateMissingRSAPrimes })
    let pem

    try {
      pem = jwkToPem(key, { calculateMissingRSAPrimes })
    } catch (err) {
      if (err instanceof errors.JOSEError) {
        throw err
      }
    }

    if (pem && key.d) {
      privateKey = createPrivateKey(pem)
    } else if (pem) {
      publicKey = createPublicKey(pem)
    }

    parameters = mergedParameters({}, key)
  } else if (key && (typeof key === 'object' || typeof key === 'string')) { // <Object> | <string> | <Buffer> passed to crypto.createPrivateKey or crypto.createPublicKey or <Buffer> passed to crypto.createSecretKey
    try {
      privateKey = createPrivateKey(key)
    } catch (err) {
      if (err instanceof errors.JOSEError) {
        throw err
      }
    }

    try {
      publicKey = createPublicKey(key)
      if (key.startsWith('-----BEGIN CERTIFICATE-----') && (!parameters || !('x5c' in parameters))) {
        parameters = mergedParameters(parameters, {
          x5c: [key.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '')]
        })
      }
    } catch (err) {
      if (err instanceof errors.JOSEError) {
        throw err
      }
    }

    try {
      // this is to filter out invalid PEM keys and certs, i'll rather have them fail import then
      // have them imported as symmetric "oct" keys
      if (!key.includes('-----BEGIN') && !openSSHpublicKey.test(key.toString('ascii').replace(/[\r\n]/g, ''))) {
        secret = createSecretKey(Buffer.isBuffer(key) ? key : Buffer.from(key))
      }
    } catch (err) {}
  }

  const keyObject = privateKey || publicKey || secret

  if (privateKey || publicKey) {
    switch (keyObject.asymmetricKeyType) {
      case 'rsa':
        return new RSAKey(keyObject, parameters)
      case 'ec':
        return new ECKey(keyObject, parameters)
      case 'ed25519':
      case 'ed448':
      case 'x25519':
      case 'x448':
        return new OKPKey(keyObject, parameters)
      default:
        throw new errors.JOSENotSupported('only RSA, EC and OKP asymmetric keys are supported')
    }
  } else if (secret) {
    return new OctKey(keyObject, parameters)
  }

  throw new errors.JWKImportFailed('key import failed')
}

module.exports = asKey
Object.defineProperty(asKey, 'deprecated', {
  value: deprecate((key, parameters) => { return asKey(key, parameters, { calculateMissingRSAPrimes: true }) }, 'JWK.importKey() is deprecated, use JWK.asKey() instead'),
  enumerable: false
})


/***/ }),

/***/ "HKOu":
/***/ (function(module, exports, __webpack_require__) {

const oids = __webpack_require__("ScBA")

module.exports = function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).optional().choice({ namedCurve: this.objid(oids) }),
    this.key('publicKey').explicit(1).optional().bitstr()
  )
}


/***/ }),

/***/ "HpSD":
/***/ (function(module, exports) {

// Credit: https://github.com/rohe/pyoidc/blob/master/src/oic/utils/webfinger.py

// -- Normalization --
// A string of any other type is interpreted as a URI either the form of scheme
// "://" authority path-abempty [ "?" query ] [ "#" fragment ] or authority
// path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986] and is
// normalized according to the following rules:
//
// If the user input Identifier does not have an RFC 3986 [RFC3986] scheme
// portion, the string is interpreted as [userinfo "@"] host [":" port]
// path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986].
// If the userinfo component is present and all of the path component, query
// component, and port component are empty, the acct scheme is assumed. In this
// case, the normalized URI is formed by prefixing acct: to the string as the
// scheme. Per the 'acct' URI Scheme [I‑D.ietf‑appsawg‑acct‑uri], if there is an
// at-sign character ('@') in the userinfo component, it needs to be
// percent-encoded as described in RFC 3986 [RFC3986].
// For all other inputs without a scheme portion, the https scheme is assumed,
// and the normalized URI is formed by prefixing https:// to the string as the
// scheme.
// If the resulting URI contains a fragment portion, it MUST be stripped off
// together with the fragment delimiter character "#".
// The WebFinger [I‑D.ietf‑appsawg‑webfinger] Resource in this case is the
// resulting URI, and the WebFinger Host is the authority component.
//
// Note: Since the definition of authority in RFC 3986 [RFC3986] is
// [ userinfo "@" ] host [ ":" port ], it is legal to have a user input
// identifier like userinfo@host:port, e.g., alice@example.com:8080.

const PORT = /^\d+$/;

function hasScheme(input) {
  if (input.includes('://')) return true;

  const authority = input.replace(/(\/|\?)/g, '#').split('#')[0];
  if (authority.includes(':')) {
    const index = authority.indexOf(':');
    const hostOrPort = authority.slice(index + 1);
    if (!PORT.test(hostOrPort)) {
      return true;
    }
  }

  return false;
}

function acctSchemeAssumed(input) {
  if (!input.includes('@')) return false;
  const parts = input.split('@');
  const host = parts[parts.length - 1];
  return !(host.includes(':') || host.includes('/') || host.includes('?'));
}

function normalize(input) {
  if (typeof input !== 'string') {
    throw new TypeError('input must be a string');
  }

  let output;
  if (hasScheme(input)) {
    output = input;
  } else if (acctSchemeAssumed(input)) {
    output = `acct:${input}`;
  } else {
    output = `https://${input}`;
  }

  return output.split('#')[0];
}

module.exports = normalize;


/***/ }),

/***/ "HrFp":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable max-classes-per-file */

const { inspect, deprecate } = __webpack_require__("jK02");
const stdhttp = __webpack_require__("KEll");
const crypto = __webpack_require__("PJMN");
const { strict: assert } = __webpack_require__("Qs3B");
const querystring = __webpack_require__("8xkj");
const url = __webpack_require__("bzos");

const { ParseError } = __webpack_require__("AfMj");
const jose = __webpack_require__("xZSz");
const base64url = __webpack_require__("+00W");
const tokenHash = __webpack_require__("ZfBq");

const defaults = __webpack_require__("M0E0");
const { assertSigningAlgValuesSupport, assertIssuerConfiguration } = __webpack_require__("N+si");
const pick = __webpack_require__("LZmR");
const isPlainObject = __webpack_require__("5j3D");
const processResponse = __webpack_require__("WeJA");
const TokenSet = __webpack_require__("IgmS");
const { OPError, RPError } = __webpack_require__("L71r");
const now = __webpack_require__("PbSP");
const { random } = __webpack_require__("iAgo");
const request = __webpack_require__("UwMm");
const {
  CALLBACK_PROPERTIES, CLIENT_DEFAULTS, JWT_CONTENT, CLOCK_TOLERANCE,
} = __webpack_require__("TJm8");
const issuerRegistry = __webpack_require__("0Aai");
const instance = __webpack_require__("0pkK");
const { authenticatedPost, resolveResponseType, resolveRedirectUri } = __webpack_require__("/JKO");
const DeviceFlowHandle = __webpack_require__("LMPv");

const { deep: defaultsDeep } = defaults;

function pickCb(input) {
  return pick(input, ...CALLBACK_PROPERTIES);
}

function authorizationHeaderValue(token, tokenType = 'Bearer') {
  return `${tokenType} ${token}`;
}

function cleanUpClaims(claims) {
  if (Object.keys(claims._claim_names).length === 0) {
    delete claims._claim_names;
  }
  if (Object.keys(claims._claim_sources).length === 0) {
    delete claims._claim_sources;
  }
}

function assignClaim(target, source, sourceName, throwOnMissing = true) {
  return ([claim, inSource]) => {
    if (inSource === sourceName) {
      if (throwOnMissing && source[claim] === undefined) {
        throw new RPError(`expected claim "${claim}" in "${sourceName}"`);
      } else if (source[claim] !== undefined) {
        target[claim] = source[claim];
      }
      delete target._claim_names[claim];
    }
  };
}

function verifyPresence(payload, jwt, prop) {
  if (payload[prop] === undefined) {
    throw new RPError({
      message: `missing required JWT property ${prop}`,
      jwt,
    });
  }
}

function authorizationParams(params) {
  const authParams = {
    client_id: this.client_id,
    scope: 'openid',
    response_type: resolveResponseType.call(this),
    redirect_uri: resolveRedirectUri.call(this),
    ...params,
  };

  Object.entries(authParams).forEach(([key, value]) => {
    if (value === null || value === undefined) {
      delete authParams[key];
    } else if (key === 'claims' && typeof value === 'object') {
      authParams[key] = JSON.stringify(value);
    } else if (key === 'resource' && Array.isArray(value)) {
      authParams[key] = value;
    } else if (typeof value !== 'string') {
      authParams[key] = String(value);
    }
  });

  return authParams;
}

async function claimJWT(label, jwt) {
  try {
    const { header, payload } = jose.JWT.decode(jwt, { complete: true });
    const { iss } = payload;

    if (header.alg === 'none') {
      return payload;
    }

    let key;
    if (!iss || iss === this.issuer.issuer) {
      key = await this.issuer.queryKeyStore(header);
    } else if (issuerRegistry.has(iss)) {
      key = await issuerRegistry.get(iss).queryKeyStore(header);
    } else {
      const discovered = await this.issuer.constructor.discover(iss);
      key = await discovered.queryKeyStore(header);
    }
    return jose.JWT.verify(jwt, key);
  } catch (err) {
    if (err instanceof RPError || err instanceof OPError || err.name === 'AggregateError') {
      throw err;
    } else {
      throw new RPError({
        printf: ['failed to validate the %s JWT (%s: %s)', label, err.name, err.message],
        jwt,
      });
    }
  }
}

function getKeystore(jwks) {
  const keystore = jose.JWKS.asKeyStore(jwks);
  if (keystore.all().some((key) => key.type !== 'private')) {
    throw new TypeError('jwks must only contain private keys');
  }
  return keystore;
}

// if an OP doesnt support client_secret_basic but supports client_secret_post, use it instead
// this is in place to take care of most common pitfalls when first using discovered Issuers without
// the support for default values defined by Discovery 1.0
function checkBasicSupport(client, metadata, properties) {
  try {
    const supported = client.issuer.token_endpoint_auth_methods_supported;
    if (!supported.includes(properties.token_endpoint_auth_method)) {
      if (supported.includes('client_secret_post')) {
        properties.token_endpoint_auth_method = 'client_secret_post';
      }
    }
  } catch (err) {}
}

function handleCommonMistakes(client, metadata, properties) {
  if (!metadata.token_endpoint_auth_method) { // if no explicit value was provided
    checkBasicSupport(client, metadata, properties);
  }

  // :fp: c'mon people... RTFM
  if (metadata.redirect_uri) {
    if (metadata.redirect_uris) {
      throw new TypeError('provide a redirect_uri or redirect_uris, not both');
    }
    properties.redirect_uris = [metadata.redirect_uri];
    delete properties.redirect_uri;
  }

  if (metadata.response_type) {
    if (metadata.response_types) {
      throw new TypeError('provide a response_type or response_types, not both');
    }
    properties.response_types = [metadata.response_type];
    delete properties.response_type;
  }
}

function getDefaultsForEndpoint(endpoint, issuer, properties) {
  if (!issuer[`${endpoint}_endpoint`]) return;

  const tokenEndpointAuthMethod = properties.token_endpoint_auth_method;
  const tokenEndpointAuthSigningAlg = properties.token_endpoint_auth_signing_alg;

  const eam = `${endpoint}_endpoint_auth_method`;
  const easa = `${endpoint}_endpoint_auth_signing_alg`;

  if (properties[eam] === undefined && properties[easa] === undefined) {
    if (tokenEndpointAuthMethod !== undefined) {
      properties[eam] = tokenEndpointAuthMethod;
    }
    if (tokenEndpointAuthSigningAlg !== undefined) {
      properties[easa] = tokenEndpointAuthSigningAlg;
    }
  }
}

class BaseClient {}

module.exports = (issuer, aadIssValidation = false) => class Client extends BaseClient {
  /**
   * @name constructor
   * @api public
   */
  constructor(metadata = {}, jwks, options) {
    super();

    if (typeof metadata.client_id !== 'string' || !metadata.client_id) {
      throw new TypeError('client_id is required');
    }

    const properties = { ...CLIENT_DEFAULTS, ...metadata };

    handleCommonMistakes(this, metadata, properties);

    assertSigningAlgValuesSupport('token', this.issuer, properties);

    ['introspection', 'revocation'].forEach((endpoint) => {
      getDefaultsForEndpoint(endpoint, this.issuer, properties);
      assertSigningAlgValuesSupport(endpoint, this.issuer, properties);
    });

    Object.entries(properties).forEach(([key, value]) => {
      instance(this).get('metadata').set(key, value);
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() { return instance(this).get('metadata').get(key); },
          enumerable: true,
        });
      }
    });

    if (jwks !== undefined) {
      const keystore = getKeystore.call(this, jwks);
      instance(this).set('keystore', keystore);
    }

    if (options !== undefined) {
      instance(this).set('options', options);
    }

    this[CLOCK_TOLERANCE] = 0;
  }

  /**
   * @name authorizationUrl
   * @api public
   */
  authorizationUrl(params = {}) {
    if (!isPlainObject(params)) {
      throw new TypeError('params must be a plain object');
    }
    assertIssuerConfiguration(this.issuer, 'authorization_endpoint');
    const target = url.parse(this.issuer.authorization_endpoint, true);
    target.search = null;
    target.query = {
      ...target.query,
      ...authorizationParams.call(this, params),
    };
    return url.format(target);
  }

  /**
   * @name authorizationPost
   * @api public
   */
  authorizationPost(params = {}) {
    if (!isPlainObject(params)) {
      throw new TypeError('params must be a plain object');
    }
    const inputs = authorizationParams.call(this, params);
    const formInputs = Object.keys(inputs)
      .map((name) => `<input type="hidden" name="${name}" value="${inputs[name]}"/>`).join('\n');

    return `<!DOCTYPE html>
<head>
  <title>Requesting Authorization</title>
</head>
<body onload="javascript:document.forms[0].submit()">
  <form method="post" action="${this.issuer.authorization_endpoint}">
    ${formInputs}
  </form>
</body>
</html>`;
  }

  /**
   * @name endSessionUrl
   * @api public
   */
  endSessionUrl(params = {}) {
    assertIssuerConfiguration(this.issuer, 'end_session_endpoint');

    const {
      0: postLogout,
      length,
    } = this.post_logout_redirect_uris || [];

    const {
      post_logout_redirect_uri = length === 1 ? postLogout : undefined,
    } = params;

    let hint = params.id_token_hint;

    if (hint instanceof TokenSet) {
      if (!hint.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      hint = hint.id_token;
    }

    const target = url.parse(this.issuer.end_session_endpoint, true);
    target.search = null;
    target.query = {
      ...params,
      ...target.query,
      ...{
        post_logout_redirect_uri,
        id_token_hint: hint,
      },
    };

    Object.entries(target.query).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        delete target.query[key];
      }
    });

    return url.format(target);
  }

  /**
   * @name callbackParams
   * @api public
   */
  callbackParams(input) { // eslint-disable-line class-methods-use-this
    const isIncomingMessage = input instanceof stdhttp.IncomingMessage
      || (input && input.method && input.url);
    const isString = typeof input === 'string';

    if (!isString && !isIncomingMessage) {
      throw new TypeError('#callbackParams only accepts string urls, http.IncomingMessage or a lookalike');
    }

    if (isIncomingMessage) {
      switch (input.method) {
        case 'GET':
          return pickCb(url.parse(input.url, true).query);
        case 'POST':
          if (input.body === undefined) {
            throw new TypeError('incoming message body missing, include a body parser prior to this method call');
          }
          switch (typeof input.body) {
            case 'object':
            case 'string':
              if (Buffer.isBuffer(input.body)) {
                return pickCb(querystring.parse(input.body.toString('utf-8')));
              }
              if (typeof input.body === 'string') {
                return pickCb(querystring.parse(input.body));
              }

              return pickCb(input.body);
            default:
              throw new TypeError('invalid IncomingMessage body object');
          }
        default:
          throw new TypeError('invalid IncomingMessage method');
      }
    } else {
      return pickCb(url.parse(input, true).query);
    }
  }

  /**
   * @name callback
   * @api public
   */
  async callback(
    redirectUri,
    parameters,
    checks = {},
    { exchangeBody, clientAssertionPayload } = {},
  ) {
    let params = pickCb(parameters);

    if (checks.jarm && !('response' in parameters)) {
      throw new RPError({
        message: 'expected a JARM response',
        checks,
        params,
      });
    } else if ('response' in parameters) {
      const decrypted = await this.decryptJARM(params.response);
      params = await this.validateJARM(decrypted);
    }

    if (this.default_max_age && !checks.max_age) {
      checks.max_age = this.default_max_age;
    }

    if (params.state && !checks.state) {
      throw new TypeError('checks.state argument is missing');
    }

    if (!params.state && checks.state) {
      throw new RPError({
        message: 'state missing from the response',
        checks,
        params,
      });
    }

    if (checks.state !== params.state) {
      throw new RPError({
        printf: ['state mismatch, expected %s, got: %s', checks.state, params.state],
        checks,
        params,
      });
    }

    if (params.error) {
      throw new OPError(params);
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      id_token: ['id_token'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) { // eslint-disable-line no-restricted-syntax
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            throw new RPError({
              message: 'unexpected params encountered for "none" response',
              checks,
              params,
            });
          }
        } else {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) { // eslint-disable-line no-restricted-syntax, max-len
            if (!params[param]) {
              throw new RPError({
                message: `${param} missing from response`,
                checks,
                params,
              });
            }
          }
        }
      }
    }

    if (params.id_token) {
      const tokenset = new TokenSet(params);
      await this.decryptIdToken(tokenset);
      await this.validateIdToken(tokenset, checks.nonce, 'authorization', checks.max_age, checks.state);

      if (!params.code) {
        return tokenset;
      }
    }

    if (params.code) {
      const tokenset = await this.grant({
        ...exchangeBody,
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: redirectUri,
        code_verifier: checks.code_verifier,
      }, { clientAssertionPayload });

      await this.decryptIdToken(tokenset);
      await this.validateIdToken(tokenset, checks.nonce, 'token', checks.max_age);

      if (params.session_state) {
        tokenset.session_state = params.session_state;
      }

      return tokenset;
    }

    return new TokenSet(params);
  }

  /**
   * @name oauthCallback
   * @api public
   */
  async oauthCallback(
    redirectUri,
    parameters,
    checks = {},
    { exchangeBody, clientAssertionPayload } = {},
  ) {
    let params = pickCb(parameters);

    if (checks.jarm && !('response' in parameters)) {
      throw new RPError({
        message: 'expected a JARM response',
        checks,
        params,
      });
    } else if ('response' in parameters) {
      const decrypted = await this.decryptJARM(params.response);
      params = await this.validateJARM(decrypted);
    }

    if (params.state && !checks.state) {
      throw new TypeError('checks.state argument is missing');
    }

    if (!params.state && checks.state) {
      throw new RPError({
        message: 'state missing from the response',
        checks,
        params,
      });
    }

    if (checks.state !== params.state) {
      throw new RPError({
        printf: ['state mismatch, expected %s, got: %s', checks.state, params.state],
        checks,
        params,
      });
    }

    if (params.error) {
      throw new OPError(params);
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) { // eslint-disable-line no-restricted-syntax
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            throw new RPError({
              message: 'unexpected params encountered for "none" response',
              checks,
              params,
            });
          }
        }

        if (RESPONSE_TYPE_REQUIRED_PARAMS[type]) {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) { // eslint-disable-line no-restricted-syntax, max-len
            if (!params[param]) {
              throw new RPError({
                message: `${param} missing from response`,
                checks,
                params,
              });
            }
          }
        }
      }
    }

    if (params.code) {
      return this.grant({
        ...exchangeBody,
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: redirectUri,
        code_verifier: checks.code_verifier,
      }, { clientAssertionPayload });
    }

    return new TokenSet(params);
  }

  /**
   * @name decryptIdToken
   * @api private
   */
  async decryptIdToken(token) {
    if (!this.id_token_encrypted_response_alg) {
      return token;
    }

    let idToken = token;

    if (idToken instanceof TokenSet) {
      if (!idToken.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      idToken = idToken.id_token;
    }

    const expectedAlg = this.id_token_encrypted_response_alg;
    const expectedEnc = this.id_token_encrypted_response_enc;

    const result = await this.decryptJWE(idToken, expectedAlg, expectedEnc);

    if (token instanceof TokenSet) {
      token.id_token = result;
      return token;
    }

    return result;
  }

  async validateJWTUserinfo(body) {
    const expectedAlg = this.userinfo_signed_response_alg;

    return this.validateJWT(body, expectedAlg, []);
  }

  /**
   * @name decryptJARM
   * @api private
   */
  async decryptJARM(response) {
    if (!this.authorization_encrypted_response_alg) {
      return response;
    }

    const expectedAlg = this.authorization_encrypted_response_alg;
    const expectedEnc = this.authorization_encrypted_response_enc;

    return this.decryptJWE(response, expectedAlg, expectedEnc);
  }

  /**
   * @name validateJARM
   * @api private
   */
  async validateJARM(response) {
    const expectedAlg = this.authorization_signed_response_alg;
    const { payload } = await this.validateJWT(response, expectedAlg, ['iss', 'exp', 'aud']);
    return pickCb(payload);
  }

  /**
   * @name decryptJWTUserinfo
   * @api private
   */
  async decryptJWTUserinfo(body) {
    if (!this.userinfo_encrypted_response_alg) {
      return body;
    }

    const expectedAlg = this.userinfo_encrypted_response_alg;
    const expectedEnc = this.userinfo_encrypted_response_enc;

    return this.decryptJWE(body, expectedAlg, expectedEnc);
  }

  /**
   * @name decryptJWE
   * @api private
   */
  async decryptJWE(jwe, expectedAlg, expectedEnc = 'A128CBC-HS256') {
    const header = JSON.parse(base64url.decode(jwe.split('.')[0]));

    if (header.alg !== expectedAlg) {
      throw new RPError({
        printf: ['unexpected JWE alg received, expected %s, got: %s', expectedAlg, header.alg],
        jwt: jwe,
      });
    }

    if (header.enc !== expectedEnc) {
      throw new RPError({
        printf: ['unexpected JWE enc received, expected %s, got: %s', expectedEnc, header.enc],
        jwt: jwe,
      });
    }

    let keyOrStore;

    if (expectedAlg.match(/^(?:RSA|ECDH)/)) {
      keyOrStore = instance(this).get('keystore');
    } else {
      keyOrStore = await this.joseSecret(expectedAlg === 'dir' ? expectedEnc : expectedAlg);
    }

    const payload = jose.JWE.decrypt(jwe, keyOrStore);
    return payload.toString('utf8');
  }

  /**
   * @name validateIdToken
   * @api private
   */
  async validateIdToken(tokenSet, nonce, returnedBy, maxAge, state) {
    let idToken = tokenSet;

    const expectedAlg = this.id_token_signed_response_alg;

    const isTokenSet = idToken instanceof TokenSet;

    if (isTokenSet) {
      if (!idToken.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      idToken = idToken.id_token;
    }

    idToken = String(idToken);

    const timestamp = now();
    const { protected: header, payload, key } = await this.validateJWT(idToken, expectedAlg);

    if (maxAge || (maxAge !== null && this.require_auth_time)) {
      if (!payload.auth_time) {
        throw new RPError({
          message: 'missing required JWT property auth_time',
          jwt: idToken,
        });
      }
      if (typeof payload.auth_time !== 'number') {
        throw new RPError({
          message: 'JWT auth_time claim must be a JSON numeric value',
          jwt: idToken,
        });
      }
    }

    if (maxAge && (payload.auth_time + maxAge < timestamp - this[CLOCK_TOLERANCE])) {
      throw new RPError({
        printf: ['too much time has elapsed since the last End-User authentication, max_age %i, auth_time: %i, now %i', maxAge, payload.auth_time, timestamp - this[CLOCK_TOLERANCE]],
        now: timestamp,
        tolerance: this[CLOCK_TOLERANCE],
        auth_time: payload.auth_time,
        jwt: idToken,
      });
    }

    if (nonce !== null && (payload.nonce || nonce !== undefined) && payload.nonce !== nonce) {
      throw new RPError({
        printf: ['nonce mismatch, expected %s, got: %s', nonce, payload.nonce],
        jwt: idToken,
      });
    }

    if (returnedBy === 'authorization') {
      if (!payload.at_hash && tokenSet.access_token) {
        throw new RPError({
          message: 'missing required property at_hash',
          jwt: idToken,
        });
      }

      if (!payload.c_hash && tokenSet.code) {
        throw new RPError({
          message: 'missing required property c_hash',
          jwt: idToken,
        });
      }

      const fapi = this.constructor.name === 'FAPIClient';

      if (fapi) {
        if (payload.iat < timestamp - 3600) {
          throw new RPError({
            printf: ['JWT issued too far in the past, now %i, iat %i', timestamp, payload.iat],
            now: timestamp,
            tolerance: this[CLOCK_TOLERANCE],
            iat: payload.iat,
            jwt: idToken,
          });
        }

        if (!payload.s_hash && (tokenSet.state || state)) {
          throw new RPError({
            message: 'missing required property s_hash',
            jwt: idToken,
          });
        }
      }

      if (payload.s_hash) {
        if (!state) {
          throw new TypeError('cannot verify s_hash, "checks.state" property not provided');
        }

        try {
          tokenHash.validate({ claim: 's_hash', source: 'state' }, payload.s_hash, state, header.alg, key && key.crv);
        } catch (err) {
          throw new RPError({ message: err.message, jwt: idToken });
        }
      }
    }

    if (tokenSet.access_token && payload.at_hash !== undefined) {
      try {
        tokenHash.validate({ claim: 'at_hash', source: 'access_token' }, payload.at_hash, tokenSet.access_token, header.alg, key && key.crv);
      } catch (err) {
        throw new RPError({ message: err.message, jwt: idToken });
      }
    }

    if (tokenSet.code && payload.c_hash !== undefined) {
      try {
        tokenHash.validate({ claim: 'c_hash', source: 'code' }, payload.c_hash, tokenSet.code, header.alg, key && key.crv);
      } catch (err) {
        throw new RPError({ message: err.message, jwt: idToken });
      }
    }

    return tokenSet;
  }

  /**
   * @name validateJWT
   * @api private
   */
  async validateJWT(jwt, expectedAlg, required = ['iss', 'sub', 'aud', 'exp', 'iat']) {
    const isSelfIssued = this.issuer.issuer === 'https://self-issued.me';
    const timestamp = now();
    let header;
    let payload;
    try {
      ({ header, payload } = jose.JWT.decode(jwt, { complete: true }));
    } catch (err) {
      throw new RPError({
        printf: ['failed to decode JWT (%s: %s)', err.name, err.message],
        jwt,
      });
    }

    if (header.alg !== expectedAlg) {
      throw new RPError({
        printf: ['unexpected JWT alg received, expected %s, got: %s', expectedAlg, header.alg],
        jwt,
      });
    }

    if (isSelfIssued) {
      required = [...required, 'sub_jwk']; // eslint-disable-line no-param-reassign
    }

    required.forEach(verifyPresence.bind(undefined, payload, jwt));

    if (payload.iss !== undefined) {
      let expectedIss = this.issuer.issuer;

      if (aadIssValidation) {
        expectedIss = this.issuer.issuer.replace('{tenantid}', payload.tid);
      }

      if (payload.iss !== expectedIss) {
        throw new RPError({
          printf: ['unexpected iss value, expected %s, got: %s', expectedIss, payload.iss],
          jwt,
        });
      }
    }

    if (payload.iat !== undefined) {
      if (typeof payload.iat !== 'number') {
        throw new RPError({
          message: 'JWT iat claim must be a JSON numeric value',
          jwt,
        });
      }
    }

    if (payload.nbf !== undefined) {
      if (typeof payload.nbf !== 'number') {
        throw new RPError({
          message: 'JWT nbf claim must be a JSON numeric value',
          jwt,
        });
      }
      if (payload.nbf > timestamp + this[CLOCK_TOLERANCE]) {
        throw new RPError({
          printf: ['JWT not active yet, now %i, nbf %i', timestamp + this[CLOCK_TOLERANCE], payload.nbf],
          now: timestamp,
          tolerance: this[CLOCK_TOLERANCE],
          nbf: payload.nbf,
          jwt,
        });
      }
    }

    if (payload.exp !== undefined) {
      if (typeof payload.exp !== 'number') {
        throw new RPError({
          message: 'JWT exp claim must be a JSON numeric value',
          jwt,
        });
      }
      if (timestamp - this[CLOCK_TOLERANCE] >= payload.exp) {
        throw new RPError({
          printf: ['JWT expired, now %i, exp %i', timestamp - this[CLOCK_TOLERANCE], payload.exp],
          now: timestamp,
          tolerance: this[CLOCK_TOLERANCE],
          exp: payload.exp,
          jwt,
        });
      }
    }

    if (payload.aud !== undefined) {
      if (Array.isArray(payload.aud)) {
        if (payload.aud.length > 1 && !payload.azp) {
          throw new RPError({
            message: 'missing required JWT property azp',
            jwt,
          });
        }

        if (!payload.aud.includes(this.client_id)) {
          throw new RPError({
            printf: ['aud is missing the client_id, expected %s to be included in %j', this.client_id, payload.aud],
            jwt,
          });
        }
      } else if (payload.aud !== this.client_id) {
        throw new RPError({
          printf: ['aud mismatch, expected %s, got: %s', this.client_id, payload.aud],
          jwt,
        });
      }
    }

    if (payload.azp !== undefined) {
      let { additionalAuthorizedParties } = instance(this).get('options') || {};

      if (typeof additionalAuthorizedParties === 'string') {
        additionalAuthorizedParties = [this.client_id, additionalAuthorizedParties];
      } else if (Array.isArray(additionalAuthorizedParties)) {
        additionalAuthorizedParties = [this.client_id, ...additionalAuthorizedParties];
      } else {
        additionalAuthorizedParties = [this.client_id];
      }

      if (!additionalAuthorizedParties.includes(payload.azp)) {
        throw new RPError({
          printf: ['azp mismatch, got: %s', payload.azp],
          jwt,
        });
      }
    }

    let key;

    if (isSelfIssued) {
      try {
        assert(isPlainObject(payload.sub_jwk));
        key = jose.JWK.asKey(payload.sub_jwk);
        assert.equal(key.type, 'public');
      } catch (err) {
        throw new RPError({
          message: 'failed to use sub_jwk claim as an asymmetric JSON Web Key',
          jwt,
        });
      }
      if (key.thumbprint !== payload.sub) {
        throw new RPError({
          message: 'failed to match the subject with sub_jwk',
          jwt,
        });
      }
    } else if (header.alg.startsWith('HS')) {
      key = await this.joseSecret();
    } else if (header.alg !== 'none') {
      key = await this.issuer.queryKeyStore(header);
    }

    if (!key && header.alg === 'none') {
      return { protected: header, payload };
    }

    try {
      return jose.JWS.verify(jwt, key, { complete: true });
    } catch (err) {
      throw new RPError({
        message: 'failed to validate JWT signature',
        jwt,
      });
    }
  }

  /**
   * @name refresh
   * @api public
   */
  async refresh(refreshToken, { exchangeBody, clientAssertionPayload } = {}) {
    let token = refreshToken;

    if (token instanceof TokenSet) {
      if (!token.refresh_token) {
        throw new TypeError('refresh_token not present in TokenSet');
      }
      token = token.refresh_token;
    }

    const tokenset = await this.grant({
      ...exchangeBody,
      grant_type: 'refresh_token',
      refresh_token: String(token),
    }, { clientAssertionPayload });

    if (tokenset.id_token) {
      await this.decryptIdToken(tokenset);
      await this.validateIdToken(tokenset, null, 'token', null);

      if (refreshToken instanceof TokenSet && refreshToken.id_token) {
        const expectedSub = refreshToken.claims().sub;
        const actualSub = tokenset.claims().sub;
        if (actualSub !== expectedSub) {
          throw new RPError({
            printf: ['sub mismatch, expected %s, got: %s', expectedSub, actualSub],
            jwt: tokenset.id_token,
          });
        }
      }
    }

    return tokenset;
  }

  async requestResource(
    resourceUrl,
    accessToken,
    {
      method,
      headers,
      body,
      tokenType = accessToken instanceof TokenSet ? accessToken.token_type : 'Bearer',
    } = {},
  ) {
    if (accessToken instanceof TokenSet) {
      if (!accessToken.access_token) {
        throw new TypeError('access_token not present in TokenSet');
      }
      accessToken = accessToken.access_token; // eslint-disable-line no-param-reassign
    }

    const requestOpts = {
      headers: {
        Authorization: authorizationHeaderValue(accessToken, tokenType),
        ...headers,
      },
      body,
    };

    const mTLS = !!this.tls_client_certificate_bound_access_tokens;

    return request.call(this, {
      ...requestOpts,
      encoding: null,
      method,
      url: resourceUrl,
    }, { mTLS });
  }

  /**
   * @name userinfo
   * @api public
   */
  async userinfo(accessToken, {
    verb = 'GET', via = 'header', tokenType, params,
  } = {}) {
    // TODO: in v4.x remove verb in favour of method
    assertIssuerConfiguration(this.issuer, 'userinfo_endpoint');
    const options = {
      tokenType,
      method: String(verb).toUpperCase(),
    };

    if (options.method !== 'GET' && options.method !== 'POST') {
      throw new TypeError('#userinfo() verb can only be POST or a GET');
    }

    if (via === 'query' && options.method !== 'GET') {
      throw new TypeError('userinfo endpoints will only parse query strings for GET requests');
    } else if (via === 'body' && options.method !== 'POST') {
      throw new TypeError('can only send body on POST');
    }

    const jwt = !!(this.userinfo_signed_response_alg
      || this.userinfo_encrypted_response_alg);

    if (jwt) {
      options.headers = { Accept: 'application/jwt' };
    } else {
      options.headers = { Accept: 'application/json' };
    }

    const mTLS = !!this.tls_client_certificate_bound_access_tokens;

    let targetUrl;
    if (mTLS && this.issuer.mtls_endpoint_aliases) {
      targetUrl = this.issuer.mtls_endpoint_aliases.userinfo_endpoint;
    }

    targetUrl = new url.URL(targetUrl || this.issuer.userinfo_endpoint);

    // when via is not header we clear the Authorization header and add either
    // query string parameters or urlencoded body access_token parameter
    if (via === 'query') {
      options.headers.Authorization = undefined;
      targetUrl.searchParams.append('access_token', accessToken instanceof TokenSet ? accessToken.access_token : accessToken);
    } else if (via === 'body') {
      options.headers.Authorization = undefined;
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = new url.URLSearchParams();
      options.body.append('access_token', accessToken instanceof TokenSet ? accessToken.access_token : accessToken);
    }

    // handle additional parameters, GET via querystring, POST via urlencoded body
    if (params) {
      if (options.method === 'GET') {
        Object.entries(params).forEach(([key, value]) => {
          targetUrl.searchParams.append(key, value);
        });
      } else if (options.body) { // POST && via body
        Object.entries(params).forEach(([key, value]) => {
          options.body.append(key, value);
        });
      } else { // POST && via header
        options.body = new url.URLSearchParams();
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        Object.entries(params).forEach(([key, value]) => {
          options.body.append(key, value);
        });
      }
    }

    if (options.body) {
      options.body = options.body.toString();
    }

    const response = await this.requestResource(targetUrl, accessToken, options);

    let parsed = processResponse(response, { bearer: true });

    if (jwt) {
      if (!JWT_CONTENT.test(response.headers['content-type'])) {
        throw new RPError({
          message: 'expected application/jwt response from the userinfo_endpoint',
          response,
        });
      }

      const body = response.body.toString();
      const userinfo = await this.decryptJWTUserinfo(body);
      if (!this.userinfo_signed_response_alg) {
        try {
          parsed = JSON.parse(userinfo);
          assert(isPlainObject(parsed));
        } catch (err) {
          throw new RPError({
            message: 'failed to parse userinfo JWE payload as JSON',
            jwt: userinfo,
          });
        }
      } else {
        ({ payload: parsed } = await this.validateJWTUserinfo(userinfo));
      }
    } else {
      try {
        parsed = JSON.parse(response.body);
      } catch (error) {
        const parseError = new ParseError(
          error, response.statusCode, response.request.gotOptions, response.body,
        );
        Object.defineProperty(parseError, 'response', { value: response });
        throw parseError;
      }
    }

    if (accessToken instanceof TokenSet && accessToken.id_token) {
      const expectedSub = accessToken.claims().sub;
      if (parsed.sub !== expectedSub) {
        throw new RPError({
          printf: ['userinfo sub mismatch, expected %s, got: %s', expectedSub, parsed.sub],
          body: parsed,
          jwt: accessToken.id_token,
        });
      }
    }

    return parsed;
  }

  /**
   * @name derivedKey
   * @api private
   */
  async derivedKey(len) {
    const cacheKey = `${len}_key`;
    if (instance(this).has(cacheKey)) {
      return instance(this).get(cacheKey);
    }

    const hash = len <= 256 ? 'sha256' : len <= 384 ? 'sha384' : len <= 512 ? 'sha512' : false; // eslint-disable-line no-nested-ternary
    if (!hash) {
      throw new Error('unsupported symmetric encryption key derivation');
    }

    const derivedBuffer = crypto.createHash(hash)
      .update(this.client_secret)
      .digest()
      .slice(0, len / 8);

    const key = jose.JWK.asKey({ k: base64url.encode(derivedBuffer), kty: 'oct' });
    instance(this).set(cacheKey, key);

    return key;
  }

  /**
   * @name joseSecret
   * @api private
   */
  async joseSecret(alg) {
    if (!this.client_secret) {
      throw new TypeError('client_secret is required');
    }
    if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
      return this.derivedKey(parseInt(RegExp.$1, 10));
    }

    if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
      return this.derivedKey(parseInt(RegExp.$2 || RegExp.$1, 10));
    }

    if (instance(this).has('jose_secret')) {
      return instance(this).get('jose_secret');
    }

    const key = jose.JWK.asKey({ k: base64url.encode(this.client_secret), kty: 'oct' });
    instance(this).set('jose_secret', key);

    return key;
  }

  /**
   * @name grant
   * @api public
   */
  async grant(body, { clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'token_endpoint');
    const response = await authenticatedPost.call(
      this,
      'token',
      {
        form: true,
        body,
        json: true,
      },
      { clientAssertionPayload },
    );
    const responseBody = processResponse(response);

    return new TokenSet(responseBody);
  }

  /**
   * @name deviceAuthorization
   * @api public
   */
  async deviceAuthorization(params = {}, { exchangeBody, clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'device_authorization_endpoint');
    assertIssuerConfiguration(this.issuer, 'token_endpoint');

    const body = authorizationParams.call(this, {
      client_id: this.client_id,
      redirect_uri: null,
      response_type: null,
      ...params,
    });

    const response = await authenticatedPost.call(
      this,
      'device_authorization',
      {
        form: true,
        body,
        json: true,
      },
      { clientAssertionPayload, endpointAuthMethod: 'token' },
    );
    const responseBody = processResponse(response);

    return new DeviceFlowHandle({
      client: this,
      exchangeBody,
      clientAssertionPayload,
      response: responseBody,
      maxAge: params.max_age,
    });
  }

  /**
   * @name revoke
   * @api public
   */
  async revoke(token, hint, { revokeBody, clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'revocation_endpoint');
    if (hint !== undefined && typeof hint !== 'string') {
      throw new TypeError('hint must be a string');
    }

    const body = { ...revokeBody, token };

    if (hint) {
      body.token_type_hint = hint;
    }

    const response = await authenticatedPost.call(
      this,
      'revocation', {
        body,
        form: true,
      }, { clientAssertionPayload },
    );
    processResponse(response, { body: false });
  }

  /**
   * @name introspect
   * @api public
   */
  async introspect(token, hint, { introspectBody, clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'introspection_endpoint');
    if (hint !== undefined && typeof hint !== 'string') {
      throw new TypeError('hint must be a string');
    }

    const body = { ...introspectBody, token };
    if (hint) {
      body.token_type_hint = hint;
    }

    const response = await authenticatedPost.call(
      this,
      'introspection',
      { body, form: true, json: true },
      { clientAssertionPayload },
    );

    const responseBody = processResponse(response);

    return responseBody;
  }

  /**
   * @name fetchDistributedClaims
   * @api public
   */
  async fetchDistributedClaims(claims, tokens = {}) {
    if (!isPlainObject(claims)) {
      throw new TypeError('claims argument must be a plain object');
    }

    if (!isPlainObject(claims._claim_sources)) {
      return claims;
    }

    if (!isPlainObject(claims._claim_names)) {
      return claims;
    }

    const distributedSources = Object.entries(claims._claim_sources)
      .filter(([, value]) => value && value.endpoint);

    await Promise.all(distributedSources.map(async ([sourceName, def]) => {
      try {
        const requestOpts = {
          headers: {
            Accept: 'application/jwt',
            Authorization: authorizationHeaderValue(def.access_token || tokens[sourceName]),
          },
        };

        const response = await request.call(this, {
          ...requestOpts,
          method: 'GET',
          url: def.endpoint,
        });
        const body = processResponse(response, { bearer: true });

        const decoded = await claimJWT.call(this, 'distributed', body);
        delete claims._claim_sources[sourceName];
        Object.entries(claims._claim_names).forEach(
          assignClaim(claims, decoded, sourceName, false),
        );
      } catch (err) {
        err.src = sourceName;
        throw err;
      }
    }));

    cleanUpClaims(claims);
    return claims;
  }

  /**
   * @name unpackAggregatedClaims
   * @api public
   */
  async unpackAggregatedClaims(claims) {
    if (!isPlainObject(claims)) {
      throw new TypeError('claims argument must be a plain object');
    }

    if (!isPlainObject(claims._claim_sources)) {
      return claims;
    }

    if (!isPlainObject(claims._claim_names)) {
      return claims;
    }

    const aggregatedSources = Object.entries(claims._claim_sources)
      .filter(([, value]) => value && value.JWT);

    await Promise.all(aggregatedSources.map(async ([sourceName, def]) => {
      try {
        const decoded = await claimJWT.call(this, 'aggregated', def.JWT);
        delete claims._claim_sources[sourceName];
        Object.entries(claims._claim_names).forEach(assignClaim(claims, decoded, sourceName));
      } catch (err) {
        err.src = sourceName;
        throw err;
      }
    }));

    cleanUpClaims(claims);
    return claims;
  }

  /**
   * @name register
   * @api public
   */
  static async register(metadata, options = {}) {
    const { initialAccessToken, jwks, ...clientOptions } = options;

    assertIssuerConfiguration(this.issuer, 'registration_endpoint');

    if (jwks !== undefined && !(metadata.jwks || metadata.jwks_uri)) {
      const keystore = getKeystore.call(this, jwks);
      metadata.jwks = keystore.toJWKS(false);
    }

    const response = await request.call(this, {
      headers: initialAccessToken ? {
        Authorization: authorizationHeaderValue(initialAccessToken),
      } : undefined,
      json: true,
      body: metadata,
      url: this.issuer.registration_endpoint,
      method: 'POST',
    });
    const responseBody = processResponse(response, { statusCode: 201, bearer: true });

    return new this(responseBody, jwks, clientOptions);
  }

  /**
   * @name metadata
   * @api public
   */
  get metadata() {
    const copy = {};
    instance(this).get('metadata').forEach((value, key) => {
      copy[key] = value;
    });
    return copy;
  }

  /**
   * @name fromUri
   * @api public
   */
  static async fromUri(registrationClientUri, registrationAccessToken, jwks, clientOptions) {
    const response = await request.call(this, {
      method: 'GET',
      url: registrationClientUri,
      json: true,
      headers: { Authorization: authorizationHeaderValue(registrationAccessToken) },
    });
    const responseBody = processResponse(response, { bearer: true });

    return new this(responseBody, jwks, clientOptions);
  }

  /**
   * @name requestObject
   * @api public
   */
  async requestObject(requestObject = {}, {
    sign: signingAlgorithm = this.request_object_signing_alg || 'none',
    encrypt: {
      alg: eKeyManagement = this.request_object_encryption_alg,
      enc: eContentEncryption = this.request_object_encryption_enc || 'A128CBC-HS256',
    } = {},
  } = {}) {
    if (!isPlainObject(requestObject)) {
      throw new TypeError('requestObject must be a plain object');
    }

    let signed;
    let key;

    const header = { alg: signingAlgorithm, typ: 'JWT' };
    const payload = JSON.stringify(defaults({}, requestObject, {
      iss: this.client_id,
      aud: this.issuer.issuer,
      client_id: this.client_id,
      jti: random(),
      iat: now(),
      exp: now() + 300,
    }));

    if (signingAlgorithm === 'none') {
      signed = [
        base64url.encode(JSON.stringify(header)),
        base64url.encode(payload),
        '',
      ].join('.');
    } else {
      const symmetric = signingAlgorithm.startsWith('HS');
      if (symmetric) {
        key = await this.joseSecret();
      } else {
        const keystore = instance(this).get('keystore');

        if (!keystore) {
          throw new TypeError(`no keystore present for client, cannot sign using alg ${signingAlgorithm}`);
        }
        key = keystore.get({ alg: signingAlgorithm, use: 'sig' });
        if (!key) {
          throw new TypeError(`no key to sign with found for alg ${signingAlgorithm}`);
        }
      }

      signed = jose.JWS.sign(payload, key, {
        ...header,
        kid: symmetric ? undefined : key.kid,
      });
    }

    if (!eKeyManagement) {
      return signed;
    }

    const fields = { alg: eKeyManagement, enc: eContentEncryption, cty: 'JWT' };

    if (fields.alg.match(/^(RSA|ECDH)/)) {
      [key] = await this.issuer.queryKeyStore({
        alg: fields.alg,
        enc: fields.enc,
        use: 'enc',
      }, { allowMulti: true });
    } else {
      key = await this.joseSecret(fields.alg === 'dir' ? fields.enc : fields.alg);
    }

    return jose.JWE.encrypt(signed, key, {
      ...fields,
      kid: key.kty === 'oct' ? undefined : key.kid,
    });
  }

  /**
   * @name issuer
   * @api public
   */
  static get issuer() {
    return issuer;
  }

  /**
   * @name issuer
   * @api public
   */
  get issuer() { // eslint-disable-line class-methods-use-this
    return issuer;
  }

  /* istanbul ignore next */
  [inspect.custom]() {
    return `${this.constructor.name} ${inspect(this.metadata, {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true,
    })}`;
  }
};

// TODO: remove in 4.x
BaseClient.prototype.resource = deprecate(
  /* istanbul ignore next */
  async function resource(resourceUrl, accessToken, options) {
    let token = accessToken;
    const opts = {
      verb: 'GET',
      via: 'header',
      ...options,
    };

    if (token instanceof TokenSet) {
      if (!token.access_token) {
        throw new TypeError('access_token not present in TokenSet');
      }
      opts.tokenType = opts.tokenType || token.token_type;
      token = token.access_token;
    }

    const verb = String(opts.verb).toUpperCase();
    let requestOpts;

    switch (opts.via) {
      case 'query':
        if (verb !== 'GET') {
          throw new TypeError('resource servers should only parse query strings for GET requests');
        }
        requestOpts = { query: { access_token: token } };
        break;
      case 'body':
        if (verb !== 'POST') {
          throw new TypeError('can only send body on POST');
        }
        requestOpts = { form: true, body: { access_token: token } };
        break;
      default:
        requestOpts = {
          headers: {
            Authorization: authorizationHeaderValue(token, opts.tokenType),
          },
        };
    }

    if (opts.params) {
      if (verb === 'POST') {
        defaultsDeep(requestOpts, { body: opts.params });
      } else {
        defaultsDeep(requestOpts, { query: opts.params });
      }
    }

    if (opts.headers) {
      defaultsDeep(requestOpts, { headers: opts.headers });
    }

    const mTLS = !!this.tls_client_certificate_bound_access_tokens;

    return request.call(this, {
      ...requestOpts,
      encoding: null,
      method: verb,
      url: resourceUrl,
    }, { mTLS });
  }, 'client.resource() is deprecated, use client.requestResource() instead, see docs for API details',
);

module.exports.BaseClient = BaseClient;


/***/ }),

/***/ "Hu8U":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    const lessThan = 0x3C;
    const greaterThan = 0x3E;
    const andSymbol = 0x26;
    const lineSeperator = 0x2028;

    // replace method
    let charCode;
    return input.replace(/[<>&\u2028\u2029]/g, (match) => {

        charCode = match.charCodeAt(0);

        if (charCode === lessThan) {
            return '\\u003c';
        }

        if (charCode === greaterThan) {
            return '\\u003e';
        }

        if (charCode === andSymbol) {
            return '\\u0026';
        }

        if (charCode === lineSeperator) {
            return '\\u2028';
        }

        return '\\u2029';
    });
};


/***/ }),

/***/ "HwNo":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

module.exports = function (Yallist) {
  Yallist.prototype[Symbol.iterator] = function* () {
    for (let walker = this.head; walker; walker = walker.next) {
      yield walker.value
    }
  }
}


/***/ }),

/***/ "HyWp":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// A linked list to keep track of recently-used-ness
const Yallist = __webpack_require__("XPeR")

const MAX = Symbol('max')
const LENGTH = Symbol('length')
const LENGTH_CALCULATOR = Symbol('lengthCalculator')
const ALLOW_STALE = Symbol('allowStale')
const MAX_AGE = Symbol('maxAge')
const DISPOSE = Symbol('dispose')
const NO_DISPOSE_ON_SET = Symbol('noDisposeOnSet')
const LRU_LIST = Symbol('lruList')
const CACHE = Symbol('cache')
const UPDATE_AGE_ON_GET = Symbol('updateAgeOnGet')

const naiveLength = () => 1

// lruList is a yallist where the head is the youngest
// item, and the tail is the oldest.  the list contains the Hit
// objects as the entries.
// Each Hit object has a reference to its Yallist.Node.  This
// never changes.
//
// cache is a Map (or PseudoMap) that matches the keys to
// the Yallist.Node object.
class LRUCache {
  constructor (options) {
    if (typeof options === 'number')
      options = { max: options }

    if (!options)
      options = {}

    if (options.max && (typeof options.max !== 'number' || options.max < 0))
      throw new TypeError('max must be a non-negative number')
    // Kind of weird to have a default max of Infinity, but oh well.
    const max = this[MAX] = options.max || Infinity

    const lc = options.length || naiveLength
    this[LENGTH_CALCULATOR] = (typeof lc !== 'function') ? naiveLength : lc
    this[ALLOW_STALE] = options.stale || false
    if (options.maxAge && typeof options.maxAge !== 'number')
      throw new TypeError('maxAge must be a number')
    this[MAX_AGE] = options.maxAge || 0
    this[DISPOSE] = options.dispose
    this[NO_DISPOSE_ON_SET] = options.noDisposeOnSet || false
    this[UPDATE_AGE_ON_GET] = options.updateAgeOnGet || false
    this.reset()
  }

  // resize the cache when the max changes.
  set max (mL) {
    if (typeof mL !== 'number' || mL < 0)
      throw new TypeError('max must be a non-negative number')

    this[MAX] = mL || Infinity
    trim(this)
  }
  get max () {
    return this[MAX]
  }

  set allowStale (allowStale) {
    this[ALLOW_STALE] = !!allowStale
  }
  get allowStale () {
    return this[ALLOW_STALE]
  }

  set maxAge (mA) {
    if (typeof mA !== 'number')
      throw new TypeError('maxAge must be a non-negative number')

    this[MAX_AGE] = mA
    trim(this)
  }
  get maxAge () {
    return this[MAX_AGE]
  }

  // resize the cache when the lengthCalculator changes.
  set lengthCalculator (lC) {
    if (typeof lC !== 'function')
      lC = naiveLength

    if (lC !== this[LENGTH_CALCULATOR]) {
      this[LENGTH_CALCULATOR] = lC
      this[LENGTH] = 0
      this[LRU_LIST].forEach(hit => {
        hit.length = this[LENGTH_CALCULATOR](hit.value, hit.key)
        this[LENGTH] += hit.length
      })
    }
    trim(this)
  }
  get lengthCalculator () { return this[LENGTH_CALCULATOR] }

  get length () { return this[LENGTH] }
  get itemCount () { return this[LRU_LIST].length }

  rforEach (fn, thisp) {
    thisp = thisp || this
    for (let walker = this[LRU_LIST].tail; walker !== null;) {
      const prev = walker.prev
      forEachStep(this, fn, walker, thisp)
      walker = prev
    }
  }

  forEach (fn, thisp) {
    thisp = thisp || this
    for (let walker = this[LRU_LIST].head; walker !== null;) {
      const next = walker.next
      forEachStep(this, fn, walker, thisp)
      walker = next
    }
  }

  keys () {
    return this[LRU_LIST].toArray().map(k => k.key)
  }

  values () {
    return this[LRU_LIST].toArray().map(k => k.value)
  }

  reset () {
    if (this[DISPOSE] &&
        this[LRU_LIST] &&
        this[LRU_LIST].length) {
      this[LRU_LIST].forEach(hit => this[DISPOSE](hit.key, hit.value))
    }

    this[CACHE] = new Map() // hash of items by key
    this[LRU_LIST] = new Yallist() // list of items in order of use recency
    this[LENGTH] = 0 // length of items in the list
  }

  dump () {
    return this[LRU_LIST].map(hit =>
      isStale(this, hit) ? false : {
        k: hit.key,
        v: hit.value,
        e: hit.now + (hit.maxAge || 0)
      }).toArray().filter(h => h)
  }

  dumpLru () {
    return this[LRU_LIST]
  }

  set (key, value, maxAge) {
    maxAge = maxAge || this[MAX_AGE]

    if (maxAge && typeof maxAge !== 'number')
      throw new TypeError('maxAge must be a number')

    const now = maxAge ? Date.now() : 0
    const len = this[LENGTH_CALCULATOR](value, key)

    if (this[CACHE].has(key)) {
      if (len > this[MAX]) {
        del(this, this[CACHE].get(key))
        return false
      }

      const node = this[CACHE].get(key)
      const item = node.value

      // dispose of the old one before overwriting
      // split out into 2 ifs for better coverage tracking
      if (this[DISPOSE]) {
        if (!this[NO_DISPOSE_ON_SET])
          this[DISPOSE](key, item.value)
      }

      item.now = now
      item.maxAge = maxAge
      item.value = value
      this[LENGTH] += len - item.length
      item.length = len
      this.get(key)
      trim(this)
      return true
    }

    const hit = new Entry(key, value, len, now, maxAge)

    // oversized objects fall out of cache automatically.
    if (hit.length > this[MAX]) {
      if (this[DISPOSE])
        this[DISPOSE](key, value)

      return false
    }

    this[LENGTH] += hit.length
    this[LRU_LIST].unshift(hit)
    this[CACHE].set(key, this[LRU_LIST].head)
    trim(this)
    return true
  }

  has (key) {
    if (!this[CACHE].has(key)) return false
    const hit = this[CACHE].get(key).value
    return !isStale(this, hit)
  }

  get (key) {
    return get(this, key, true)
  }

  peek (key) {
    return get(this, key, false)
  }

  pop () {
    const node = this[LRU_LIST].tail
    if (!node)
      return null

    del(this, node)
    return node.value
  }

  del (key) {
    del(this, this[CACHE].get(key))
  }

  load (arr) {
    // reset the cache
    this.reset()

    const now = Date.now()
    // A previous serialized cache has the most recent items first
    for (let l = arr.length - 1; l >= 0; l--) {
      const hit = arr[l]
      const expiresAt = hit.e || 0
      if (expiresAt === 0)
        // the item was created without expiration in a non aged cache
        this.set(hit.k, hit.v)
      else {
        const maxAge = expiresAt - now
        // dont add already expired items
        if (maxAge > 0) {
          this.set(hit.k, hit.v, maxAge)
        }
      }
    }
  }

  prune () {
    this[CACHE].forEach((value, key) => get(this, key, false))
  }
}

const get = (self, key, doUse) => {
  const node = self[CACHE].get(key)
  if (node) {
    const hit = node.value
    if (isStale(self, hit)) {
      del(self, node)
      if (!self[ALLOW_STALE])
        return undefined
    } else {
      if (doUse) {
        if (self[UPDATE_AGE_ON_GET])
          node.value.now = Date.now()
        self[LRU_LIST].unshiftNode(node)
      }
    }
    return hit.value
  }
}

const isStale = (self, hit) => {
  if (!hit || (!hit.maxAge && !self[MAX_AGE]))
    return false

  const diff = Date.now() - hit.now
  return hit.maxAge ? diff > hit.maxAge
    : self[MAX_AGE] && (diff > self[MAX_AGE])
}

const trim = self => {
  if (self[LENGTH] > self[MAX]) {
    for (let walker = self[LRU_LIST].tail;
      self[LENGTH] > self[MAX] && walker !== null;) {
      // We know that we're about to delete this one, and also
      // what the next least recently used key will be, so just
      // go ahead and set it now.
      const prev = walker.prev
      del(self, walker)
      walker = prev
    }
  }
}

const del = (self, node) => {
  if (node) {
    const hit = node.value
    if (self[DISPOSE])
      self[DISPOSE](hit.key, hit.value)

    self[LENGTH] -= hit.length
    self[CACHE].delete(hit.key)
    self[LRU_LIST].removeNode(node)
  }
}

class Entry {
  constructor (key, value, length, now, maxAge) {
    this.key = key
    this.value = value
    this.length = length
    this.now = now
    this.maxAge = maxAge || 0
  }
}

const forEachStep = (self, fn, node, thisp) => {
  let hit = node.value
  if (isStale(self, hit)) {
    del(self, node)
    if (!self[ALLOW_STALE])
      hit = undefined
  }
  if (hit)
    fn.call(thisp, hit.value, hit.key, self)
}

module.exports = LRUCache


/***/ }),

/***/ "IWF7":
/***/ (function(module, exports, __webpack_require__) {

const { createHmac } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const timingSafeEqual = __webpack_require__("kuaU")
const resolveNodeAlg = __webpack_require__("uGJc")
const { asInput } = __webpack_require__("1ALl")

const sign = (jwaAlg, hmacAlg, { [KEYOBJECT]: keyObject }, payload) => {
  const hmac = createHmac(hmacAlg, asInput(keyObject, false))
  hmac.update(payload)
  return hmac.digest()
}

const verify = (jwaAlg, hmacAlg, key, payload, signature) => {
  const expected = sign(jwaAlg, hmacAlg, key, payload)
  const actual = signature

  return timingSafeEqual(actual, expected)
}

module.exports = (JWA, JWK) => {
  ['HS256', 'HS384', 'HS512'].forEach((jwaAlg) => {
    const hmacAlg = resolveNodeAlg(jwaAlg)
    JWA.sign.set(jwaAlg, sign.bind(undefined, jwaAlg, hmacAlg))
    JWA.verify.set(jwaAlg, verify.bind(undefined, jwaAlg, hmacAlg))
    JWK.oct.sign[jwaAlg] = JWK.oct.verify[jwaAlg] = key => key.use === 'sig' || key.use === undefined
  })
}


/***/ }),

/***/ "IgmS":
/***/ (function(module, exports, __webpack_require__) {

const base64url = __webpack_require__("+00W");

const now = __webpack_require__("PbSP");

class TokenSet {
  /**
   * @name constructor
   * @api public
   */
  constructor(values) {
    Object.assign(this, values);
  }

  /**
   * @name expires_in=
   * @api public
   */
  set expires_in(value) { // eslint-disable-line camelcase
    this.expires_at = now() + Number(value);
  }

  /**
   * @name expires_in
   * @api public
   */
  get expires_in() { // eslint-disable-line camelcase
    return Math.max.apply(null, [this.expires_at - now(), 0]);
  }

  /**
   * @name expired
   * @api public
   */
  expired() {
    return this.expires_in === 0;
  }

  /**
   * @name claims
   * @api public
   */
  claims() {
    if (!this.id_token) {
      throw new TypeError('id_token not present in TokenSet');
    }

    return JSON.parse(base64url.decode(this.id_token.split('.')[1]));
  }
}

module.exports = TokenSet;


/***/ }),

/***/ "IhwK":
/***/ (function(module, exports, __webpack_require__) {

const { inspect } = __webpack_require__("jK02")

const Key = __webpack_require__("//Cd")

class EmbeddedX5C extends Key {
  constructor () {
    super({ type: 'embedded' })
    Object.defineProperties(this, {
      kid: { value: undefined },
      kty: { value: undefined },
      thumbprint: { value: undefined },
      toJWK: { value: undefined },
      toPEM: { value: undefined }
    })
  }

  /* c8 ignore next 3 */
  [inspect.custom] () {
    return 'Embedded.X5C {}'
  }

  algorithms () {
    return new Set()
  }
}

module.exports = new EmbeddedX5C()


/***/ }),

/***/ "IuXR":
/***/ (function(module, exports) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(r,e){"use strict";var t={};function __webpack_require__(e){if(t[e]){return t[e].exports}var a=t[e]={i:e,l:false,exports:{}};r[e].call(a.exports,a,a.exports,__webpack_require__);a.l=true;return a.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(6)}return startup()}({6:function(r){"use strict";var e=/(?:^|,)\s*?no-cache\s*?(?:,|$)/;r.exports=fresh;function fresh(r,t){var a=r["if-modified-since"];var s=r["if-none-match"];if(!a&&!s){return false}var n=r["cache-control"];if(n&&e.test(n)){return false}if(s&&s!=="*"){var i=t["etag"];if(!i){return false}var u=true;var f=parseTokenList(s);for(var o=0;o<f.length;o++){var c=f[o];if(c===i||c==="W/"+i||"W/"+c===i){u=false;break}}if(u){return false}}if(a){var p=t["last-modified"];var _=!p||!(parseHttpDate(p)<=parseHttpDate(a));if(_){return false}}return true}function parseHttpDate(r){var e=r&&Date.parse(r);return typeof e==="number"?e:NaN}function parseTokenList(r){var e=0;var t=[];var a=0;for(var s=0,n=r.length;s<n;s++){switch(r.charCodeAt(s)){case 32:if(a===e){a=e=s+1}break;case 44:t.push(r.substring(a,e));a=e=s+1;break;default:e=s+1;break}}t.push(r.substring(a,e));return t}}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "J0Hf":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function sessionHandler(sessionStore) {
    return (req) => {
        if (!req) {
            throw new Error('Request is not available');
        }
        return sessionStore.read(req);
    };
}
exports.default = sessionHandler;
//# sourceMappingURL=session.js.map

/***/ }),

/***/ "JC5t":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("xG1e");
const Clone = __webpack_require__("E9YA");
const Merge = __webpack_require__("6HRL");
const Utils = __webpack_require__("f/5Z");


const internals = {};


module.exports = function (defaults, source, options = {}) {

    Assert(defaults && typeof defaults === 'object', 'Invalid defaults value: must be an object');
    Assert(!source || source === true || typeof source === 'object', 'Invalid source value: must be true, falsy or an object');
    Assert(typeof options === 'object', 'Invalid options: must be an object');

    if (!source) {                                                  // If no source, return null
        return null;
    }

    if (options.shallow) {
        return internals.applyToDefaultsWithShallow(defaults, source, options);
    }

    const copy = Clone(defaults);

    if (source === true) {                                          // If source is set to true, use defaults
        return copy;
    }

    const nullOverride = options.nullOverride !== undefined ? options.nullOverride : false;
    return Merge(copy, source, { nullOverride, mergeArrays: false });
};


internals.applyToDefaultsWithShallow = function (defaults, source, options) {

    const keys = options.shallow;
    Assert(Array.isArray(keys), 'Invalid keys');

    options = Object.assign({}, options);
    options.shallow = false;

    const copy = Clone(defaults, { shallow: keys });

    if (source === true) {                                                      // If source is set to true, use defaults
        return copy;
    }

    const storage = Utils.store(source, keys);                              // Move shallow copy items to storage
    Merge(copy, source, { mergeArrays: false, nullOverride: false });   // Deep copy the rest
    Utils.restore(copy, source, storage);                                   // Shallow copy the stored items and restore
    return copy;
};


/***/ }),

/***/ "JT7C":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("8g7u");
const Utils = __webpack_require__("3J/O");


const internals = {
    needsProtoHack: new Set([Types.set, Types.map, Types.weakSet, Types.weakMap])
};


module.exports = internals.clone = function (obj, options = {}, _seen = null) {

    if (typeof obj !== 'object' ||
        obj === null) {

        return obj;
    }

    let clone = internals.clone;
    let seen = _seen;

    if (options.shallow) {
        if (options.shallow !== true) {
            return internals.cloneWithShallow(obj, options);
        }

        clone = (value) => value;
    }
    else {
        seen = seen || new Map();

        const lookup = seen.get(obj);
        if (lookup) {
            return lookup;
        }
    }

    // Built-in object types

    const baseProto = Types.getInternalProto(obj);
    if (baseProto === Types.buffer) {
        return Buffer && Buffer.from(obj);              // $lab:coverage:ignore$
    }

    if (baseProto === Types.date) {
        return new Date(obj.getTime());
    }

    if (baseProto === Types.regex) {
        return new RegExp(obj);
    }

    // Generic objects

    const newObj = internals.base(obj, baseProto, options);
    if (newObj === obj) {
        return obj;
    }

    if (seen) {
        seen.set(obj, newObj);                              // Set seen, since obj could recurse
    }

    if (baseProto === Types.set) {
        for (const value of obj) {
            newObj.add(clone(value, options, seen));
        }
    }
    else if (baseProto === Types.map) {
        for (const [key, value] of obj) {
            newObj.set(key, clone(value, options, seen));
        }
    }

    const keys = Utils.keys(obj, options);
    for (const key of keys) {
        if (key === '__proto__') {
            continue;
        }

        if (baseProto === Types.array &&
            key === 'length') {

            newObj.length = obj.length;
            continue;
        }

        const descriptor = Object.getOwnPropertyDescriptor(obj, key);
        if (descriptor) {
            if (descriptor.get ||
                descriptor.set) {

                Object.defineProperty(newObj, key, descriptor);
            }
            else if (descriptor.enumerable) {
                newObj[key] = clone(obj[key], options, seen);
            }
            else {
                Object.defineProperty(newObj, key, { enumerable: false, writable: true, configurable: true, value: clone(obj[key], options, seen) });
            }
        }
        else {
            Object.defineProperty(newObj, key, {
                enumerable: true,
                writable: true,
                configurable: true,
                value: clone(obj[key], options, seen)
            });
        }
    }

    return newObj;
};


internals.cloneWithShallow = function (source, options) {

    const keys = options.shallow;
    options = Object.assign({}, options);
    options.shallow = false;

    const storage = Utils.store(source, keys);    // Move shallow copy items to storage
    const copy = internals.clone(source, options);      // Deep copy the rest
    Utils.restore(copy, source, storage);         // Shallow copy the stored items and restore
    return copy;
};


internals.base = function (obj, baseProto, options) {

    if (baseProto === Types.array) {
        return [];
    }

    if (options.prototype === false) {                  // Defaults to true
        if (internals.needsProtoHack.has(baseProto)) {
            return new baseProto.constructor();
        }

        return {};
    }

    const proto = Object.getPrototypeOf(obj);
    if (proto &&
        proto.isImmutable) {

        return obj;
    }

    if (internals.needsProtoHack.has(baseProto)) {
        const newObj = new proto.constructor();
        if (proto !== baseProto) {
            Object.setPrototypeOf(newObj, proto);
        }

        return newObj;
    }

    return Object.create(proto);
};


/***/ }),

/***/ "JXcb":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (method) {

    if (method._hoekOnce) {
        return method;
    }

    let once = false;
    const wrapped = function (...args) {

        if (!once) {
            once = true;
            method(...args);
        }
    };

    wrapped._hoekOnce = true;
    return wrapped;
};


/***/ }),

/***/ "JlL/":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = [
	'beforeError',
	'init',
	'beforeRequest',
	'beforeRedirect',
	'beforeRetry',
	'afterResponse'
];


/***/ }),

/***/ "K0QS":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {Transform} = __webpack_require__("msIP");

module.exports = {
	download(response, emitter, downloadBodySize) {
		let downloaded = 0;

		return new Transform({
			transform(chunk, encoding, callback) {
				downloaded += chunk.length;

				const percent = downloadBodySize ? downloaded / downloadBodySize : 0;

				// Let `flush()` be responsible for emitting the last event
				if (percent < 1) {
					emitter.emit('downloadProgress', {
						percent,
						transferred: downloaded,
						total: downloadBodySize
					});
				}

				callback(null, chunk);
			},

			flush(callback) {
				emitter.emit('downloadProgress', {
					percent: 1,
					transferred: downloaded,
					total: downloadBodySize
				});

				callback();
			}
		});
	},

	upload(request, emitter, uploadBodySize) {
		const uploadEventFrequency = 150;
		let uploaded = 0;
		let progressInterval;

		emitter.emit('uploadProgress', {
			percent: 0,
			transferred: 0,
			total: uploadBodySize
		});

		request.once('error', () => {
			clearInterval(progressInterval);
		});

		request.once('response', () => {
			clearInterval(progressInterval);

			emitter.emit('uploadProgress', {
				percent: 1,
				transferred: uploaded,
				total: uploadBodySize
			});
		});

		request.once('socket', socket => {
			const onSocketConnect = () => {
				progressInterval = setInterval(() => {
					const lastUploaded = uploaded;
					/* istanbul ignore next: see #490 (occurs randomly!) */
					const headersSize = request._header ? Buffer.byteLength(request._header) : 0;
					uploaded = socket.bytesWritten - headersSize;

					// Don't emit events with unchanged progress and
					// prevent last event from being emitted, because
					// it's emitted when `response` is emitted
					if (uploaded === lastUploaded || uploaded === uploadBodySize) {
						return;
					}

					emitter.emit('uploadProgress', {
						percent: uploadBodySize ? uploaded / uploadBodySize : 0,
						transferred: uploaded,
						total: uploadBodySize
					});
				}, uploadEventFrequency);
			};

			/* istanbul ignore next: hard to test */
			if (socket.connecting) {
				socket.once('connect', onSocketConnect);
			} else if (socket.writable) {
				// The socket is being reused from pool,
				// so the connect event will not be emitted
				onSocketConnect();
			}
		});
	}
};


/***/ }),

/***/ "K29m":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (array1, array2, options = {}) {

    if (!array1 ||
        !array2) {

        return (options.first ? null : []);
    }

    const common = [];
    const hash = (Array.isArray(array1) ? new Set(array1) : array1);
    const found = new Set();
    for (const value of array2) {
        if (internals.has(hash, value) &&
            !found.has(value)) {

            if (options.first) {
                return value;
            }

            common.push(value);
            found.add(value);
        }
    }

    return (options.first ? null : common);
};


internals.has = function (ref, key) {

    if (typeof ref.has === 'function') {
        return ref.has(key);
    }

    return ref[key] !== undefined;
};


/***/ }),

/***/ "KEll":
/***/ (function(module, exports) {

module.exports = require("http");

/***/ }),

/***/ "KQbz":
/***/ (function(module, exports) {

module.exports = (a = {}, b = {}) => {
  const keysA = Object.keys(a)
  const keysB = new Set(Object.keys(b))
  return !keysA.some((ka) => keysB.has(ka))
}


/***/ }),

/***/ "KQmy":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    const lessThan = 0x3C;
    const greaterThan = 0x3E;
    const andSymbol = 0x26;
    const lineSeperator = 0x2028;

    // replace method
    let charCode;
    return input.replace(/[<>&\u2028\u2029]/g, (match) => {

        charCode = match.charCodeAt(0);

        if (charCode === lessThan) {
            return '\\u003c';
        }

        if (charCode === greaterThan) {
            return '\\u003e';
        }

        if (charCode === andSymbol) {
            return '\\u0026';
        }

        if (charCode === lineSeperator) {
            return '\\u2028';
        }

        return '\\u2029';
    });
};


/***/ }),

/***/ "KqAr":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);

    

    /* harmony default export */ __webpack_exports__["default"] = (function (ctx) {
      return Promise.all([])
    });
  

/***/ }),

/***/ "KqF2":
/***/ (function(module, exports) {

module.exports = new Map([
  ['A128CBC-HS256', 128],
  ['A128GCM', 96],
  ['A128GCMKW', 96],
  ['A192CBC-HS384', 128],
  ['A192GCM', 96],
  ['A192GCMKW', 96],
  ['A256CBC-HS512', 128],
  ['A256GCM', 96],
  ['A256GCMKW', 96]
])


/***/ }),

/***/ "L71r":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable camelcase */
const { format } = __webpack_require__("jK02");

const makeError = __webpack_require__("b1HN");

function OPError({
  error_description,
  error,
  error_uri,
  session_state,
  state,
  scope,
}, response) {
  OPError.super.call(this, !error_description ? error : `${error} (${error_description})`);

  Object.assign(
    this,
    { error },
    (error_description && { error_description }),
    (error_uri && { error_uri }),
    (state && { state }),
    (scope && { scope }),
    (session_state && { session_state }),
  );

  if (response) {
    Object.defineProperty(this, 'response', {
      value: response,
    });
  }
}

makeError(OPError);

function RPError(...args) {
  if (typeof args[0] === 'string') {
    RPError.super.call(this, format(...args));
  } else {
    const {
      message, printf, response, ...rest
    } = args[0];
    if (printf) {
      RPError.super.call(this, format(...printf));
    } else {
      RPError.super.call(this, message);
    }
    Object.assign(this, rest);
    if (response) {
      Object.defineProperty(this, 'response', {
        value: response,
      });
    }
  }
}

makeError(RPError);

module.exports = {
  OPError,
  RPError,
};


/***/ }),

/***/ "LDEB":
/***/ (function(module, exports, __webpack_require__) {

const errors = __webpack_require__("yt7c")

const importKey = __webpack_require__("GhER")

const RSAKey = __webpack_require__("RoCg")
const ECKey = __webpack_require__("3HlQ")
const OKPKey = __webpack_require__("vC2k")
const OctKey = __webpack_require__("BBt9")

const generate = async (kty, crvOrSize, params, generatePrivate = true) => {
  switch (kty) {
    case 'RSA':
      return importKey(
        await RSAKey.generate(crvOrSize, generatePrivate),
        params
      )
    case 'EC':
      return importKey(
        await ECKey.generate(crvOrSize, generatePrivate),
        params
      )
    case 'OKP':
      return importKey(
        await OKPKey.generate(crvOrSize, generatePrivate),
        params
      )
    case 'oct':
      return importKey(
        await OctKey.generate(crvOrSize, generatePrivate),
        params
      )
    default:
      throw new errors.JOSENotSupported(`unsupported key type: ${kty}`)
  }
}

const generateSync = (kty, crvOrSize, params, generatePrivate = true) => {
  switch (kty) {
    case 'RSA':
      return importKey(RSAKey.generateSync(crvOrSize, generatePrivate), params)
    case 'EC':
      return importKey(ECKey.generateSync(crvOrSize, generatePrivate), params)
    case 'OKP':
      return importKey(OKPKey.generateSync(crvOrSize, generatePrivate), params)
    case 'oct':
      return importKey(OctKey.generateSync(crvOrSize, generatePrivate), params)
    default:
      throw new errors.JOSENotSupported(`unsupported key type: ${kty}`)
  }
}

module.exports.generate = generate
module.exports.generateSync = generateSync


/***/ }),

/***/ "LMPv":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable camelcase */
const { inspect } = __webpack_require__("jK02");

const { RPError, OPError } = __webpack_require__("L71r");
const instance = __webpack_require__("0pkK");
const now = __webpack_require__("PbSP");
const { authenticatedPost } = __webpack_require__("/JKO");
const processResponse = __webpack_require__("WeJA");
const TokenSet = __webpack_require__("IgmS");

class DeviceFlowHandle {
  constructor({
    client, exchangeBody, clientAssertionPayload, response, maxAge,
  }) {
    ['verification_uri', 'user_code', 'device_code'].forEach((prop) => {
      if (typeof response[prop] !== 'string' || !response[prop]) {
        throw new RPError(`expected ${prop} string to be returned by Device Authorization Response, got %j`, response[prop]);
      }
    });

    if (!Number.isSafeInteger(response.expires_in)) {
      throw new RPError('expected expires_in number to be returned by Device Authorization Response, got %j', response.expires_in);
    }

    instance(this).expires_at = now() + response.expires_in;
    instance(this).client = client;
    instance(this).maxAge = maxAge;
    instance(this).exchangeBody = exchangeBody;
    instance(this).clientAssertionPayload = clientAssertionPayload;
    instance(this).response = response;
    instance(this).interval = response.interval * 1000 || 5000;
  }

  async poll() {
    if (this.expired()) {
      throw new RPError('the device code %j has expired and the device authorization session has concluded', this.device_code);
    }

    await new Promise((resolve) => setTimeout(resolve, instance(this).interval));

    const response = await authenticatedPost.call(
      instance(this).client,
      'token',
      {
        form: true,
        body: {
          ...instance(this).exchangeBody,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.device_code,
        },
        json: true,
      },
      { clientAssertionPayload: instance(this).clientAssertionPayload },
    );

    let responseBody;
    try {
      responseBody = processResponse(response);
    } catch (err) {
      switch (err instanceof OPError && err.error) {
        case 'slow_down':
          instance(this).interval += 5000;
        case 'authorization_pending': // eslint-disable-line no-fallthrough
          return this.poll();
        default:
          throw err;
      }
    }

    const tokenset = new TokenSet(responseBody);

    if ('id_token' in tokenset) {
      await instance(this).client.decryptIdToken(tokenset);
      await instance(this).client.validateIdToken(tokenset, undefined, 'token', instance(this).maxAge);
    }

    return tokenset;
  }

  get device_code() {
    return instance(this).response.device_code;
  }

  get user_code() {
    return instance(this).response.user_code;
  }

  get verification_uri() {
    return instance(this).response.verification_uri;
  }

  get verification_uri_complete() {
    return instance(this).response.verification_uri_complete;
  }

  get expires_in() {
    return Math.max.apply(null, [instance(this).expires_at - now(), 0]);
  }

  expired() {
    return this.expires_in === 0;
  }

  /* istanbul ignore next */
  [inspect.custom]() {
    return `${this.constructor.name} ${inspect(instance(this).response, {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true,
    })}`;
  }
}

module.exports = DeviceFlowHandle;


/***/ }),

/***/ "LZmR":
/***/ (function(module, exports) {

module.exports = function pick(object, ...paths) {
  const obj = {};
  for (const path of paths) { // eslint-disable-line no-restricted-syntax
    if (object[path]) {
      obj[path] = object[path];
    }
  }
  return obj;
};


/***/ }),

/***/ "M0E0":
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable no-restricted-syntax, no-continue */

const isPlainObject = __webpack_require__("5j3D");

function defaults(deep, target, ...sources) {
  for (const source of sources) {
    if (!isPlainObject(source)) {
      continue;
    }
    for (const [key, value] of Object.entries(source)) {
      /* istanbul ignore if */
      if (key === '__proto__' || key === 'constructor') {
        continue;
      }
      if (typeof target[key] === 'undefined' && typeof value !== 'undefined') {
        target[key] = value;
      }

      if (deep && isPlainObject(target[key]) && isPlainObject(value)) {
        defaults(true, target[key], value);
      }
    }
  }

  return target;
}

module.exports = defaults.bind(undefined, false);
module.exports.deep = defaults.bind(undefined, true);


/***/ }),

/***/ "M8F5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Hoek = __webpack_require__("e95r");

const Decoder = __webpack_require__("ONme");
const Encoder = __webpack_require__("BzZA");


exports.decode = Decoder.decode;

exports.encode = Encoder.encode;

exports.Decoder = Decoder.Decoder;

exports.Encoder = Encoder.Encoder;


// Base64url (RFC 4648) encode

exports.base64urlEncode = function (value, encoding) {

    Hoek.assert(typeof value === 'string' || Buffer.isBuffer(value), 'value must be string or buffer');
    const buf = (Buffer.isBuffer(value) ? value : Buffer.from(value, encoding || 'binary'));
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
};


// Base64url (RFC 4648) decode

exports.base64urlDecode = function (value, encoding) {

    if (typeof value !== 'string') {

        throw new Error('Value not a string');
    }

    if (!/^[\w\-]*$/.test(value)) {

        throw new Error('Invalid character');
    }

    const buf = Buffer.from(value, 'base64');
    return (encoding === 'buffer' ? buf : buf.toString(encoding || 'binary'));
};


/***/ }),

/***/ "MoRj":
/***/ (function(module, exports, __webpack_require__) {

const { sign: signOneShot, verify: verifyOneShot } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const { edDSASupported } = __webpack_require__("pDDt")

const sign = ({ [KEYOBJECT]: keyObject }, payload) => {
  if (typeof payload === 'string') {
    payload = Buffer.from(payload)
  }
  return signOneShot(undefined, payload, keyObject)
}

const verify = ({ [KEYOBJECT]: keyObject }, payload, signature) => {
  return verifyOneShot(undefined, payload, keyObject, signature)
}

module.exports = (JWA, JWK) => {
  if (edDSASupported) {
    JWA.sign.set('EdDSA', sign)
    JWA.verify.set('EdDSA', verify)
    JWK.OKP.sign.EdDSA = key => key.private && JWK.OKP.verify.EdDSA(key)
    JWK.OKP.verify.EdDSA = key => (key.use === 'sig' || key.use === undefined) && key.keyObject.asymmetricKeyType.startsWith('ed')
  }
}


/***/ }),

/***/ "MrQC":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {Readable} = __webpack_require__("msIP");

module.exports = input => (
	new Readable({
		read() {
			this.push(input);
			this.push(null);
		}
	})
);


/***/ }),

/***/ "Mu3n":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class CookieSessionStoreSettings {
    constructor(settings) {
        this.cookieSecret = settings.cookieSecret;
        if (!this.cookieSecret || !this.cookieSecret.length) {
            throw new Error('The cookieSecret setting is empty or null');
        }
        if (this.cookieSecret.length < 32) {
            throw new Error('The cookieSecret should be at least 32 characters long');
        }
        this.cookieName = settings.cookieName || 'a0:session';
        if (!this.cookieName || !this.cookieName.length) {
            throw new Error('The cookieName setting is empty or null');
        }
        this.cookieSameSite = settings.cookieSameSite;
        if (this.cookieSameSite === undefined) {
            this.cookieSameSite = 'lax';
        }
        this.cookieDomain = settings.cookieDomain || '';
        this.cookieLifetime = settings.cookieLifetime || 60 * 60 * 8;
        this.cookiePath = settings.cookiePath || '/';
        if (!this.cookiePath || !this.cookiePath.length) {
            throw new Error('The cookiePath setting is empty or null');
        }
        this.storeIdToken = settings.storeIdToken || false;
        this.storeAccessToken = settings.storeAccessToken || false;
        this.storeRefreshToken = settings.storeRefreshToken || false;
    }
}
exports.default = CookieSessionStoreSettings;
//# sourceMappingURL=settings.js.map

/***/ }),

/***/ "MuTT":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("0/Ix");


const internals = {
    mismatched: null
};


module.exports = function (obj, ref, options) {

    options = Object.assign({ prototype: true }, options);

    return !!internals.isDeepEqual(obj, ref, options, []);
};


internals.isDeepEqual = function (obj, ref, options, seen) {

    if (obj === ref) {                                                      // Copied from Deep-eql, copyright(c) 2013 Jake Luer, jake@alogicalparadox.com, MIT Licensed, https://github.com/chaijs/deep-eql
        return obj !== 0 || 1 / obj === 1 / ref;
    }

    const type = typeof obj;

    if (type !== typeof ref) {
        return false;
    }

    if (obj === null ||
        ref === null) {

        return false;
    }

    if (type === 'function') {
        if (!options.deepFunction ||
            obj.toString() !== ref.toString()) {

            return false;
        }

        // Continue as object
    }
    else if (type !== 'object') {
        return obj !== obj && ref !== ref;                                  // NaN
    }

    const instanceType = internals.getSharedType(obj, ref, !!options.prototype);
    switch (instanceType) {
        case Types.buffer:
            return Buffer && Buffer.prototype.equals.call(obj, ref);        // $lab:coverage:ignore$
        case Types.promise:
            return obj === ref;
        case Types.regex:
            return obj.toString() === ref.toString();
        case internals.mismatched:
            return false;
    }

    for (let i = seen.length - 1; i >= 0; --i) {
        if (seen[i].isSame(obj, ref)) {
            return true;                                                    // If previous comparison failed, it would have stopped execution
        }
    }

    seen.push(new internals.SeenEntry(obj, ref));

    try {
        return !!internals.isDeepEqualObj(instanceType, obj, ref, options, seen);
    }
    finally {
        seen.pop();
    }
};


internals.getSharedType = function (obj, ref, checkPrototype) {

    if (checkPrototype) {
        if (Object.getPrototypeOf(obj) !== Object.getPrototypeOf(ref)) {
            return internals.mismatched;
        }

        return Types.getInternalProto(obj);
    }

    const type = Types.getInternalProto(obj);
    if (type !== Types.getInternalProto(ref)) {
        return internals.mismatched;
    }

    return type;
};


internals.valueOf = function (obj) {

    const objValueOf = obj.valueOf;
    if (objValueOf === undefined) {
        return obj;
    }

    try {
        return objValueOf.call(obj);
    }
    catch (err) {
        return err;
    }
};


internals.hasOwnEnumerableProperty = function (obj, key) {

    return Object.prototype.propertyIsEnumerable.call(obj, key);
};


internals.isSetSimpleEqual = function (obj, ref) {

    for (const entry of obj) {
        if (!ref.has(entry)) {
            return false;
        }
    }

    return true;
};


internals.isDeepEqualObj = function (instanceType, obj, ref, options, seen) {

    const { isDeepEqual, valueOf, hasOwnEnumerableProperty } = internals;
    const { keys, getOwnPropertySymbols } = Object;

    if (instanceType === Types.array) {
        if (options.part) {

            // Check if any index match any other index

            for (const objValue of obj) {
                for (const refValue of ref) {
                    if (isDeepEqual(objValue, refValue, options, seen)) {
                        return true;
                    }
                }
            }
        }
        else {
            if (obj.length !== ref.length) {
                return false;
            }

            for (let i = 0; i < obj.length; ++i) {
                if (!isDeepEqual(obj[i], ref[i], options, seen)) {
                    return false;
                }
            }

            return true;
        }
    }
    else if (instanceType === Types.set) {
        if (obj.size !== ref.size) {
            return false;
        }

        if (!internals.isSetSimpleEqual(obj, ref)) {

            // Check for deep equality

            const ref2 = new Set(ref);
            for (const objEntry of obj) {
                if (ref2.delete(objEntry)) {
                    continue;
                }

                let found = false;
                for (const refEntry of ref2) {
                    if (isDeepEqual(objEntry, refEntry, options, seen)) {
                        ref2.delete(refEntry);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    return false;
                }
            }
        }
    }
    else if (instanceType === Types.map) {
        if (obj.size !== ref.size) {
            return false;
        }

        for (const [key, value] of obj) {
            if (value === undefined && !ref.has(key)) {
                return false;
            }

            if (!isDeepEqual(value, ref.get(key), options, seen)) {
                return false;
            }
        }
    }
    else if (instanceType === Types.error) {

        // Always check name and message

        if (obj.name !== ref.name ||
            obj.message !== ref.message) {

            return false;
        }
    }

    // Check .valueOf()

    const valueOfObj = valueOf(obj);
    const valueOfRef = valueOf(ref);
    if ((obj !== valueOfObj || ref !== valueOfRef) &&
        !isDeepEqual(valueOfObj, valueOfRef, options, seen)) {

        return false;
    }

    // Check properties

    const objKeys = keys(obj);
    if (!options.part &&
        objKeys.length !== keys(ref).length &&
        !options.skip) {

        return false;
    }

    let skipped = 0;
    for (const key of objKeys) {
        if (options.skip &&
            options.skip.includes(key)) {

            if (ref[key] === undefined) {
                ++skipped;
            }

            continue;
        }

        if (!hasOwnEnumerableProperty(ref, key)) {
            return false;
        }

        if (!isDeepEqual(obj[key], ref[key], options, seen)) {
            return false;
        }
    }

    if (!options.part &&
        objKeys.length - skipped !== keys(ref).length) {

        return false;
    }

    // Check symbols

    if (options.symbols !== false) {                                // Defaults to true
        const objSymbols = getOwnPropertySymbols(obj);
        const refSymbols = new Set(getOwnPropertySymbols(ref));

        for (const key of objSymbols) {
            if (!options.skip ||
                !options.skip.includes(key)) {

                if (hasOwnEnumerableProperty(obj, key)) {
                    if (!hasOwnEnumerableProperty(ref, key)) {
                        return false;
                    }

                    if (!isDeepEqual(obj[key], ref[key], options, seen)) {
                        return false;
                    }
                }
                else if (hasOwnEnumerableProperty(ref, key)) {
                    return false;
                }
            }

            refSymbols.delete(key);
        }

        for (const key of refSymbols) {
            if (hasOwnEnumerableProperty(ref, key)) {
                return false;
            }
        }
    }

    return true;
};


internals.SeenEntry = class {

    constructor(obj, ref) {

        this.obj = obj;
        this.ref = ref;
    }

    isSame(obj, ref) {

        return this.obj === obj && this.ref === ref;
    }
};


/***/ }),

/***/ "N+nT":
/***/ (function(module, exports, __webpack_require__) {

const EC_CURVES = __webpack_require__("b9eJ")
const IVLENGTHS = __webpack_require__("KqF2")
const JWA = __webpack_require__("Fo+H")
const JWK = __webpack_require__("OgAF")
const KEYLENGTHS = __webpack_require__("EB1F")
const OKP_CURVES = __webpack_require__("AlvL")
const ECDH_DERIVE_LENGTHS = __webpack_require__("aOmh")

module.exports = {
  EC_CURVES,
  ECDH_DERIVE_LENGTHS,
  IVLENGTHS,
  JWA,
  JWK,
  KEYLENGTHS,
  OKP_CURVES
}


/***/ }),

/***/ "N+si":
/***/ (function(module, exports) {

function assertSigningAlgValuesSupport(endpoint, issuer, properties) {
  if (!issuer[`${endpoint}_endpoint`]) return;

  const eam = `${endpoint}_endpoint_auth_method`;
  const easa = `${endpoint}_endpoint_auth_signing_alg`;
  const easavs = `${endpoint}_endpoint_auth_signing_alg_values_supported`;

  if (properties[eam] && properties[eam].endsWith('_jwt') && !properties[easa] && !issuer[easavs]) {
    throw new TypeError(`${easavs} must be configured on the issuer if ${easa} is not defined on a client`);
  }
}

function assertIssuerConfiguration(issuer, endpoint) {
  if (!issuer[endpoint]) {
    throw new TypeError(`${endpoint} must be configured on the issuer`);
  }
}

module.exports = {
  assertSigningAlgValuesSupport,
  assertIssuerConfiguration,
};


/***/ }),

/***/ "N6Fi":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

exports.__esModule = true;
exports.pathToRegexp = exports.default = exports.customRouteMatcherOptions = exports.matcherOptions = void 0;

var pathToRegexp = _interopRequireWildcard(__webpack_require__("zOyy"));

exports.pathToRegexp = pathToRegexp;

function _getRequireWildcardCache() {
  if (typeof WeakMap !== "function") return null;
  var cache = new WeakMap();

  _getRequireWildcardCache = function () {
    return cache;
  };

  return cache;
}

function _interopRequireWildcard(obj) {
  if (obj && obj.__esModule) {
    return obj;
  }

  if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
    return {
      default: obj
    };
  }

  var cache = _getRequireWildcardCache();

  if (cache && cache.has(obj)) {
    return cache.get(obj);
  }

  var newObj = {};
  var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;

  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;

      if (desc && (desc.get || desc.set)) {
        Object.defineProperty(newObj, key, desc);
      } else {
        newObj[key] = obj[key];
      }
    }
  }

  newObj.default = obj;

  if (cache) {
    cache.set(obj, newObj);
  }

  return newObj;
}

const matcherOptions = {
  sensitive: false,
  delimiter: '/'
};
exports.matcherOptions = matcherOptions;

const customRouteMatcherOptions = _objectSpread(_objectSpread({}, matcherOptions), {}, {
  strict: true
});

exports.customRouteMatcherOptions = customRouteMatcherOptions;

var _default = (customRoute = false) => {
  return path => {
    const keys = [];
    const matcherRegex = pathToRegexp.pathToRegexp(path, keys, customRoute ? customRouteMatcherOptions : matcherOptions);
    const matcher = pathToRegexp.regexpToFunction(matcherRegex, keys);
    return (pathname, params) => {
      const res = pathname == null ? false : matcher(pathname);

      if (!res) {
        return false;
      }

      if (customRoute) {
        for (const key of keys) {
          // unnamed params should be removed as they
          // are not allowed to be used in the destination
          if (typeof key.name === 'number') {
            delete res.params[key.name];
          }
        }
      }

      return _objectSpread(_objectSpread({}, params), res.params);
    };
  };
};

exports.default = _default;

/***/ }),

/***/ "ND7K":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const base64url_1 = tslib_1.__importDefault(__webpack_require__("+00W"));
const crypto_1 = __webpack_require__("PJMN");
/**
 * Create a state which can include custom data.
 * @param payload
 */
function createState(payload) {
    const stateObject = payload || {};
    stateObject.nonce = createNonce();
    return encodeState(stateObject);
}
exports.createState = createState;
/**
 * Generates a nonce value.
 */
function createNonce() {
    return crypto_1.randomBytes(16).toString('hex');
}
/**
 * Prepare a state object to send.
 */
function encodeState(stateObject) {
    return base64url_1.default.encode(JSON.stringify(stateObject));
}
/**
 * Decode a state value. */
function decodeState(stateValue) {
    const decoded = base64url_1.default.decode(stateValue);
    // Backwards compatibility
    if (decoded.indexOf('{') !== 0) {
        return { nonce: stateValue };
    }
    return JSON.parse(base64url_1.default.decode(stateValue));
}
exports.decodeState = decodeState;
//# sourceMappingURL=state.js.map

/***/ }),

/***/ "NFjz":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const pump = __webpack_require__("b1mx");
const bufferStream = __webpack_require__("E1OP");

class MaxBufferError extends Error {
	constructor() {
		super('maxBuffer exceeded');
		this.name = 'MaxBufferError';
	}
}

function getStream(inputStream, options) {
	if (!inputStream) {
		return Promise.reject(new Error('Expected a stream'));
	}

	options = Object.assign({maxBuffer: Infinity}, options);

	const {maxBuffer} = options;

	let stream;
	return new Promise((resolve, reject) => {
		const rejectPromise = error => {
			if (error) { // A null check
				error.bufferedData = stream.getBufferedValue();
			}
			reject(error);
		};

		stream = pump(inputStream, bufferStream(options), error => {
			if (error) {
				rejectPromise(error);
				return;
			}

			resolve();
		});

		stream.on('data', () => {
			if (stream.getBufferedLength() > maxBuffer) {
				rejectPromise(new MaxBufferError());
			}
		});
	}).then(() => stream.getBufferedValue());
}

module.exports = getStream;
module.exports.buffer = (stream, options) => getStream(stream, Object.assign({}, options, {encoding: 'buffer'}));
module.exports.array = (stream, options) => getStream(stream, Object.assign({}, options, {array: true}));
module.exports.MaxBufferError = MaxBufferError;


/***/ }),

/***/ "NHoT":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const is = __webpack_require__("6mOv");

module.exports = url => {
	const options = {
		protocol: url.protocol,
		hostname: url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname,
		hash: url.hash,
		search: url.search,
		pathname: url.pathname,
		href: url.href
	};

	if (is.string(url.port) && url.port.length > 0) {
		options.port = Number(url.port);
	}

	if (url.username || url.password) {
		options.auth = `${url.username}:${url.password}`;
	}

	options.path = is.null(url.search) ? url.pathname : `${url.pathname}${url.search}`;

	return options;
};


/***/ }),

/***/ "Ndh8":
/***/ (function(module, exports, __webpack_require__) {

const url = __webpack_require__("bzos");
const { strict: assert } = __webpack_require__("Qs3B");

module.exports = (target) => {
  try {
    const { protocol } = new url.URL(target);
    assert(protocol.match(/^(https?:)$/));
    return true;
  } catch (err) {
    throw new TypeError('only valid absolute URLs can be requested');
  }
};


/***/ }),

/***/ "Nfr/":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.flatten = function (array, target) {

    const result = target || [];

    for (let i = 0; i < array.length; ++i) {
        if (Array.isArray(array[i])) {
            internals.flatten(array[i], result);
        }
        else {
            result.push(array[i]);
        }
    }

    return result;
};


/***/ }),

/***/ "Ni7F":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class AccessTokenError extends Error {
    constructor(code, message) {
        super(message);
        // Saving class name in the property of our custom error as a shortcut.
        this.name = this.constructor.name;
        // Capturing stack trace, excluding constructor call from it.
        Error.captureStackTrace(this, this.constructor);
        // Machine readable code.
        this.code = code;
    }
}
exports.default = AccessTokenError;
//# sourceMappingURL=access-token-error.js.map

/***/ }),

/***/ "NjLM":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("xG1e");
const DeepEqual = __webpack_require__("MuTT");
const EscapeRegex = __webpack_require__("Efly");
const Utils = __webpack_require__("f/5Z");


const internals = {};


module.exports = function (ref, values, options = {}) {        // options: { deep, once, only, part, symbols }

    /*
        string -> string(s)
        array -> item(s)
        object -> key(s)
        object -> object (key:value)
    */

    if (typeof values !== 'object') {
        values = [values];
    }

    Assert(!Array.isArray(values) || values.length, 'Values array cannot be empty');

    // String

    if (typeof ref === 'string') {
        return internals.string(ref, values, options);
    }

    // Array

    if (Array.isArray(ref)) {
        return internals.array(ref, values, options);
    }

    // Object

    Assert(typeof ref === 'object', 'Reference must be string or an object');
    return internals.object(ref, values, options);
};


internals.array = function (ref, values, options) {

    if (!Array.isArray(values)) {
        values = [values];
    }

    if (!ref.length) {
        return false;
    }

    if (options.only &&
        options.once &&
        ref.length !== values.length) {

        return false;
    }

    let compare;

    // Map values

    const map = new Map();
    for (const value of values) {
        if (!options.deep ||
            !value ||
            typeof value !== 'object') {

            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
        else {
            compare = compare || internals.compare(options);

            let found = false;
            for (const [key, existing] of map.entries()) {
                if (compare(key, value)) {
                    ++existing.allowed;
                    found = true;
                    break;
                }
            }

            if (!found) {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
    }

    // Lookup values

    let hits = 0;
    for (const item of ref) {
        let match;
        if (!options.deep ||
            !item ||
            typeof item !== 'object') {

            match = map.get(item);
        }
        else {
            for (const [key, existing] of map.entries()) {
                if (compare(key, item)) {
                    match = existing;
                    break;
                }
            }
        }

        if (match) {
            ++match.hits;
            ++hits;

            if (options.once &&
                match.hits > match.allowed) {

                return false;
            }
        }
    }

    // Validate results

    if (options.only &&
        hits !== ref.length) {

        return false;
    }

    for (const match of map.values()) {
        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }
    }

    return !!hits;
};


internals.object = function (ref, values, options) {

    Assert(options.once === undefined, 'Cannot use option once with object');

    const keys = Utils.keys(ref, options);
    if (!keys.length) {
        return false;
    }

    // Keys list

    if (Array.isArray(values)) {
        return internals.array(keys, values, options);
    }

    // Key value pairs

    const symbols = Object.getOwnPropertySymbols(values).filter((sym) => values.propertyIsEnumerable(sym));
    const targets = [...Object.keys(values), ...symbols];

    const compare = internals.compare(options);
    const set = new Set(targets);

    for (const key of keys) {
        if (!set.has(key)) {
            if (options.only) {
                return false;
            }

            continue;
        }

        if (!compare(values[key], ref[key])) {
            return false;
        }

        set.delete(key);
    }

    if (set.size) {
        return options.part ? set.size < targets.length : false;
    }

    return true;
};


internals.string = function (ref, values, options) {

    // Empty string

    if (ref === '') {
        return values.length === 1 && values[0] === '' ||               // '' contains ''
            !options.once && !values.some((v) => v !== '');             // '' contains multiple '' if !once
    }

    // Map values

    const map = new Map();
    const patterns = [];

    for (const value of values) {
        Assert(typeof value === 'string', 'Cannot compare string reference to non-string value');

        if (value) {
            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
                patterns.push(EscapeRegex(value));
            }
        }
        else if (options.once ||
            options.only) {

            return false;
        }
    }

    if (!patterns.length) {                     // Non-empty string contains unlimited empty string
        return true;
    }

    // Match patterns

    const regex = new RegExp(`(${patterns.join('|')})`, 'g');
    const leftovers = ref.replace(regex, ($0, $1) => {

        ++map.get($1).hits;
        return '';                              // Remove from string
    });

    // Validate results

    if (options.only &&
        leftovers) {

        return false;
    }

    let any = false;
    for (const match of map.values()) {
        if (match.hits) {
            any = true;
        }

        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }

        // match.hits > match.allowed

        if (options.once) {
            return false;
        }
    }

    return !!any;
};


internals.compare = function (options) {

    if (!options.deep) {
        return internals.shallow;
    }

    const hasOnly = options.only !== undefined;
    const hasPart = options.part !== undefined;

    const flags = {
        prototype: hasOnly ? options.only : hasPart ? !options.part : false,
        part: hasOnly ? !options.only : hasPart ? options.part : false
    };

    return (a, b) => DeepEqual(a, b, flags);
};


internals.shallow = function (a, b) {

    return a === b;
};


/***/ }),

/***/ "NkYg":
/***/ (function(module, exports) {

module.exports = require("buffer");

/***/ }),

/***/ "Nndd":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.default = '0.16.0';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "NqRk":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function () { };


/***/ }),

/***/ "O3E8":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const openid_client_1 = __webpack_require__("ecj1");
function getClient(settings) {
    let client = null;
    const clientSettings = settings.oidcClient || {
        httpTimeout: 2500
    };
    return () => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (client) {
            return client;
        }
        const issuer = yield openid_client_1.Issuer.discover(`https://${settings.domain}/`);
        client = new issuer.Client({
            client_id: settings.clientId,
            client_secret: settings.clientSecret,
            redirect_uris: [settings.redirectUri],
            response_types: ['code']
        });
        if (clientSettings.httpTimeout) {
            const timeout = clientSettings.httpTimeout;
            client[openid_client_1.custom.http_options] = function setHttpOptions(options) {
                return Object.assign(Object.assign({}, options), { timeout });
            };
        }
        if (clientSettings.clockTolerance) {
            client[openid_client_1.custom.clock_tolerance] = clientSettings.clockTolerance / 1000;
        }
        return client;
    });
}
exports.default = getClient;
//# sourceMappingURL=oidc-client.js.map

/***/ }),

/***/ "O9d4":
/***/ (function(module, exports) {

module.exports = obj => JSON.parse(JSON.stringify(obj))


/***/ }),

/***/ "O9zF":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Readable = __webpack_require__("msIP").Readable;
const lowercaseKeys = __webpack_require__("y1+z");

class Response extends Readable {
	constructor(statusCode, headers, body, url) {
		if (typeof statusCode !== 'number') {
			throw new TypeError('Argument `statusCode` should be a number');
		}
		if (typeof headers !== 'object') {
			throw new TypeError('Argument `headers` should be an object');
		}
		if (!(body instanceof Buffer)) {
			throw new TypeError('Argument `body` should be a buffer');
		}
		if (typeof url !== 'string') {
			throw new TypeError('Argument `url` should be a string');
		}

		super();
		this.statusCode = statusCode;
		this.headers = lowercaseKeys(headers);
		this.body = body;
		this.url = url;
	}

	_read() {
		this.push(this.body);
		this.push(null);
	}
}

module.exports = Response;


/***/ }),

/***/ "OAWW":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.Bench = class {

    constructor() {

        this.ts = 0;
        this.reset();
    }

    reset() {

        this.ts = internals.Bench.now();
    }

    elapsed() {

        return internals.Bench.now() - this.ts;
    }

    static now() {

        const ts = process.hrtime();
        return (ts[0] * 1e3) + (ts[1] / 1e6);
    }
};


/***/ }),

/***/ "OHZa":
/***/ (function(module, exports, __webpack_require__) {

const isDisjoint = __webpack_require__("KQbz")
const base64url = __webpack_require__("Xab3")
let validateCrit = __webpack_require__("urXW")
const { JWEInvalid, JOSENotSupported } = __webpack_require__("yt7c")

validateCrit = validateCrit.bind(undefined, JWEInvalid)

module.exports = (prot, unprotected, recipients, checkAlgorithms, crit) => {
  if (typeof prot === 'string') {
    try {
      prot = base64url.JSON.decode(prot)
    } catch (err) {
      throw new JWEInvalid('could not parse JWE protected header')
    }
  }

  let alg = []
  const enc = new Set()
  if (!isDisjoint(prot, unprotected) || !recipients.every(({ header }) => {
    if (typeof header === 'object') {
      alg.push(header.alg)
      enc.add(header.enc)
    }
    const combined = { ...unprotected, ...header }
    validateCrit(prot, combined, crit)
    if ('zip' in combined) {
      throw new JWEInvalid('"zip" Header Parameter MUST be integrity protected')
    } else if (prot && 'zip' in prot && prot.zip !== 'DEF') {
      throw new JOSENotSupported('only "DEF" compression algorithm is supported')
    }
    return isDisjoint(header, prot) && isDisjoint(header, unprotected)
  })) {
    throw new JWEInvalid('JWE Shared Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint')
  }

  if (typeof prot === 'object') {
    alg.push(prot.alg)
    enc.add(prot.enc)
  }
  if (typeof unprotected === 'object') {
    alg.push(unprotected.alg)
    enc.add(unprotected.enc)
  }

  alg = alg.filter(Boolean)
  enc.delete(undefined)

  if (recipients.length !== 1) {
    if (alg.includes('dir') || alg.includes('ECDH-ES')) {
      throw new JWEInvalid('dir and ECDH-ES alg may only be used with a single recipient')
    }
  }

  if (checkAlgorithms) {
    if (alg.length !== recipients.length) {
      throw new JWEInvalid('missing Key Management algorithm')
    }
    if (enc.size === 0) {
      throw new JWEInvalid('missing Content Encryption algorithm')
    } else if (enc.size !== 1) {
      throw new JWEInvalid('there must only be one Content Encryption algorithm')
    }
  } else {
    if (enc.size > 1) {
      throw new JWEInvalid('there must only be one Content Encryption algorithm')
    }
  }

  return [...enc][0]
}


/***/ }),

/***/ "ONme":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/*
    Decode functions adapted from:
    Version 1.0 12/25/99 Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>
    http://www.onicos.com/staff/iz/amuse/javascript/expert/base64.txt
*/

const Stream = __webpack_require__("msIP");


const internals = {
    decodeChars: [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    ]
};


exports.decode = function (buffer) {

    const decodeChars = internals.decodeChars;
    const len = buffer.length;
    const allocated = Math.ceil(len / 4) * 3;
    const result = Buffer.alloc(allocated);

    let c1;
    let c2;
    let c3;
    let c4;
    let j = 0;

    for (let i = 0; i < len; ) {
        do {
            c1 = decodeChars[buffer[i++] & 0xff];
        }
        while (i < len && c1 === -1);

        if (c1 === -1) {
            break;
        }

        do {
            c2 = decodeChars[buffer[i++] & 0xff];
        }
        while (i < len && c2 === -1);

        if (c2 === -1) {
            break;
        }

        result[j++] = (c1 << 2) | ((c2 & 0x30) >> 4);

        do {
            c3 = buffer[i++] & 0xff;
            if (c3 === 61) {                        // =
                return result.slice(0, j);
            }

            c3 = decodeChars[c3];
        }
        while (i < len && c3 === -1);

        if (c3 === -1) {
            break;
        }

        result[j++] = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);

        do {
            c4 = buffer[i++] & 0xff;
            if (c4 === 61) {                        // =
                return result.slice(0, j);
            }

            c4 = decodeChars[c4];
        }
        while (i < len && c4 === -1);

        if (c4 !== -1) {
            result[j++] = ((c3 & 0x03) << 6) | c4;
        }
    }

    return (j === allocated ? result : result.slice(0, j));
};


exports.Decoder = class Decoder extends Stream.Transform {
    constructor() {

        super();
        this._reminder = null;
    }

    _transform(chunk, encoding, callback) {

        let part = this._reminder ? Buffer.concat([this._reminder, chunk]) : chunk;
        const remaining = part.length % 4;
        if (remaining) {
            this._reminder = part.slice(part.length - remaining);
            part = part.slice(0, part.length - remaining);
        }
        else {
            this._reminder = null;
        }

        this.push(exports.decode(part));
        return callback();
    }

    _flush(callback) {

        if (this._reminder) {
            this.push(exports.decode(this._reminder));
        }

        return callback();
    }
};


/***/ }),

/***/ "OgAF":
/***/ (function(module, exports) {

module.exports = {
  oct: {
    decrypt: {},
    deriveKey: {},
    encrypt: {},
    sign: {},
    unwrapKey: {},
    verify: {},
    wrapKey: {}
  },
  EC: {
    decrypt: {},
    deriveKey: {},
    encrypt: {},
    sign: {},
    unwrapKey: {},
    verify: {},
    wrapKey: {}
  },
  RSA: {
    decrypt: {},
    deriveKey: {},
    encrypt: {},
    sign: {},
    unwrapKey: {},
    verify: {},
    wrapKey: {}
  },
  OKP: {
    decrypt: {},
    deriveKey: {},
    encrypt: {},
    sign: {},
    unwrapKey: {},
    verify: {},
    wrapKey: {}
  }
}


/***/ }),

/***/ "P7tk":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var next_plugin_loader_middleware_on_init_server___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("GX0O");
/* harmony import */ var next_plugin_loader_middleware_on_error_server___WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__("KqAr");
/* harmony import */ var next_dist_next_server_server_node_polyfill_fetch__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__("fkL1");
/* harmony import */ var next_dist_next_server_server_node_polyfill_fetch__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(next_dist_next_server_server_node_polyfill_fetch__WEBPACK_IMPORTED_MODULE_2__);

      
      
      

      
    const { processEnv } = __webpack_require__("fXeI")
    processEnv([{"path":".env","contents":"AUTH0_DOMAIN=dev-yxi32afc.auth0.com\nAUTH0_CLIENT_ID=NWKCY8XY7noa3gp8Xpy2Cs87gPYZ28jf\nAUTH0_CLIENT_SECRET=UbQZj9hK1vUxZHlQjemJnVVqjpf-uQYfeYQ1jJYv9DftSapH6zDL89Xafz4SfaMm\nCOOKIE_SECRET=764vTs4Q4BJq7WpsfQ5mkxgTh7XfzDxC\nMYSQL_HOST = 127.0.0.1\nMYSQL_USERNAME = jonah\nMYSQL_PASSWORD = Admin1234!\nMYSQL_DATABASE = resumate\nMYSQL_PORT = 3306\nAWS_ACCESS_KEY_ID = AKIAJDKFHTAJAXPUFFXQ\nAWS_SECRET_ACCESS_KEY = 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\nAWS_REGION = us-east-1\nUPLOAD_BUCKET = tabgrab-video\n"}])
  
      
      const runtimeConfig = {}
      
      const { parse: parseUrl } = __webpack_require__("bzos")
      const { apiResolver } = __webpack_require__("PCLx")
      
    const { rewrites } = __webpack_require__("Skye")
    const { pathToRegexp, default: pathMatch } = __webpack_require__("N6Fi")
  

      

      

      

      
    const getCustomRouteMatcher = pathMatch(true)
    const prepareDestination = __webpack_require__("6mnf").default

    function handleRewrites(parsedUrl) {
      for (const rewrite of rewrites) {
        const matcher = getCustomRouteMatcher(rewrite.source)
        const params = matcher(parsedUrl.pathname)

        if (params) {
          const { parsedDestination } = prepareDestination(
            rewrite.destination,
            params,
            parsedUrl.query,
            true,
            ""
          )

          Object.assign(parsedUrl.query, parsedDestination.query)
          delete parsedDestination.query

          Object.assign(parsedUrl, parsedDestination)

          if (parsedUrl.pathname === '/api/login'){
            break
          }
          
        }
      }

      return parsedUrl
    }
  

      /* harmony default export */ __webpack_exports__["default"] = (async (req, res) => {
        try {
          await Object(next_plugin_loader_middleware_on_init_server___WEBPACK_IMPORTED_MODULE_0__["default"])()

          // We need to trust the dynamic route params from the proxy
          // to ensure we are using the correct values
          const trustQuery = req.headers['x-vercel-id']
          const parsedUrl = handleRewrites(parseUrl(req.url, true))

          

          const params = {}

          const resolver = __webpack_require__("A4T3")
          await apiResolver(
            req,
            res,
            Object.assign({}, parsedUrl.query, params ),
            resolver,
            {previewModeId:"d963bac48de3ccab82391de76e234e01",previewModeSigningKey:"21942e5990c554d4ded7980cf8873cf20080031ad8bc8d14e746c8093c7b0347",previewModeEncryptionKey:"d784bada93a485e8b4bf5e5fc4b089f218359c7d0b424bbfde486e7b43c65b97"},
            true,
            next_plugin_loader_middleware_on_error_server___WEBPACK_IMPORTED_MODULE_1__["default"]
          )
        } catch (err) {
          console.error(err)
          await Object(next_plugin_loader_middleware_on_error_server___WEBPACK_IMPORTED_MODULE_1__["default"])(err)

          // TODO: better error for DECODE_FAILED?
          if (err.code === 'DECODE_FAILED') {
            res.statusCode = 400
            res.end('Bad Request')
          } else {
            // Throw the error to crash the serverless function
            throw err
          }
        }
      });
    

/***/ }),

/***/ "PC/d":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const login_1 = tslib_1.__importDefault(__webpack_require__("1gXH"));
const logout_1 = tslib_1.__importDefault(__webpack_require__("m2VO"));
const callback_1 = tslib_1.__importDefault(__webpack_require__("5sNo"));
const profile_1 = tslib_1.__importDefault(__webpack_require__("2KX+"));
const session_1 = tslib_1.__importDefault(__webpack_require__("J0Hf"));
const require_authentication_1 = tslib_1.__importDefault(__webpack_require__("9YuQ"));
const token_cache_1 = tslib_1.__importDefault(__webpack_require__("0Kms"));
exports.default = {
    CallbackHandler: callback_1.default,
    LoginHandler: login_1.default,
    LogoutHandler: logout_1.default,
    ProfileHandler: profile_1.default,
    SessionHandler: session_1.default,
    RequireAuthentication: require_authentication_1.default,
    TokenCache: token_cache_1.default
};
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "PCLx":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.apiResolver=apiResolver;exports.parseBody=parseBody;exports.getCookieParser=getCookieParser;exports.sendStatusCode=sendStatusCode;exports.redirect=redirect;exports.sendData=sendData;exports.sendJson=sendJson;exports.tryGetPreviewData=tryGetPreviewData;exports.sendError=sendError;exports.setLazyProp=setLazyProp;exports.ApiError=exports.SYMBOL_PREVIEW_DATA=void 0;var _contentType=__webpack_require__("g6Ax");var _etag=_interopRequireDefault(__webpack_require__("Z3Jd"));var _fresh=_interopRequireDefault(__webpack_require__("IuXR"));var _rawBody=_interopRequireDefault(__webpack_require__("CMUe"));var _stream=__webpack_require__("msIP");var _utils=__webpack_require__("g/15");var _cryptoUtils=__webpack_require__("S6s8");var _loadComponents=__webpack_require__("AWHq");function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{default:obj};}async function apiResolver(req,res,query,resolverModule,apiContext,propagateError,onError){const apiReq=req;const apiRes=res;try{var _config$api,_config$api2;if(!resolverModule){res.statusCode=404;res.end('Not Found');return;}const config=resolverModule.config||{};const bodyParser=((_config$api=config.api)==null?void 0:_config$api.bodyParser)!==false;const externalResolver=((_config$api2=config.api)==null?void 0:_config$api2.externalResolver)||false;// Parsing of cookies
setLazyProp({req:apiReq},'cookies',getCookieParser(req));// Parsing query string
apiReq.query=query;// Parsing preview data
setLazyProp({req:apiReq},'previewData',()=>tryGetPreviewData(req,res,apiContext));// Checking if preview mode is enabled
setLazyProp({req:apiReq},'preview',()=>apiReq.previewData!==false?true:undefined);// Parsing of body
if(bodyParser){apiReq.body=await parseBody(apiReq,config.api&&config.api.bodyParser&&config.api.bodyParser.sizeLimit?config.api.bodyParser.sizeLimit:'1mb');}apiRes.status=statusCode=>sendStatusCode(apiRes,statusCode);apiRes.send=data=>sendData(apiReq,apiRes,data);apiRes.json=data=>sendJson(apiRes,data);apiRes.redirect=(statusOrUrl,url)=>redirect(apiRes,statusOrUrl,url);apiRes.setPreviewData=(data,options={})=>setPreviewData(apiRes,data,Object.assign({},apiContext,options));apiRes.clearPreviewData=()=>clearPreviewData(apiRes);const resolver=(0,_loadComponents.interopDefault)(resolverModule);let wasPiped=false;if(false){}// Call API route method
await resolver(req,res);if(false){}}catch(err){if(err instanceof ApiError){sendError(apiRes,err.statusCode,err.message);}else{console.error(err);if(onError)await onError({err});if(propagateError){throw err;}sendError(apiRes,500,'Internal Server Error');}}}/**
 * Parse incoming message like `json` or `urlencoded`
 * @param req request object
 */async function parseBody(req,limit){const contentType=(0,_contentType.parse)(req.headers['content-type']||'text/plain');const{type,parameters}=contentType;const encoding=parameters.charset||'utf-8';let buffer;try{buffer=await(0,_rawBody.default)(req,{encoding,limit});}catch(e){if(e.type==='entity.too.large'){throw new ApiError(413,`Body exceeded ${limit} limit`);}else{throw new ApiError(400,'Invalid body');}}const body=buffer.toString();if(type==='application/json'||type==='application/ld+json'){return parseJson(body);}else if(type==='application/x-www-form-urlencoded'){const qs=__webpack_require__("8xkj");return qs.decode(body);}else{return body;}}/**
 * Parse `JSON` and handles invalid `JSON` strings
 * @param str `JSON` string
 */function parseJson(str){if(str.length===0){// special-case empty json body, as it's a common client-side mistake
return{};}try{return JSON.parse(str);}catch(e){throw new ApiError(400,'Invalid JSON');}}/**
 * Parse cookies from `req` header
 * @param req request object
 */function getCookieParser(req){return function parseCookie(){const header=req.headers.cookie;if(!header){return{};}const{parse:parseCookieFn}=__webpack_require__("SN/4");return parseCookieFn(Array.isArray(header)?header.join(';'):header);};}/**
 *
 * @param res response object
 * @param statusCode `HTTP` status code of response
 */function sendStatusCode(res,statusCode){res.statusCode=statusCode;return res;}/**
 *
 * @param res response object
 * @param [statusOrUrl] `HTTP` status code of redirect
 * @param url URL of redirect
 */function redirect(res,statusOrUrl,url){if(typeof statusOrUrl==='string'){url=statusOrUrl;statusOrUrl=307;}if(typeof statusOrUrl!=='number'||typeof url!=='string'){throw new Error(`Invalid redirect arguments. Please use a single argument URL, e.g. res.redirect('/destination') or use a status code and URL, e.g. res.redirect(307, '/destination').`);}res.writeHead(statusOrUrl,{Location:url}).end();return res;}function sendEtagResponse(req,res,body){const etag=(0,_etag.default)(body);if((0,_fresh.default)(req.headers,{etag})){res.statusCode=304;res.end();return true;}res.setHeader('ETag',etag);return false;}/**
 * Send `any` body to response
 * @param req request object
 * @param res response object
 * @param body of response
 */function sendData(req,res,body){if(body===null){res.end();return;}const contentType=res.getHeader('Content-Type');if(body instanceof _stream.Stream){if(!contentType){res.setHeader('Content-Type','application/octet-stream');}body.pipe(res);return;}const isJSONLike=['object','number','boolean'].includes(typeof body);const stringifiedBody=isJSONLike?JSON.stringify(body):body;if(sendEtagResponse(req,res,stringifiedBody)){return;}if(Buffer.isBuffer(body)){if(!contentType){res.setHeader('Content-Type','application/octet-stream');}res.setHeader('Content-Length',body.length);res.end(body);return;}if(isJSONLike){res.setHeader('Content-Type','application/json; charset=utf-8');}res.setHeader('Content-Length',Buffer.byteLength(stringifiedBody));res.end(stringifiedBody);}/**
 * Send `JSON` object
 * @param res response object
 * @param jsonBody of data
 */function sendJson(res,jsonBody){// Set header to application/json
res.setHeader('Content-Type','application/json; charset=utf-8');// Use send to handle request
res.send(jsonBody);}const COOKIE_NAME_PRERENDER_BYPASS=`__prerender_bypass`;const COOKIE_NAME_PRERENDER_DATA=`__next_preview_data`;const SYMBOL_PREVIEW_DATA=Symbol(COOKIE_NAME_PRERENDER_DATA);exports.SYMBOL_PREVIEW_DATA=SYMBOL_PREVIEW_DATA;const SYMBOL_CLEARED_COOKIES=Symbol(COOKIE_NAME_PRERENDER_BYPASS);function tryGetPreviewData(req,res,options){// Read cached preview data if present
if(SYMBOL_PREVIEW_DATA in req){return req[SYMBOL_PREVIEW_DATA];}const getCookies=getCookieParser(req);let cookies;try{cookies=getCookies();}catch(_unused){// TODO: warn
return false;}const hasBypass=(COOKIE_NAME_PRERENDER_BYPASS in cookies);const hasData=(COOKIE_NAME_PRERENDER_DATA in cookies);// Case: neither cookie is set.
if(!(hasBypass||hasData)){return false;}// Case: one cookie is set, but not the other.
if(hasBypass!==hasData){clearPreviewData(res);return false;}// Case: preview session is for an old build.
if(cookies[COOKIE_NAME_PRERENDER_BYPASS]!==options.previewModeId){clearPreviewData(res);return false;}const tokenPreviewData=cookies[COOKIE_NAME_PRERENDER_DATA];const jsonwebtoken=__webpack_require__("sJmi");let encryptedPreviewData;try{encryptedPreviewData=jsonwebtoken.verify(tokenPreviewData,options.previewModeSigningKey);}catch(_unused2){// TODO: warn
clearPreviewData(res);return false;}const decryptedPreviewData=(0,_cryptoUtils.decryptWithSecret)(Buffer.from(options.previewModeEncryptionKey),encryptedPreviewData.data);try{// TODO: strict runtime type checking
const data=JSON.parse(decryptedPreviewData);// Cache lookup
Object.defineProperty(req,SYMBOL_PREVIEW_DATA,{value:data,enumerable:false});return data;}catch(_unused3){return false;}}function setPreviewData(res,data,// TODO: strict runtime type checking
options){if(typeof options.previewModeId!=='string'||options.previewModeId.length<16){throw new Error('invariant: invalid previewModeId');}if(typeof options.previewModeEncryptionKey!=='string'||options.previewModeEncryptionKey.length<16){throw new Error('invariant: invalid previewModeEncryptionKey');}if(typeof options.previewModeSigningKey!=='string'||options.previewModeSigningKey.length<16){throw new Error('invariant: invalid previewModeSigningKey');}const jsonwebtoken=__webpack_require__("sJmi");const payload=jsonwebtoken.sign({data:(0,_cryptoUtils.encryptWithSecret)(Buffer.from(options.previewModeEncryptionKey),JSON.stringify(data))},options.previewModeSigningKey,{algorithm:'HS256',...(options.maxAge!==undefined?{expiresIn:options.maxAge}:undefined)});// limit preview mode cookie to 2KB since we shouldn't store too much
// data here and browsers drop cookies over 4KB
if(payload.length>2048){throw new Error(`Preview data is limited to 2KB currently, reduce how much data you are storing as preview data to continue`);}const{serialize}=__webpack_require__("SN/4");const previous=res.getHeader('Set-Cookie');res.setHeader(`Set-Cookie`,[...(typeof previous==='string'?[previous]:Array.isArray(previous)?previous:[]),serialize(COOKIE_NAME_PRERENDER_BYPASS,options.previewModeId,{httpOnly:true,sameSite: true?'none':undefined,secure:"production"!=='development',path:'/',...(options.maxAge!==undefined?{maxAge:options.maxAge}:undefined)}),serialize(COOKIE_NAME_PRERENDER_DATA,payload,{httpOnly:true,sameSite: true?'none':undefined,secure:"production"!=='development',path:'/',...(options.maxAge!==undefined?{maxAge:options.maxAge}:undefined)})]);return res;}function clearPreviewData(res){if(SYMBOL_CLEARED_COOKIES in res){return res;}const{serialize}=__webpack_require__("SN/4");const previous=res.getHeader('Set-Cookie');res.setHeader(`Set-Cookie`,[...(typeof previous==='string'?[previous]:Array.isArray(previous)?previous:[]),serialize(COOKIE_NAME_PRERENDER_BYPASS,'',{// To delete a cookie, set `expires` to a date in the past:
// https://tools.ietf.org/html/rfc6265#section-4.1.1
// `Max-Age: 0` is not valid, thus ignored, and the cookie is persisted.
expires:new Date(0),httpOnly:true,sameSite: true?'none':undefined,secure:"production"!=='development',path:'/'}),serialize(COOKIE_NAME_PRERENDER_DATA,'',{// To delete a cookie, set `expires` to a date in the past:
// https://tools.ietf.org/html/rfc6265#section-4.1.1
// `Max-Age: 0` is not valid, thus ignored, and the cookie is persisted.
expires:new Date(0),httpOnly:true,sameSite: true?'none':undefined,secure:"production"!=='development',path:'/'})]);Object.defineProperty(res,SYMBOL_CLEARED_COOKIES,{value:true,enumerable:false});return res;}/**
 * Custom error class
 */class ApiError extends Error{constructor(statusCode,message){super(message);this.statusCode=void 0;this.statusCode=statusCode;}}/**
 * Sends error in `response`
 * @param res response object
 * @param statusCode of response
 * @param message of response
 */exports.ApiError=ApiError;function sendError(res,statusCode,message){res.statusCode=statusCode;res.statusMessage=message;res.end(message);}/**
 * Execute getter function only if its needed
 * @param LazyProps `req` and `params` for lazyProp
 * @param prop name of property
 * @param getter function to get data
 */function setLazyProp({req,params},prop,getter){const opts={configurable:true,enumerable:true};const optsReset={...opts,writable:true};Object.defineProperty(req,prop,{...opts,get:()=>{let value=getter();if(params&&typeof params!=='boolean'){value={...value,...params};}// we set the property on the object to avoid recalculating it
Object.defineProperty(req,prop,{...optsReset,value});return value;},set:value=>{Object.defineProperty(req,prop,{...optsReset,value});}});}
//# sourceMappingURL=api-utils.js.map

/***/ }),

/***/ "PJMN":
/***/ (function(module, exports) {

module.exports = require("crypto");

/***/ }),

/***/ "PJv+":
/***/ (function(module, exports) {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = function() { return []; };
webpackEmptyContext.resolve = webpackEmptyContext;
module.exports = webpackEmptyContext;
webpackEmptyContext.id = "PJv+";

/***/ }),

/***/ "PTLu":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function intersect(a, b) {
    const set1 = new Set(a);
    const set2 = new Set(b);
    return new Set([...set1].filter((x) => set2.has(x)));
}
exports.intersect = intersect;
function match(arr1, arr2) {
    const set1 = new Set(arr1);
    const set2 = new Set(arr2);
    if (set1.size !== set2.size) {
        return false;
    }
    for (let i = 0; i < arr1.length; i += 1) {
        const item = arr1[i];
        if (!set2.has(item)) {
            return false;
        }
    }
    return true;
}
exports.match = match;
//# sourceMappingURL=array.js.map

/***/ }),

/***/ "PX5Q":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (...args) {

    try {
        return JSON.stringify.apply(null, args);
    }
    catch (err) {
        return '[Cannot display object: ' + err.message + ']';
    }
};


/***/ }),

/***/ "PbSP":
/***/ (function(module, exports) {

module.exports = () => Math.floor(Date.now() / 1000);


/***/ }),

/***/ "PsWn":
/***/ (function(module, exports) {

const MAX_INT32 = Math.pow(2, 32)

module.exports = (value, buf = Buffer.allocUnsafe(8)) => {
  const high = Math.floor(value / MAX_INT32)
  const low = value % MAX_INT32

  buf.writeUInt32BE(high, 0)
  buf.writeUInt32BE(low, 4)
  return buf
}


/***/ }),

/***/ "QBaJ":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("q4ve");


const internals = {};


module.exports = function (attribute) {

    // Allowed value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "

    Assert(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\]*$/.test(attribute), 'Bad attribute value (' + attribute + ')');

    return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');                             // Escape quotes and slash
};


/***/ }),

/***/ "QQHG":
/***/ (function(module, exports, __webpack_require__) {

const { inherits } = __webpack_require__("jK02")

const DERDecoder = __webpack_require__("R7nf")

function PEMDecoder (entity) {
  DERDecoder.call(this, entity)
  this.enc = 'pem'
}
inherits(PEMDecoder, DERDecoder)

PEMDecoder.prototype.decode = function decode (data, options) {
  const lines = data.toString().split(/[\r\n]+/g)

  const label = options.label.toUpperCase()

  const re = /^-----(BEGIN|END) ([^-]+)-----$/
  let start = -1
  let end = -1
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(re)
    if (match === null) { continue }

    if (match[2] !== label) { continue }

    if (start === -1) {
      if (match[1] !== 'BEGIN') { break }
      start = i
    } else {
      if (match[1] !== 'END') { break }
      end = i
      break
    }
  }
  if (start === -1 || end === -1) { throw new Error(`PEM section not found for: ${label}`) }

  const base64 = lines.slice(start + 1, end).join('')
  // Remove excessive symbols
  base64.replace(/[^a-z0-9+/=]+/gi, '')

  const input = Buffer.from(base64, 'base64')
  return DERDecoder.prototype.decode.call(this, input, options)
}

module.exports = PEMDecoder


/***/ }),

/***/ "Qs2e":
/***/ (function(module, exports) {

module.exports = require("net");

/***/ }),

/***/ "Qs3B":
/***/ (function(module, exports) {

module.exports = require("assert");

/***/ }),

/***/ "R0c8":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (timeout) {

    return new Promise((resolve) => setTimeout(resolve, timeout));
};


/***/ }),

/***/ "R7nf":
/***/ (function(module, exports, __webpack_require__) {

/* global BigInt */
const { inherits } = __webpack_require__("jK02")

const { DecoderBuffer } = __webpack_require__("Z9M3")
const Node = __webpack_require__("k+0e")

// Import DER constants
const der = __webpack_require__("1Gj5")

function DERDecoder (entity) {
  this.enc = 'der'
  this.name = entity.name
  this.entity = entity

  // Construct base tree
  this.tree = new DERNode()
  this.tree._init(entity.body)
}

DERDecoder.prototype.decode = function decode (data, options) {
  if (!DecoderBuffer.isDecoderBuffer(data)) {
    data = new DecoderBuffer(data, options)
  }

  return this.tree._decode(data, options)
}

// Tree methods

function DERNode (parent) {
  Node.call(this, 'der', parent)
}
inherits(DERNode, Node)

DERNode.prototype._peekTag = function peekTag (buffer, tag, any) {
  if (buffer.isEmpty()) { return false }

  const state = buffer.save()
  const decodedTag = derDecodeTag(buffer, `Failed to peek tag: "${tag}"`)
  if (buffer.isError(decodedTag)) { return decodedTag }

  buffer.restore(state)

  return decodedTag.tag === tag || decodedTag.tagStr === tag || (decodedTag.tagStr + 'of') === tag || any
}

DERNode.prototype._decodeTag = function decodeTag (buffer, tag, any) {
  const decodedTag = derDecodeTag(buffer,
    `Failed to decode tag of "${tag}"`)
  if (buffer.isError(decodedTag)) { return decodedTag }

  let len = derDecodeLen(buffer,
    decodedTag.primitive,
    `Failed to get length of "${tag}"`)

  // Failure
  if (buffer.isError(len)) { return len }

  if (!any &&
      decodedTag.tag !== tag &&
      decodedTag.tagStr !== tag &&
      decodedTag.tagStr + 'of' !== tag) {
    return buffer.error(`Failed to match tag: "${tag}"`)
  }

  if (decodedTag.primitive || len !== null) { return buffer.skip(len, `Failed to match body of: "${tag}"`) }

  // Indefinite length... find END tag
  const state = buffer.save()
  const res = this._skipUntilEnd(
    buffer,
    `Failed to skip indefinite length body: "${this.tag}"`)
  if (buffer.isError(res)) { return res }

  len = buffer.offset - state.offset
  buffer.restore(state)
  return buffer.skip(len, `Failed to match body of: "${tag}"`)
}

DERNode.prototype._skipUntilEnd = function skipUntilEnd (buffer, fail) {
  for (;;) {
    const tag = derDecodeTag(buffer, fail)
    if (buffer.isError(tag)) { return tag }
    const len = derDecodeLen(buffer, tag.primitive, fail)
    if (buffer.isError(len)) { return len }

    let res
    if (tag.primitive || len !== null) { res = buffer.skip(len) } else { res = this._skipUntilEnd(buffer, fail) }

    // Failure
    if (buffer.isError(res)) { return res }

    if (tag.tagStr === 'end') { break }
  }
}

DERNode.prototype._decodeList = function decodeList (buffer, tag, decoder,
  options) {
  const result = []
  while (!buffer.isEmpty()) {
    const possibleEnd = this._peekTag(buffer, 'end')
    if (buffer.isError(possibleEnd)) { return possibleEnd }

    const res = decoder.decode(buffer, 'der', options)
    if (buffer.isError(res) && possibleEnd) { break }
    result.push(res)
  }
  return result
}

DERNode.prototype._decodeStr = function decodeStr (buffer, tag) {
  if (tag === 'bitstr') {
    const unused = buffer.readUInt8()
    if (buffer.isError(unused)) { return unused }
    return { unused: unused, data: buffer.raw() }
  } else if (tag === 'bmpstr') {
    const raw = buffer.raw()
    if (raw.length % 2 === 1) { return buffer.error('Decoding of string type: bmpstr length mismatch') }

    let str = ''
    for (let i = 0; i < raw.length / 2; i++) {
      str += String.fromCharCode(raw.readUInt16BE(i * 2))
    }
    return str
  } else if (tag === 'numstr') {
    const numstr = buffer.raw().toString('ascii')
    if (!this._isNumstr(numstr)) {
      return buffer.error('Decoding of string type: numstr unsupported characters')
    }
    return numstr
  } else if (tag === 'octstr') {
    return buffer.raw()
  } else if (tag === 'objDesc') {
    return buffer.raw()
  } else if (tag === 'printstr') {
    const printstr = buffer.raw().toString('ascii')
    if (!this._isPrintstr(printstr)) {
      return buffer.error('Decoding of string type: printstr unsupported characters')
    }
    return printstr
  } else if (/str$/.test(tag)) {
    return buffer.raw().toString()
  } else {
    return buffer.error(`Decoding of string type: ${tag} unsupported`)
  }
}

DERNode.prototype._decodeObjid = function decodeObjid (buffer, values, relative) {
  let result
  const identifiers = []
  let ident = 0
  let subident = 0
  while (!buffer.isEmpty()) {
    subident = buffer.readUInt8()
    ident <<= 7
    ident |= subident & 0x7f
    if ((subident & 0x80) === 0) {
      identifiers.push(ident)
      ident = 0
    }
  }
  if (subident & 0x80) { identifiers.push(ident) }

  const first = (identifiers[0] / 40) | 0
  const second = identifiers[0] % 40

  if (relative) { result = identifiers } else { result = [first, second].concat(identifiers.slice(1)) }

  if (values) {
    let tmp = values[result.join(' ')]
    if (tmp === undefined) { tmp = values[result.join('.')] }
    if (tmp !== undefined) { result = tmp }
  }

  return result
}

DERNode.prototype._decodeTime = function decodeTime (buffer, tag) {
  const str = buffer.raw().toString()

  let year
  let mon
  let day
  let hour
  let min
  let sec
  if (tag === 'gentime') {
    year = str.slice(0, 4) | 0
    mon = str.slice(4, 6) | 0
    day = str.slice(6, 8) | 0
    hour = str.slice(8, 10) | 0
    min = str.slice(10, 12) | 0
    sec = str.slice(12, 14) | 0
  } else if (tag === 'utctime') {
    year = str.slice(0, 2) | 0
    mon = str.slice(2, 4) | 0
    day = str.slice(4, 6) | 0
    hour = str.slice(6, 8) | 0
    min = str.slice(8, 10) | 0
    sec = str.slice(10, 12) | 0
    if (year < 70) { year = 2000 + year } else { year = 1900 + year }
  } else {
    return buffer.error(`Decoding ${tag} time is not supported yet`)
  }

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0)
}

DERNode.prototype._decodeNull = function decodeNull () {
  return null
}

DERNode.prototype._decodeBool = function decodeBool (buffer) {
  const res = buffer.readUInt8()
  if (buffer.isError(res)) { return res } else { return res !== 0 }
}

DERNode.prototype._decodeInt = function decodeInt (buffer, values) {
  // Bigint, return as it is (assume big endian)
  const raw = buffer.raw()
  let res = BigInt(`0x${raw.toString('hex')}`)

  if (values) {
    res = values[res.toString(10)] || res
  }

  return res
}

DERNode.prototype._use = function use (entity, obj) {
  if (typeof entity === 'function') { entity = entity(obj) }
  return entity._getDecoder('der').tree
}

// Utility methods

function derDecodeTag (buf, fail) {
  let tag = buf.readUInt8(fail)
  if (buf.isError(tag)) { return tag }

  const cls = der.tagClass[tag >> 6]
  const primitive = (tag & 0x20) === 0

  // Multi-octet tag - load
  if ((tag & 0x1f) === 0x1f) {
    let oct = tag
    tag = 0
    while ((oct & 0x80) === 0x80) {
      oct = buf.readUInt8(fail)
      if (buf.isError(oct)) { return oct }

      tag <<= 7
      tag |= oct & 0x7f
    }
  } else {
    tag &= 0x1f
  }
  const tagStr = der.tag[tag]

  return {
    cls: cls,
    primitive: primitive,
    tag: tag,
    tagStr: tagStr
  }
}

function derDecodeLen (buf, primitive, fail) {
  let len = buf.readUInt8(fail)
  if (buf.isError(len)) { return len }

  // Indefinite form
  if (!primitive && len === 0x80) { return null }

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len
  }

  // Long form
  const num = len & 0x7f
  if (num > 4) { return buf.error('length octect is too long') }

  len = 0
  for (let i = 0; i < num; i++) {
    len <<= 8
    const j = buf.readUInt8(fail)
    if (buf.isError(j)) { return j }
    len |= j
  }

  return len
}

module.exports = DERDecoder


/***/ }),

/***/ "RF0s":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var pad_string_1 = __webpack_require__("vUsp");
function encode(input, encoding) {
    if (encoding === void 0) { encoding = "utf8"; }
    if (Buffer.isBuffer(input)) {
        return fromBase64(input.toString("base64"));
    }
    return fromBase64(Buffer.from(input, encoding).toString("base64"));
}
;
function decode(base64url, encoding) {
    if (encoding === void 0) { encoding = "utf8"; }
    return Buffer.from(toBase64(base64url), "base64").toString(encoding);
}
function toBase64(base64url) {
    base64url = base64url.toString();
    return pad_string_1.default(base64url)
        .replace(/\-/g, "+")
        .replace(/_/g, "/");
}
function fromBase64(base64) {
    return base64
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}
function toBuffer(base64url) {
    return Buffer.from(toBase64(base64url), "base64");
}
var base64url = encode;
base64url.encode = encode;
base64url.decode = decode;
base64url.toBase64 = toBase64;
base64url.fromBase64 = fromBase64;
base64url.toBuffer = toBuffer;
exports.default = base64url;


/***/ }),

/***/ "RFts":
/***/ (function(module, exports, __webpack_require__) {

const { improvedDH } = __webpack_require__("pDDt")

if (improvedDH) {
  const { diffieHellman } = __webpack_require__("PJMN")

  const { KeyObject } = __webpack_require__("1ALl")
  const importKey = __webpack_require__("GhER")

  module.exports = ({ keyObject: privateKey }, publicKey) => {
    if (!(publicKey instanceof KeyObject)) {
      ({ keyObject: publicKey } = importKey(publicKey))
    }

    return diffieHellman({ privateKey, publicKey })
  }
} else {
  const { createECDH, constants: { POINT_CONVERSION_UNCOMPRESSED } } = __webpack_require__("PJMN")

  const base64url = __webpack_require__("Xab3")

  const crvToCurve = (crv) => {
    switch (crv) {
      case 'P-256':
        return 'prime256v1'
      case 'P-384':
        return 'secp384r1'
      case 'P-521':
        return 'secp521r1'
    }
  }

  const UNCOMPRESSED = Buffer.alloc(1, POINT_CONVERSION_UNCOMPRESSED)
  const pubToBuffer = (x, y) => Buffer.concat([UNCOMPRESSED, base64url.decodeToBuffer(x), base64url.decodeToBuffer(y)])

  module.exports = ({ crv, d }, { x, y }) => {
    const curve = crvToCurve(crv)
    const exchange = createECDH(curve)

    exchange.setPrivateKey(base64url.decodeToBuffer(d))

    return exchange.computeSecret(pubToBuffer(x, y))
  }
}


/***/ }),

/***/ "RGIU":
/***/ (function(module, exports, __webpack_require__) {

const { randomBytes } = __webpack_require__("PJMN")

const { createSecretKey } = __webpack_require__("1ALl")
const { KEYLENGTHS } = __webpack_require__("N+nT")
const Key = __webpack_require__("BBt9")

module.exports = (alg) => {
  const keyLength = KEYLENGTHS.get(alg)

  if (!keyLength) {
    return new Key({ type: 'secret' })
  }

  return new Key(createSecretKey(randomBytes(keyLength / 8)), { use: 'enc', alg })
}


/***/ }),

/***/ "RIp3":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var crypto = __webpack_require__("PJMN");

/**
 * Exported function
 *
 * Options:
 *
 *  - `algorithm` hash algo to be used by this instance: *'sha1', 'md5'
 *  - `excludeValues` {true|*false} hash object keys, values ignored
 *  - `encoding` hash encoding, supports 'buffer', '*hex', 'binary', 'base64'
 *  - `ignoreUnknown` {true|*false} ignore unknown object types
 *  - `replacer` optional function that replaces values before hashing
 *  - `respectFunctionProperties` {*true|false} consider function properties when hashing
 *  - `respectFunctionNames` {*true|false} consider 'name' property of functions for hashing
 *  - `respectType` {*true|false} Respect special properties (prototype, constructor)
 *    when hashing to distinguish between types
 *  - `unorderedArrays` {true|*false} Sort all arrays before hashing
 *  - `unorderedSets` {*true|false} Sort `Set` and `Map` instances before hashing
 *  * = default
 *
 * @param {object} object value to hash
 * @param {object} options hashing options
 * @return {string} hash value
 * @api public
 */
exports = module.exports = objectHash;

function objectHash(object, options){
  options = applyDefaults(object, options);

  return hash(object, options);
}

/**
 * Exported sugar methods
 *
 * @param {object} object value to hash
 * @return {string} hash value
 * @api public
 */
exports.sha1 = function(object){
  return objectHash(object);
};
exports.keys = function(object){
  return objectHash(object, {excludeValues: true, algorithm: 'sha1', encoding: 'hex'});
};
exports.MD5 = function(object){
  return objectHash(object, {algorithm: 'md5', encoding: 'hex'});
};
exports.keysMD5 = function(object){
  return objectHash(object, {algorithm: 'md5', encoding: 'hex', excludeValues: true});
};

// Internals
var hashes = crypto.getHashes ? crypto.getHashes().slice() : ['sha1', 'md5'];
hashes.push('passthrough');
var encodings = ['buffer', 'hex', 'binary', 'base64'];

function applyDefaults(object, sourceOptions){
  sourceOptions = sourceOptions || {};

  // create a copy rather than mutating
  var options = {};
  options.algorithm = sourceOptions.algorithm || 'sha1';
  options.encoding = sourceOptions.encoding || 'hex';
  options.excludeValues = sourceOptions.excludeValues ? true : false;
  options.algorithm = options.algorithm.toLowerCase();
  options.encoding = options.encoding.toLowerCase();
  options.ignoreUnknown = sourceOptions.ignoreUnknown !== true ? false : true; // default to false
  options.respectType = sourceOptions.respectType === false ? false : true; // default to true
  options.respectFunctionNames = sourceOptions.respectFunctionNames === false ? false : true;
  options.respectFunctionProperties = sourceOptions.respectFunctionProperties === false ? false : true;
  options.unorderedArrays = sourceOptions.unorderedArrays !== true ? false : true; // default to false
  options.unorderedSets = sourceOptions.unorderedSets === false ? false : true; // default to false
  options.unorderedObjects = sourceOptions.unorderedObjects === false ? false : true; // default to true
  options.replacer = sourceOptions.replacer || undefined;
  options.excludeKeys = sourceOptions.excludeKeys || undefined;

  if(typeof object === 'undefined') {
    throw new Error('Object argument required.');
  }

  // if there is a case-insensitive match in the hashes list, accept it
  // (i.e. SHA256 for sha256)
  for (var i = 0; i < hashes.length; ++i) {
    if (hashes[i].toLowerCase() === options.algorithm.toLowerCase()) {
      options.algorithm = hashes[i];
    }
  }

  if(hashes.indexOf(options.algorithm) === -1){
    throw new Error('Algorithm "' + options.algorithm + '"  not supported. ' +
      'supported values: ' + hashes.join(', '));
  }

  if(encodings.indexOf(options.encoding) === -1 &&
     options.algorithm !== 'passthrough'){
    throw new Error('Encoding "' + options.encoding + '"  not supported. ' +
      'supported values: ' + encodings.join(', '));
  }

  return options;
}

/** Check if the given function is a native function */
function isNativeFunction(f) {
  if ((typeof f) !== 'function') {
    return false;
  }
  var exp = /^function\s+\w*\s*\(\s*\)\s*{\s+\[native code\]\s+}$/i;
  return exp.exec(Function.prototype.toString.call(f)) != null;
}

function hash(object, options) {
  var hashingStream;

  if (options.algorithm !== 'passthrough') {
    hashingStream = crypto.createHash(options.algorithm);
  } else {
    hashingStream = new PassThrough();
  }

  if (typeof hashingStream.write === 'undefined') {
    hashingStream.write = hashingStream.update;
    hashingStream.end   = hashingStream.update;
  }

  var hasher = typeHasher(options, hashingStream);
  hasher.dispatch(object);
  if (!hashingStream.update) {
    hashingStream.end('');
  }

  if (hashingStream.digest) {
    return hashingStream.digest(options.encoding === 'buffer' ? undefined : options.encoding);
  }

  var buf = hashingStream.read();
  if (options.encoding === 'buffer') {
    return buf;
  }

  return buf.toString(options.encoding);
}

/**
 * Expose streaming API
 *
 * @param {object} object  Value to serialize
 * @param {object} options  Options, as for hash()
 * @param {object} stream  A stream to write the serializiation to
 * @api public
 */
exports.writeToStream = function(object, options, stream) {
  if (typeof stream === 'undefined') {
    stream = options;
    options = {};
  }

  options = applyDefaults(object, options);

  return typeHasher(options, stream).dispatch(object);
};

function typeHasher(options, writeTo, context){
  context = context || [];
  var write = function(str) {
    if (writeTo.update) {
      return writeTo.update(str, 'utf8');
    } else {
      return writeTo.write(str, 'utf8');
    }
  };

  return {
    dispatch: function(value){
      if (options.replacer) {
        value = options.replacer(value);
      }

      var type = typeof value;
      if (value === null) {
        type = 'null';
      }

      //console.log("[DEBUG] Dispatch: ", value, "->", type, " -> ", "_" + type);

      return this['_' + type](value);
    },
    _object: function(object) {
      var pattern = (/\[object (.*)\]/i);
      var objString = Object.prototype.toString.call(object);
      var objType = pattern.exec(objString);
      if (!objType) { // object type did not match [object ...]
        objType = 'unknown:[' + objString + ']';
      } else {
        objType = objType[1]; // take only the class name
      }

      objType = objType.toLowerCase();

      var objectNumber = null;

      if ((objectNumber = context.indexOf(object)) >= 0) {
        return this.dispatch('[CIRCULAR:' + objectNumber + ']');
      } else {
        context.push(object);
      }

      if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(object)) {
        write('buffer:');
        return write(object);
      }

      if(objType !== 'object' && objType !== 'function' && objType !== 'asyncfunction') {
        if(this['_' + objType]) {
          this['_' + objType](object);
        } else if (options.ignoreUnknown) {
          return write('[' + objType + ']');
        } else {
          throw new Error('Unknown object type "' + objType + '"');
        }
      }else{
        var keys = Object.keys(object);
        if (options.unorderedObjects) {
          keys = keys.sort();
        }
        // Make sure to incorporate special properties, so
        // Types with different prototypes will produce
        // a different hash and objects derived from
        // different functions (`new Foo`, `new Bar`) will
        // produce different hashes.
        // We never do this for native functions since some
        // seem to break because of that.
        if (options.respectType !== false && !isNativeFunction(object)) {
          keys.splice(0, 0, 'prototype', '__proto__', 'constructor');
        }

        if (options.excludeKeys) {
          keys = keys.filter(function(key) { return !options.excludeKeys(key); });
        }

        write('object:' + keys.length + ':');
        var self = this;
        return keys.forEach(function(key){
          self.dispatch(key);
          write(':');
          if(!options.excludeValues) {
            self.dispatch(object[key]);
          }
          write(',');
        });
      }
    },
    _array: function(arr, unordered){
      unordered = typeof unordered !== 'undefined' ? unordered :
        options.unorderedArrays !== false; // default to options.unorderedArrays

      var self = this;
      write('array:' + arr.length + ':');
      if (!unordered || arr.length <= 1) {
        return arr.forEach(function(entry) {
          return self.dispatch(entry);
        });
      }

      // the unordered case is a little more complicated:
      // since there is no canonical ordering on objects,
      // i.e. {a:1} < {a:2} and {a:1} > {a:2} are both false,
      // we first serialize each entry using a PassThrough stream
      // before sorting.
      // also: we can’t use the same context array for all entries
      // since the order of hashing should *not* matter. instead,
      // we keep track of the additions to a copy of the context array
      // and add all of them to the global context array when we’re done
      var contextAdditions = [];
      var entries = arr.map(function(entry) {
        var strm = new PassThrough();
        var localContext = context.slice(); // make copy
        var hasher = typeHasher(options, strm, localContext);
        hasher.dispatch(entry);
        // take only what was added to localContext and append it to contextAdditions
        contextAdditions = contextAdditions.concat(localContext.slice(context.length));
        return strm.read().toString();
      });
      context = context.concat(contextAdditions);
      entries.sort();
      return this._array(entries, false);
    },
    _date: function(date){
      return write('date:' + date.toJSON());
    },
    _symbol: function(sym){
      return write('symbol:' + sym.toString());
    },
    _error: function(err){
      return write('error:' + err.toString());
    },
    _boolean: function(bool){
      return write('bool:' + bool.toString());
    },
    _string: function(string){
      write('string:' + string.length + ':');
      write(string.toString());
    },
    _function: function(fn){
      write('fn:');
      if (isNativeFunction(fn)) {
        this.dispatch('[native]');
      } else {
        this.dispatch(fn.toString());
      }

      if (options.respectFunctionNames !== false) {
        // Make sure we can still distinguish native functions
        // by their name, otherwise String and Function will
        // have the same hash
        this.dispatch("function-name:" + String(fn.name));
      }

      if (options.respectFunctionProperties) {
        this._object(fn);
      }
    },
    _number: function(number){
      return write('number:' + number.toString());
    },
    _xml: function(xml){
      return write('xml:' + xml.toString());
    },
    _null: function() {
      return write('Null');
    },
    _undefined: function() {
      return write('Undefined');
    },
    _regexp: function(regex){
      return write('regex:' + regex.toString());
    },
    _uint8array: function(arr){
      write('uint8array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _uint8clampedarray: function(arr){
      write('uint8clampedarray:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _int8array: function(arr){
      write('uint8array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _uint16array: function(arr){
      write('uint16array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _int16array: function(arr){
      write('uint16array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _uint32array: function(arr){
      write('uint32array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _int32array: function(arr){
      write('uint32array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _float32array: function(arr){
      write('float32array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _float64array: function(arr){
      write('float64array:');
      return this.dispatch(Array.prototype.slice.call(arr));
    },
    _arraybuffer: function(arr){
      write('arraybuffer:');
      return this.dispatch(new Uint8Array(arr));
    },
    _url: function(url) {
      return write('url:' + url.toString(), 'utf8');
    },
    _map: function(map) {
      write('map:');
      var arr = Array.from(map);
      return this._array(arr, options.unorderedSets !== false);
    },
    _set: function(set) {
      write('set:');
      var arr = Array.from(set);
      return this._array(arr, options.unorderedSets !== false);
    },
    _blob: function() {
      if (options.ignoreUnknown) {
        return write('[blob]');
      }

      throw Error('Hashing Blob objects is currently not supported\n' +
        '(see https://github.com/puleos/object-hash/issues/26)\n' +
        'Use "options.replacer" or "options.ignoreUnknown"\n');
    },
    _domwindow: function() { return write('domwindow'); },
    /* Node.js standard native objects */
    _process: function() { return write('process'); },
    _timer: function() { return write('timer'); },
    _pipe: function() { return write('pipe'); },
    _tcp: function() { return write('tcp'); },
    _udp: function() { return write('udp'); },
    _tty: function() { return write('tty'); },
    _statwatcher: function() { return write('statwatcher'); },
    _securecontext: function() { return write('securecontext'); },
    _connection: function() { return write('connection'); },
    _zlib: function() { return write('zlib'); },
    _context: function() { return write('context'); },
    _nodescript: function() { return write('nodescript'); },
    _httpparser: function() { return write('httpparser'); },
    _dataview: function() { return write('dataview'); },
    _signal: function() { return write('signal'); },
    _fsevent: function() { return write('fsevent'); },
    _tlswrap: function() { return write('tlswrap'); }
  };
}

// Mini-implementation of stream.PassThrough
// We are far from having need for the full implementation, and we can
// make assumptions like "many writes, then only one final read"
// and we can ignore encoding specifics
function PassThrough() {
  return {
    buf: '',

    write: function(b) {
      this.buf += b;
    },

    end: function(b) {
      this.buf += b;
    },

    read: function() {
      return this.buf;
    }
  };
}


/***/ }),

/***/ "Ra3S":
/***/ (function(module, exports) {

module.exports = function () {
  this.seq().obj(
    this.key('version').int({ 0: 'two-prime', 1: 'multi' }),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int()
  )
}


/***/ }),

/***/ "RoCg":
/***/ (function(module, exports, __webpack_require__) {

const { generateKeyPairSync, generateKeyPair: async } = __webpack_require__("PJMN")
const { promisify } = __webpack_require__("jK02")

const {
  THUMBPRINT_MATERIAL, JWK_MEMBERS, PUBLIC_MEMBERS,
  PRIVATE_MEMBERS, KEY_MANAGEMENT_DECRYPT, KEY_MANAGEMENT_ENCRYPT
} = __webpack_require__("ehsS")
const { keyObjectSupported } = __webpack_require__("pDDt")
const { createPublicKey, createPrivateKey } = __webpack_require__("1ALl")

const Key = __webpack_require__("//Cd")

const generateKeyPair = promisify(async)

const RSA_PUBLIC = new Set(['e', 'n'])
Object.freeze(RSA_PUBLIC)
const RSA_PRIVATE = new Set([...RSA_PUBLIC, 'd', 'p', 'q', 'dp', 'dq', 'qi'])
Object.freeze(RSA_PRIVATE)

// RSA Key Type
class RSAKey extends Key {
  constructor (...args) {
    super(...args)
    this[JWK_MEMBERS]()
    Object.defineProperties(this, {
      kty: {
        value: 'RSA',
        enumerable: true
      },
      length: {
        get () {
          Object.defineProperty(this, 'length', {
            value: Buffer.byteLength(this.n, 'base64') * 8,
            configurable: false
          })

          return this.length
        },
        configurable: true
      }
    })
  }

  static get [PUBLIC_MEMBERS] () {
    return RSA_PUBLIC
  }

  static get [PRIVATE_MEMBERS] () {
    return RSA_PRIVATE
  }

  // https://tc39.github.io/ecma262/#sec-ordinaryownpropertykeys no need for any special
  // JSON.stringify handling in V8
  [THUMBPRINT_MATERIAL] () {
    return { e: this.e, kty: 'RSA', n: this.n }
  }

  [KEY_MANAGEMENT_ENCRYPT] () {
    return this.algorithms('wrapKey')
  }

  [KEY_MANAGEMENT_DECRYPT] () {
    return this.algorithms('unwrapKey')
  }

  static async generate (len = 2048, privat = true) {
    if (!Number.isSafeInteger(len) || len < 512 || len % 8 !== 0 || (('electron' in process.versions) && len % 128 !== 0)) {
      throw new TypeError('invalid bit length')
    }

    let privateKey, publicKey

    if (keyObjectSupported) {
      ({ privateKey, publicKey } = await generateKeyPair('rsa', { modulusLength: len }))
      return privat ? privateKey : publicKey
    }

    ({ privateKey, publicKey } = await generateKeyPair('rsa', {
      modulusLength: len,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }))

    if (privat) {
      return createPrivateKey(privateKey)
    } else {
      return createPublicKey(publicKey)
    }
  }

  static generateSync (len = 2048, privat = true) {
    if (!Number.isSafeInteger(len) || len < 512 || len % 8 !== 0 || (('electron' in process.versions) && len % 128 !== 0)) {
      throw new TypeError('invalid bit length')
    }

    let privateKey, publicKey

    if (keyObjectSupported) {
      ({ privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: len }))
      return privat ? privateKey : publicKey
    }

    ({ privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: len,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }))

    if (privat) {
      return createPrivateKey(privateKey)
    } else {
      return createPublicKey(publicKey)
    }
  }
}

module.exports = RSAKey


/***/ }),

/***/ "S6im":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = (string, count = 1, options) => {
	options = {
		indent: ' ',
		includeEmptyLines: false,
		...options
	};

	if (typeof string !== 'string') {
		throw new TypeError(
			`Expected \`input\` to be a \`string\`, got \`${typeof string}\``
		);
	}

	if (typeof count !== 'number') {
		throw new TypeError(
			`Expected \`count\` to be a \`number\`, got \`${typeof count}\``
		);
	}

	if (typeof options.indent !== 'string') {
		throw new TypeError(
			`Expected \`options.indent\` to be a \`string\`, got \`${typeof options.indent}\``
		);
	}

	if (count === 0) {
		return string;
	}

	const regex = options.includeEmptyLines ? /^/gm : /^(?!\s*$)/gm;

	return string.replace(regex, options.indent.repeat(count));
};


/***/ }),

/***/ "S6s8":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.encryptWithSecret=encryptWithSecret;exports.decryptWithSecret=decryptWithSecret;var _crypto=_interopRequireDefault(__webpack_require__("PJMN"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{default:obj};}// Background:
// https://security.stackexchange.com/questions/184305/why-would-i-ever-use-aes-256-cbc-if-aes-256-gcm-is-more-secure
const CIPHER_ALGORITHM=`aes-256-gcm`,CIPHER_KEY_LENGTH=32,// https://stackoverflow.com/a/28307668/4397028
CIPHER_IV_LENGTH=16,// https://stackoverflow.com/a/28307668/4397028
CIPHER_TAG_LENGTH=16,CIPHER_SALT_LENGTH=64;const PBKDF2_ITERATIONS=100000;// https://support.1password.com/pbkdf2/
function encryptWithSecret(secret,data){const iv=_crypto.default.randomBytes(CIPHER_IV_LENGTH);const salt=_crypto.default.randomBytes(CIPHER_SALT_LENGTH);// https://nodejs.org/api/crypto.html#crypto_crypto_pbkdf2sync_password_salt_iterations_keylen_digest
const key=_crypto.default.pbkdf2Sync(secret,salt,PBKDF2_ITERATIONS,CIPHER_KEY_LENGTH,`sha512`);const cipher=_crypto.default.createCipheriv(CIPHER_ALGORITHM,key,iv);const encrypted=Buffer.concat([cipher.update(data,`utf8`),cipher.final()]);// https://nodejs.org/api/crypto.html#crypto_cipher_getauthtag
const tag=cipher.getAuthTag();return Buffer.concat([// Data as required by:
// Salt for Key: https://nodejs.org/api/crypto.html#crypto_crypto_pbkdf2sync_password_salt_iterations_keylen_digest
// IV: https://nodejs.org/api/crypto.html#crypto_class_decipher
// Tag: https://nodejs.org/api/crypto.html#crypto_decipher_setauthtag_buffer
salt,iv,tag,encrypted]).toString(`hex`);}function decryptWithSecret(secret,encryptedData){const buffer=Buffer.from(encryptedData,`hex`);const salt=buffer.slice(0,CIPHER_SALT_LENGTH);const iv=buffer.slice(CIPHER_SALT_LENGTH,CIPHER_SALT_LENGTH+CIPHER_IV_LENGTH);const tag=buffer.slice(CIPHER_SALT_LENGTH+CIPHER_IV_LENGTH,CIPHER_SALT_LENGTH+CIPHER_IV_LENGTH+CIPHER_TAG_LENGTH);const encrypted=buffer.slice(CIPHER_SALT_LENGTH+CIPHER_IV_LENGTH+CIPHER_TAG_LENGTH);// https://nodejs.org/api/crypto.html#crypto_crypto_pbkdf2sync_password_salt_iterations_keylen_digest
const key=_crypto.default.pbkdf2Sync(secret,salt,PBKDF2_ITERATIONS,CIPHER_KEY_LENGTH,`sha512`);const decipher=_crypto.default.createDecipheriv(CIPHER_ALGORITHM,key,iv);decipher.setAuthTag(tag);return decipher.update(encrypted)+decipher.final(`utf8`);}
//# sourceMappingURL=crypto-utils.js.map

/***/ }),

/***/ "SN/4":
/***/ (function(module, exports) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,r){"use strict";var t={};function __webpack_require__(r){if(t[r]){return t[r].exports}var i=t[r]={i:r,l:false,exports:{}};e[r].call(i.exports,i,i.exports,__webpack_require__);i.l=true;return i.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(693)}return startup()}({693:function(e,r){"use strict";r.parse=parse;r.serialize=serialize;var t=decodeURIComponent;var i=encodeURIComponent;var a=/; */;var n=/^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;function parse(e,r){if(typeof e!=="string"){throw new TypeError("argument str must be a string")}var i={};var n=r||{};var o=e.split(a);var s=n.decode||t;for(var p=0;p<o.length;p++){var u=o[p];var f=u.indexOf("=");if(f<0){continue}var c=u.substr(0,f).trim();var v=u.substr(++f,u.length).trim();if('"'==v[0]){v=v.slice(1,-1)}if(undefined==i[c]){i[c]=tryDecode(v,s)}}return i}function serialize(e,r,t){var a=t||{};var o=a.encode||i;if(typeof o!=="function"){throw new TypeError("option encode is invalid")}if(!n.test(e)){throw new TypeError("argument name is invalid")}var s=o(r);if(s&&!n.test(s)){throw new TypeError("argument val is invalid")}var p=e+"="+s;if(null!=a.maxAge){var u=a.maxAge-0;if(isNaN(u)||!isFinite(u)){throw new TypeError("option maxAge is invalid")}p+="; Max-Age="+Math.floor(u)}if(a.domain){if(!n.test(a.domain)){throw new TypeError("option domain is invalid")}p+="; Domain="+a.domain}if(a.path){if(!n.test(a.path)){throw new TypeError("option path is invalid")}p+="; Path="+a.path}if(a.expires){if(typeof a.expires.toUTCString!=="function"){throw new TypeError("option expires is invalid")}p+="; Expires="+a.expires.toUTCString()}if(a.httpOnly){p+="; HttpOnly"}if(a.secure){p+="; Secure"}if(a.sameSite){var f=typeof a.sameSite==="string"?a.sameSite.toLowerCase():a.sameSite;switch(f){case true:p+="; SameSite=Strict";break;case"lax":p+="; SameSite=Lax";break;case"strict":p+="; SameSite=Strict";break;case"none":p+="; SameSite=None";break;default:throw new TypeError("option sameSite is invalid")}}return p}function tryDecode(e,r){try{return r(e)}catch(r){return e}}}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "ScBA":
/***/ (function(module, exports, __webpack_require__) {

const { name: secp256k1 } = __webpack_require__("F/JS")

const oids = {
  '1 2 840 10045 3 1 7': 'P-256',
  '1 3 132 0 10': secp256k1,
  '1 3 132 0 34': 'P-384',
  '1 3 132 0 35': 'P-521',
  '1 2 840 10045 2 1': 'ecPublicKey',
  '1 2 840 113549 1 1 1': 'rsaEncryption',
  '1 3 101 110': 'X25519',
  '1 3 101 111': 'X448',
  '1 3 101 112': 'Ed25519',
  '1 3 101 113': 'Ed448'
}

module.exports = oids


/***/ }),

/***/ "Skye":
/***/ (function(module) {

module.exports = JSON.parse("{\"version\":3,\"pages404\":true,\"basePath\":\"\",\"redirects\":[{\"source\":\"/:path+/\",\"destination\":\"/:path+\",\"statusCode\":308,\"regex\":\"^(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))/$\"}],\"rewrites\":[],\"headers\":[],\"dynamicRoutes\":[],\"dataRoutes\":[]}");

/***/ }),

/***/ "SwXk":
/***/ (function(module, exports, __webpack_require__) {

const isObject = __webpack_require__("kF1/")
let validateCrit = __webpack_require__("urXW")
const { JWSInvalid } = __webpack_require__("yt7c")

validateCrit = validateCrit.bind(undefined, JWSInvalid)

const compactSerializer = (payload, [recipient]) => {
  return `${recipient.protected}.${payload}.${recipient.signature}`
}
compactSerializer.validate = (jws, { 0: { unprotectedHeader, protectedHeader }, length }) => {
  if (length !== 1 || unprotectedHeader) {
    throw new JWSInvalid('JWS Compact Serialization doesn\'t support multiple recipients or JWS unprotected headers')
  }
  validateCrit(protectedHeader, unprotectedHeader, protectedHeader ? protectedHeader.crit : undefined)
}

const flattenedSerializer = (payload, [recipient]) => {
  const { header, signature, protected: prot } = recipient

  return {
    payload,
    ...prot ? { protected: prot } : undefined,
    ...header ? { header } : undefined,
    signature
  }
}
flattenedSerializer.validate = (jws, { 0: { unprotectedHeader, protectedHeader }, length }) => {
  if (length !== 1) {
    throw new JWSInvalid('Flattened JWS JSON Serialization doesn\'t support multiple recipients')
  }
  validateCrit(protectedHeader, unprotectedHeader, protectedHeader ? protectedHeader.crit : undefined)
}

const generalSerializer = (payload, recipients) => {
  return {
    payload,
    signatures: recipients.map(({ header, signature, protected: prot }) => {
      return {
        ...prot ? { protected: prot } : undefined,
        ...header ? { header } : undefined,
        signature
      }
    })
  }
}
generalSerializer.validate = (jws, recipients) => {
  let validateB64 = false
  recipients.forEach(({ protectedHeader, unprotectedHeader }) => {
    if (protectedHeader && !validateB64 && 'b64' in protectedHeader) {
      validateB64 = true
    }
    validateCrit(protectedHeader, unprotectedHeader, protectedHeader ? protectedHeader.crit : undefined)
  })

  if (validateB64) {
    const values = recipients.map(({ protectedHeader }) => protectedHeader && protectedHeader.b64)
    if (!values.every((actual, i, [expected]) => actual === expected)) {
      throw new JWSInvalid('the "b64" Header Parameter value MUST be the same for all recipients')
    }
  }
}

const isJSON = (input) => {
  return isObject(input) && (typeof input.payload === 'string' || Buffer.isBuffer(input.payload))
}

const isValidRecipient = (recipient) => {
  return isObject(recipient) && typeof recipient.signature === 'string' &&
    (recipient.header === undefined || isObject(recipient.header)) &&
    (recipient.protected === undefined || typeof recipient.protected === 'string')
}

const isMultiRecipient = (input) => {
  if (Array.isArray(input.signatures) && input.signatures.every(isValidRecipient)) {
    return true
  }

  return false
}

const detect = (input) => {
  if (typeof input === 'string' && input.split('.').length === 3) {
    return 'compact'
  }

  if (isJSON(input)) {
    if (isMultiRecipient(input)) {
      return 'general'
    }

    if (isValidRecipient(input)) {
      return 'flattened'
    }
  }

  throw new JWSInvalid('JWS malformed or invalid serialization')
}

module.exports = {
  compact: compactSerializer,
  flattened: flattenedSerializer,
  general: generalSerializer,
  detect
}


/***/ }),

/***/ "TJm8":
/***/ (function(module, exports) {

const OIDC_DISCOVERY = '/.well-known/openid-configuration';
const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';
const WEBFINGER = '/.well-known/webfinger';
const REL = 'http://openid.net/specs/connect/1.0/issuer';
const AAD_MULTITENANT_DISCOVERY = [
  `https://login.microsoftonline.com/common${OIDC_DISCOVERY}`,
  `https://login.microsoftonline.com/common/v2.0${OIDC_DISCOVERY}`,
  `https://login.microsoftonline.com/organizations/v2.0${OIDC_DISCOVERY}`,
  `https://login.microsoftonline.com/consumers/v2.0${OIDC_DISCOVERY}`,
];

const CLIENT_DEFAULTS = {
  grant_types: ['authorization_code'],
  id_token_signed_response_alg: 'RS256',
  authorization_signed_response_alg: 'RS256',
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
};

const ISSUER_DEFAULTS = {
  claim_types_supported: ['normal'],
  claims_parameter_supported: false,
  grant_types_supported: ['authorization_code', 'implicit'],
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
  response_modes_supported: ['query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
};

const CALLBACK_PROPERTIES = [
  'access_token', // 6749
  'code', // 6749
  'error', // 6749
  'error_description', // 6749
  'error_uri', // 6749
  'expires_in', // 6749
  'id_token', // Core 1.0
  'state', // 6749
  'token_type', // 6749
  'session_state', // Session Management
  'response', // JARM
];

const JWT_CONTENT = /^application\/jwt/;

const HTTP_OPTIONS = Symbol('openid-client.custom.http-options');
const CLOCK_TOLERANCE = Symbol('openid-client.custom.clock-tolerance');

module.exports = {
  AAD_MULTITENANT_DISCOVERY,
  CALLBACK_PROPERTIES,
  CLIENT_DEFAULTS,
  CLOCK_TOLERANCE,
  HTTP_OPTIONS,
  ISSUER_DEFAULTS,
  JWT_CONTENT,
  OAUTH2_DISCOVERY,
  OIDC_DISCOVERY,
  REL,
  WEBFINGER,
};


/***/ }),

/***/ "U064":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var stream = __webpack_require__("msIP");

function DuplexWrapper(options, writable, readable) {
  if (typeof readable === "undefined") {
    readable = writable;
    writable = options;
    options = null;
  }

  stream.Duplex.call(this, options);

  if (typeof readable.read !== "function") {
    readable = (new stream.Readable(options)).wrap(readable);
  }

  this._writable = writable;
  this._readable = readable;
  this._waiting = false;

  var self = this;

  writable.once("finish", function() {
    self.end();
  });

  this.once("finish", function() {
    writable.end();
  });

  readable.on("readable", function() {
    if (self._waiting) {
      self._waiting = false;
      self._read();
    }
  });

  readable.once("end", function() {
    self.push(null);
  });

  if (!options || typeof options.bubbleErrors === "undefined" || options.bubbleErrors) {
    writable.on("error", function(err) {
      self.emit("error", err);
    });

    readable.on("error", function(err) {
      self.emit("error", err);
    });
  }
}

DuplexWrapper.prototype = Object.create(stream.Duplex.prototype, {constructor: {value: DuplexWrapper}});

DuplexWrapper.prototype._write = function _write(input, encoding, done) {
  this._writable.write(input, encoding, done);
};

DuplexWrapper.prototype._read = function _read() {
  var buf;
  var reads = 0;
  while ((buf = this._readable.read()) !== null) {
    this.push(buf);
    reads++;
  }
  if (reads === 0) {
    this._waiting = true;
  }
};

module.exports = function duplex2(options, writable, readable) {
  return new DuplexWrapper(options, writable, readable);
};

module.exports.DuplexWrapper = DuplexWrapper;


/***/ }),

/***/ "Ug5E":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (string) {

    // Escape ^$.*+-?=!:|\/()[]{},

    return string.replace(/[\^\$\.\*\+\-\?\=\!\:\|\\\/\(\)\[\]\{\}\,]/g, '\\$&');
};


/***/ }),

/***/ "UwMm":
/***/ (function(module, exports, __webpack_require__) {

const Got = __webpack_require__("AfMj");

const pkg = __webpack_require__("nK8a");

const { deep: defaultsDeep } = __webpack_require__("M0E0");
const isAbsoluteUrl = __webpack_require__("Ndh8");
const { HTTP_OPTIONS } = __webpack_require__("TJm8");

let DEFAULT_HTTP_OPTIONS;
let got;

const setDefaults = (options) => {
  DEFAULT_HTTP_OPTIONS = defaultsDeep({}, options, DEFAULT_HTTP_OPTIONS);
  got = Got.extend(DEFAULT_HTTP_OPTIONS);
};

setDefaults({
  followRedirect: false,
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  retry: 0,
  timeout: 2500,
  throwHttpErrors: false,
});

module.exports = function request(options, { mTLS = false } = {}) {
  const { url } = options;
  isAbsoluteUrl(url);
  const optsFn = this[HTTP_OPTIONS];
  let opts;
  if (optsFn) {
    opts = optsFn.call(this, defaultsDeep({}, options, DEFAULT_HTTP_OPTIONS));
  } else {
    opts = options;
  }

  if (mTLS && (!opts.key || !opts.cert)) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }
  return got(opts);
};

module.exports.setDefaults = setDefaults;


/***/ }),

/***/ "VHkT":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (...args) {

    try {
        return JSON.stringify.apply(null, args);
    }
    catch (err) {
        return '[Cannot display object: ' + err.message + ']';
    }
};


/***/ }),

/***/ "VZIC":
/***/ (function(module, exports, __webpack_require__) {

const { Reporter } = __webpack_require__("1WHo")
const { DecoderBuffer, EncoderBuffer } = __webpack_require__("Z9M3")
const Node = __webpack_require__("k+0e")

module.exports = {
  DecoderBuffer,
  EncoderBuffer,
  Node,
  Reporter
}


/***/ }),

/***/ "VmuJ":
/***/ (function(module, exports, __webpack_require__) {

var wrappy = __webpack_require__("1jOq")
module.exports = wrappy(once)
module.exports.strict = wrappy(onceStrict)

once.proto = once(function () {
  Object.defineProperty(Function.prototype, 'once', {
    value: function () {
      return once(this)
    },
    configurable: true
  })

  Object.defineProperty(Function.prototype, 'onceStrict', {
    value: function () {
      return onceStrict(this)
    },
    configurable: true
  })
})

function once (fn) {
  var f = function () {
    if (f.called) return f.value
    f.called = true
    return f.value = fn.apply(this, arguments)
  }
  f.called = false
  return f
}

function onceStrict (fn) {
  var f = function () {
    if (f.called)
      throw new Error(f.onceError)
    f.called = true
    return f.value = fn.apply(this, arguments)
  }
  var name = fn.name || 'Function wrapped with `once`'
  f.onceError = name + " shouldn't be called more than once"
  f.called = false
  return f
}


/***/ }),

/***/ "VzzF":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// TODO: Use the `URL` global when targeting Node.js 10
const URLParser = typeof URL === 'undefined' ? __webpack_require__("bzos").URL : URL;

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
const DATA_URL_DEFAULT_MIME_TYPE = 'text/plain';
const DATA_URL_DEFAULT_CHARSET = 'us-ascii';

const testParameter = (name, filters) => {
	return filters.some(filter => filter instanceof RegExp ? filter.test(name) : filter === name);
};

const normalizeDataURL = (urlString, {stripHash}) => {
	const parts = urlString.match(/^data:(.*?),(.*?)(?:#(.*))?$/);

	if (!parts) {
		throw new Error(`Invalid URL: ${urlString}`);
	}

	const mediaType = parts[1].split(';');
	const body = parts[2];
	const hash = stripHash ? '' : parts[3];

	let base64 = false;

	if (mediaType[mediaType.length - 1] === 'base64') {
		mediaType.pop();
		base64 = true;
	}

	// Lowercase MIME type
	const mimeType = (mediaType.shift() || '').toLowerCase();
	const attributes = mediaType
		.map(attribute => {
			let [key, value = ''] = attribute.split('=').map(string => string.trim());

			// Lowercase `charset`
			if (key === 'charset') {
				value = value.toLowerCase();

				if (value === DATA_URL_DEFAULT_CHARSET) {
					return '';
				}
			}

			return `${key}${value ? `=${value}` : ''}`;
		})
		.filter(Boolean);

	const normalizedMediaType = [
		...attributes
	];

	if (base64) {
		normalizedMediaType.push('base64');
	}

	if (normalizedMediaType.length !== 0 || (mimeType && mimeType !== DATA_URL_DEFAULT_MIME_TYPE)) {
		normalizedMediaType.unshift(mimeType);
	}

	return `data:${normalizedMediaType.join(';')},${base64 ? body.trim() : body}${hash ? `#${hash}` : ''}`;
};

const normalizeUrl = (urlString, options) => {
	options = {
		defaultProtocol: 'http:',
		normalizeProtocol: true,
		forceHttp: false,
		forceHttps: false,
		stripAuthentication: true,
		stripHash: false,
		stripWWW: true,
		removeQueryParameters: [/^utm_\w+/i],
		removeTrailingSlash: true,
		removeDirectoryIndex: false,
		sortQueryParameters: true,
		...options
	};

	// TODO: Remove this at some point in the future
	if (Reflect.has(options, 'normalizeHttps')) {
		throw new Error('options.normalizeHttps is renamed to options.forceHttp');
	}

	if (Reflect.has(options, 'normalizeHttp')) {
		throw new Error('options.normalizeHttp is renamed to options.forceHttps');
	}

	if (Reflect.has(options, 'stripFragment')) {
		throw new Error('options.stripFragment is renamed to options.stripHash');
	}

	urlString = urlString.trim();

	// Data URL
	if (/^data:/i.test(urlString)) {
		return normalizeDataURL(urlString, options);
	}

	const hasRelativeProtocol = urlString.startsWith('//');
	const isRelativeUrl = !hasRelativeProtocol && /^\.*\//.test(urlString);

	// Prepend protocol
	if (!isRelativeUrl) {
		urlString = urlString.replace(/^(?!(?:\w+:)?\/\/)|^\/\//, options.defaultProtocol);
	}

	const urlObj = new URLParser(urlString);

	if (options.forceHttp && options.forceHttps) {
		throw new Error('The `forceHttp` and `forceHttps` options cannot be used together');
	}

	if (options.forceHttp && urlObj.protocol === 'https:') {
		urlObj.protocol = 'http:';
	}

	if (options.forceHttps && urlObj.protocol === 'http:') {
		urlObj.protocol = 'https:';
	}

	// Remove auth
	if (options.stripAuthentication) {
		urlObj.username = '';
		urlObj.password = '';
	}

	// Remove hash
	if (options.stripHash) {
		urlObj.hash = '';
	}

	// Remove duplicate slashes if not preceded by a protocol
	if (urlObj.pathname) {
		// TODO: Use the following instead when targeting Node.js 10
		// `urlObj.pathname = urlObj.pathname.replace(/(?<!https?:)\/{2,}/g, '/');`
		urlObj.pathname = urlObj.pathname.replace(/((?!:).|^)\/{2,}/g, (_, p1) => {
			if (/^(?!\/)/g.test(p1)) {
				return `${p1}/`;
			}

			return '/';
		});
	}

	// Decode URI octets
	if (urlObj.pathname) {
		urlObj.pathname = decodeURI(urlObj.pathname);
	}

	// Remove directory index
	if (options.removeDirectoryIndex === true) {
		options.removeDirectoryIndex = [/^index\.[a-z]+$/];
	}

	if (Array.isArray(options.removeDirectoryIndex) && options.removeDirectoryIndex.length > 0) {
		let pathComponents = urlObj.pathname.split('/');
		const lastComponent = pathComponents[pathComponents.length - 1];

		if (testParameter(lastComponent, options.removeDirectoryIndex)) {
			pathComponents = pathComponents.slice(0, pathComponents.length - 1);
			urlObj.pathname = pathComponents.slice(1).join('/') + '/';
		}
	}

	if (urlObj.hostname) {
		// Remove trailing dot
		urlObj.hostname = urlObj.hostname.replace(/\.$/, '');

		// Remove `www.`
		if (options.stripWWW && /^www\.([a-z\-\d]{2,63})\.([a-z.]{2,5})$/.test(urlObj.hostname)) {
			// Each label should be max 63 at length (min: 2).
			// The extension should be max 5 at length (min: 2).
			// Source: https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_host_names
			urlObj.hostname = urlObj.hostname.replace(/^www\./, '');
		}
	}

	// Remove query unwanted parameters
	if (Array.isArray(options.removeQueryParameters)) {
		for (const key of [...urlObj.searchParams.keys()]) {
			if (testParameter(key, options.removeQueryParameters)) {
				urlObj.searchParams.delete(key);
			}
		}
	}

	// Sort query parameters
	if (options.sortQueryParameters) {
		urlObj.searchParams.sort();
	}

	if (options.removeTrailingSlash) {
		urlObj.pathname = urlObj.pathname.replace(/\/$/, '');
	}

	// Take advantage of many of the Node `url` normalizations
	urlString = urlObj.toString();

	// Remove ending `/`
	if ((options.removeTrailingSlash || urlObj.pathname === '/') && urlObj.hash === '') {
		urlString = urlString.replace(/\/$/, '');
	}

	// Restore relative protocol, if applicable
	if (hasRelativeProtocol && !options.normalizeProtocol) {
		urlString = urlString.replace(/^http:\/\//, '//');
	}

	// Remove http/https
	if (options.stripProtocol) {
		urlString = urlString.replace(/^(?:https?:)?\/\//, '');
	}

	return urlString;
};

module.exports = normalizeUrl;
// TODO: Remove this for the next major release
module.exports.default = normalizeUrl;


/***/ }),

/***/ "W5Ll":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("vbc4");
const Utils = __webpack_require__("jvMF");


const internals = {
    needsProtoHack: new Set([Types.set, Types.map, Types.weakSet, Types.weakMap])
};


module.exports = internals.clone = function (obj, options = {}, _seen = null) {

    if (typeof obj !== 'object' ||
        obj === null) {

        return obj;
    }

    let clone = internals.clone;
    let seen = _seen;

    if (options.shallow) {
        if (options.shallow !== true) {
            return internals.cloneWithShallow(obj, options);
        }

        clone = (value) => value;
    }
    else {
        seen = seen || new Map();

        const lookup = seen.get(obj);
        if (lookup) {
            return lookup;
        }
    }

    // Built-in object types

    const baseProto = Types.getInternalProto(obj);
    if (baseProto === Types.buffer) {
        return Buffer && Buffer.from(obj);              // $lab:coverage:ignore$
    }

    if (baseProto === Types.date) {
        return new Date(obj.getTime());
    }

    if (baseProto === Types.regex) {
        return new RegExp(obj);
    }

    // Generic objects

    const newObj = internals.base(obj, baseProto, options);
    if (newObj === obj) {
        return obj;
    }

    if (seen) {
        seen.set(obj, newObj);                              // Set seen, since obj could recurse
    }

    if (baseProto === Types.set) {
        for (const value of obj) {
            newObj.add(clone(value, options, seen));
        }
    }
    else if (baseProto === Types.map) {
        for (const [key, value] of obj) {
            newObj.set(key, clone(value, options, seen));
        }
    }

    const keys = Utils.keys(obj, options);
    for (const key of keys) {
        if (key === '__proto__') {
            continue;
        }

        if (baseProto === Types.array &&
            key === 'length') {

            newObj.length = obj.length;
            continue;
        }

        const descriptor = Object.getOwnPropertyDescriptor(obj, key);
        if (descriptor) {
            if (descriptor.get ||
                descriptor.set) {

                Object.defineProperty(newObj, key, descriptor);
            }
            else if (descriptor.enumerable) {
                newObj[key] = clone(obj[key], options, seen);
            }
            else {
                Object.defineProperty(newObj, key, { enumerable: false, writable: true, configurable: true, value: clone(obj[key], options, seen) });
            }
        }
        else {
            Object.defineProperty(newObj, key, {
                enumerable: true,
                writable: true,
                configurable: true,
                value: clone(obj[key], options, seen)
            });
        }
    }

    return newObj;
};


internals.cloneWithShallow = function (source, options) {

    const keys = options.shallow;
    options = Object.assign({}, options);
    options.shallow = false;

    const storage = Utils.store(source, keys);    // Move shallow copy items to storage
    const copy = internals.clone(source, options);      // Deep copy the rest
    Utils.restore(copy, source, storage);         // Shallow copy the stored items and restore
    return copy;
};


internals.base = function (obj, baseProto, options) {

    if (baseProto === Types.array) {
        return [];
    }

    if (options.prototype === false) {                  // Defaults to true
        if (internals.needsProtoHack.has(baseProto)) {
            return new baseProto.constructor();
        }

        return {};
    }

    const proto = Object.getPrototypeOf(obj);
    if (proto &&
        proto.isImmutable) {

        return obj;
    }

    if (internals.needsProtoHack.has(baseProto)) {
        const newObj = new proto.constructor();
        if (proto !== baseProto) {
            Object.setPrototypeOf(newObj, proto);
        }

        return newObj;
    }

    return Object.create(proto);
};


/***/ }),

/***/ "WPgm":
/***/ (function(module, exports, __webpack_require__) {

const KeyStore = __webpack_require__("aIoy")

module.exports = KeyStore


/***/ }),

/***/ "WTaE":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Hoek = __webpack_require__("+6AY");


const internals = {
    codes: new Map([
        [100, 'Continue'],
        [101, 'Switching Protocols'],
        [102, 'Processing'],
        [200, 'OK'],
        [201, 'Created'],
        [202, 'Accepted'],
        [203, 'Non-Authoritative Information'],
        [204, 'No Content'],
        [205, 'Reset Content'],
        [206, 'Partial Content'],
        [207, 'Multi-Status'],
        [300, 'Multiple Choices'],
        [301, 'Moved Permanently'],
        [302, 'Moved Temporarily'],
        [303, 'See Other'],
        [304, 'Not Modified'],
        [305, 'Use Proxy'],
        [307, 'Temporary Redirect'],
        [400, 'Bad Request'],
        [401, 'Unauthorized'],
        [402, 'Payment Required'],
        [403, 'Forbidden'],
        [404, 'Not Found'],
        [405, 'Method Not Allowed'],
        [406, 'Not Acceptable'],
        [407, 'Proxy Authentication Required'],
        [408, 'Request Time-out'],
        [409, 'Conflict'],
        [410, 'Gone'],
        [411, 'Length Required'],
        [412, 'Precondition Failed'],
        [413, 'Request Entity Too Large'],
        [414, 'Request-URI Too Large'],
        [415, 'Unsupported Media Type'],
        [416, 'Requested Range Not Satisfiable'],
        [417, 'Expectation Failed'],
        [418, 'I\'m a teapot'],
        [422, 'Unprocessable Entity'],
        [423, 'Locked'],
        [424, 'Failed Dependency'],
        [425, 'Unordered Collection'],
        [426, 'Upgrade Required'],
        [428, 'Precondition Required'],
        [429, 'Too Many Requests'],
        [431, 'Request Header Fields Too Large'],
        [451, 'Unavailable For Legal Reasons'],
        [500, 'Internal Server Error'],
        [501, 'Not Implemented'],
        [502, 'Bad Gateway'],
        [503, 'Service Unavailable'],
        [504, 'Gateway Time-out'],
        [505, 'HTTP Version Not Supported'],
        [506, 'Variant Also Negotiates'],
        [507, 'Insufficient Storage'],
        [509, 'Bandwidth Limit Exceeded'],
        [510, 'Not Extended'],
        [511, 'Network Authentication Required']
    ])
};


module.exports = internals.Boom = class extends Error {

    constructor(message, options = {}) {

        if (message instanceof Error) {
            return internals.Boom.boomify(Hoek.clone(message), options);
        }

        const { statusCode = 500, data = null, ctor = internals.Boom } = options;
        const error = new Error(message ? message : undefined);         // Avoids settings null message
        Error.captureStackTrace(error, ctor);                           // Filter the stack to our external API
        error.data = data;
        const boom = internals.initialize(error, statusCode);

        Object.defineProperty(boom, 'typeof', { value: ctor });

        if (options.decorate) {
            Object.assign(boom, options.decorate);
        }

        return boom;
    }

    static [Symbol.hasInstance](instance) {

        return internals.Boom.isBoom(instance);
    }

    static isBoom(err) {

        return err instanceof Error && !!err.isBoom;
    }

    static boomify(err, options) {

        Hoek.assert(err instanceof Error, 'Cannot wrap non-Error object');

        options = options || {};

        if (options.data !== undefined) {
            err.data = options.data;
        }

        if (options.decorate) {
            Object.assign(err, options.decorate);
        }

        if (!err.isBoom) {
            return internals.initialize(err, options.statusCode || 500, options.message);
        }

        if (options.override === false ||                           // Defaults to true
            !options.statusCode && !options.message) {

            return err;
        }

        return internals.initialize(err, options.statusCode || err.output.statusCode, options.message);
    }

    // 4xx Client Errors

    static badRequest(message, data) {

        return new internals.Boom(message, { statusCode: 400, data, ctor: internals.Boom.badRequest });
    }

    static unauthorized(message, scheme, attributes) {          // Or (message, wwwAuthenticate[])

        const err = new internals.Boom(message, { statusCode: 401, ctor: internals.Boom.unauthorized });

        // function (message)

        if (!scheme) {
            return err;
        }

        // function (message, wwwAuthenticate[])

        if (typeof scheme !== 'string') {
            err.output.headers['WWW-Authenticate'] = scheme.join(', ');
            return err;
        }

        // function (message, scheme, attributes)

        let wwwAuthenticate = `${scheme} `;

        if (attributes ||
            message) {

            err.output.payload.attributes = {};
        }

        if (attributes) {
            if (typeof attributes === 'string') {
                wwwAuthenticate += Hoek.escapeHeaderAttribute(attributes);
                err.output.payload.attributes = attributes;
            }
            else {
                wwwAuthenticate += Object.keys(attributes).map((name) => {

                    let value = attributes[name];
                    if (value === null ||
                        value === undefined) {

                        value = '';
                    }

                    err.output.payload.attributes[name] = value;
                    return `${name}="${Hoek.escapeHeaderAttribute(value.toString())}"`;
                })
                    .join(', ');
            }
        }

        if (message) {
            if (attributes) {
                wwwAuthenticate += ', ';
            }

            wwwAuthenticate += `error="${Hoek.escapeHeaderAttribute(message)}"`;
            err.output.payload.attributes.error = message;
        }
        else {
            err.isMissing = true;
        }

        err.output.headers['WWW-Authenticate'] = wwwAuthenticate;
        return err;
    }

    static paymentRequired(message, data) {

        return new internals.Boom(message, { statusCode: 402, data, ctor: internals.Boom.paymentRequired });
    }

    static forbidden(message, data) {

        return new internals.Boom(message, { statusCode: 403, data, ctor: internals.Boom.forbidden });
    }

    static notFound(message, data) {

        return new internals.Boom(message, { statusCode: 404, data, ctor: internals.Boom.notFound });
    }

    static methodNotAllowed(message, data, allow) {

        const err = new internals.Boom(message, { statusCode: 405, data, ctor: internals.Boom.methodNotAllowed });

        if (typeof allow === 'string') {
            allow = [allow];
        }

        if (Array.isArray(allow)) {
            err.output.headers.Allow = allow.join(', ');
        }

        return err;
    }

    static notAcceptable(message, data) {

        return new internals.Boom(message, { statusCode: 406, data, ctor: internals.Boom.notAcceptable });
    }

    static proxyAuthRequired(message, data) {

        return new internals.Boom(message, { statusCode: 407, data, ctor: internals.Boom.proxyAuthRequired });
    }

    static clientTimeout(message, data) {

        return new internals.Boom(message, { statusCode: 408, data, ctor: internals.Boom.clientTimeout });
    }

    static conflict(message, data) {

        return new internals.Boom(message, { statusCode: 409, data, ctor: internals.Boom.conflict });
    }

    static resourceGone(message, data) {

        return new internals.Boom(message, { statusCode: 410, data, ctor: internals.Boom.resourceGone });
    }

    static lengthRequired(message, data) {

        return new internals.Boom(message, { statusCode: 411, data, ctor: internals.Boom.lengthRequired });
    }

    static preconditionFailed(message, data) {

        return new internals.Boom(message, { statusCode: 412, data, ctor: internals.Boom.preconditionFailed });
    }

    static entityTooLarge(message, data) {

        return new internals.Boom(message, { statusCode: 413, data, ctor: internals.Boom.entityTooLarge });
    }

    static uriTooLong(message, data) {

        return new internals.Boom(message, { statusCode: 414, data, ctor: internals.Boom.uriTooLong });
    }

    static unsupportedMediaType(message, data) {

        return new internals.Boom(message, { statusCode: 415, data, ctor: internals.Boom.unsupportedMediaType });
    }

    static rangeNotSatisfiable(message, data) {

        return new internals.Boom(message, { statusCode: 416, data, ctor: internals.Boom.rangeNotSatisfiable });
    }

    static expectationFailed(message, data) {

        return new internals.Boom(message, { statusCode: 417, data, ctor: internals.Boom.expectationFailed });
    }

    static teapot(message, data) {

        return new internals.Boom(message, { statusCode: 418, data, ctor: internals.Boom.teapot });
    }

    static badData(message, data) {

        return new internals.Boom(message, { statusCode: 422, data, ctor: internals.Boom.badData });
    }

    static locked(message, data) {

        return new internals.Boom(message, { statusCode: 423, data, ctor: internals.Boom.locked });
    }

    static failedDependency(message, data) {

        return new internals.Boom(message, { statusCode: 424, data, ctor: internals.Boom.failedDependency });
    }

    static preconditionRequired(message, data) {

        return new internals.Boom(message, { statusCode: 428, data, ctor: internals.Boom.preconditionRequired });
    }

    static tooManyRequests(message, data) {

        return new internals.Boom(message, { statusCode: 429, data, ctor: internals.Boom.tooManyRequests });
    }

    static illegal(message, data) {

        return new internals.Boom(message, { statusCode: 451, data, ctor: internals.Boom.illegal });
    }

    // 5xx Server Errors

    static internal(message, data, statusCode = 500) {

        return internals.serverError(message, data, statusCode, internals.Boom.internal);
    }

    static notImplemented(message, data) {

        return internals.serverError(message, data, 501, internals.Boom.notImplemented);
    }

    static badGateway(message, data) {

        return internals.serverError(message, data, 502, internals.Boom.badGateway);
    }

    static serverUnavailable(message, data) {

        return internals.serverError(message, data, 503, internals.Boom.serverUnavailable);
    }

    static gatewayTimeout(message, data) {

        return internals.serverError(message, data, 504, internals.Boom.gatewayTimeout);
    }

    static badImplementation(message, data) {

        const err = internals.serverError(message, data, 500, internals.Boom.badImplementation);
        err.isDeveloperError = true;
        return err;
    }
};


internals.Boom.default = internals.Boom;        // Support ES6 module import


internals.initialize = function (err, statusCode, message) {

    const numberCode = parseInt(statusCode, 10);
    Hoek.assert(!isNaN(numberCode) && numberCode >= 400, 'First argument must be a number (400+):', statusCode);

    err.isBoom = true;
    err.isServer = numberCode >= 500;

    if (!err.hasOwnProperty('data')) {
        err.data = null;
    }

    err.output = {
        statusCode: numberCode,
        payload: {},
        headers: {}
    };

    Object.defineProperty(err, 'reformat', { value: internals.reformat });

    if (!message &&
        !err.message) {

        err.reformat();
        message = err.output.payload.error;
    }

    if (message) {
        const props = Object.getOwnPropertyDescriptor(err, 'message') || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(err), 'message');
        Hoek.assert(props.configurable && !props.get, 'The error is not compatible with boom');

        err.message = message + (err.message ? ': ' + err.message : '');
        err.output.payload.message = err.message;
    }

    err.reformat();
    return err;
};


internals.reformat = function (debug = false) {

    this.output.payload.statusCode = this.output.statusCode;
    this.output.payload.error = internals.codes.get(this.output.statusCode) || 'Unknown';

    if (this.output.statusCode === 500 && debug !== true) {
        this.output.payload.message = 'An internal server error occurred';              // Hide actual error from user
    }
    else if (this.message) {
        this.output.payload.message = this.message;
    }
};


internals.serverError = function (message, data, statusCode, ctor) {

    if (data instanceof Error &&
        !data.isBoom) {

        return internals.Boom.boomify(data, { statusCode, message });
    }

    return new internals.Boom(message, { statusCode, data, ctor });
};


/***/ }),

/***/ "WeJA":
/***/ (function(module, exports, __webpack_require__) {

const { STATUS_CODES } = __webpack_require__("KEll");
const { format } = __webpack_require__("jK02");

const { OPError } = __webpack_require__("L71r");

const REGEXP = /(\w+)=("[^"]*")/g;
const throwAuthenticateErrors = (response) => {
  const params = {};
  try {
    while ((REGEXP.exec(response.headers['www-authenticate'])) !== null) {
      if (RegExp.$1 && RegExp.$2) {
        params[RegExp.$1] = RegExp.$2.slice(1, -1);
      }
    }
  } catch (err) {}

  if (params.error) {
    throw new OPError(params, response);
  }
};

const isStandardBodyError = (response) => {
  let result = false;
  try {
    let jsonbody;
    if (typeof response.body !== 'object' || Buffer.isBuffer(response.body)) {
      jsonbody = JSON.parse(response.body);
    } else {
      jsonbody = response.body;
    }
    result = typeof jsonbody.error === 'string' && jsonbody.error.length;
    if (result) response.body = jsonbody;
  } catch (err) {}

  return result;
};

function processResponse(response, { statusCode = 200, body = true, bearer = false } = {}) {
  if (response.statusCode !== statusCode) {
    if (bearer) {
      throwAuthenticateErrors(response);
    }

    if (isStandardBodyError(response)) {
      throw new OPError(response.body, response);
    }

    throw new OPError({
      error: format('expected %i %s, got: %i %s', statusCode, STATUS_CODES[statusCode], response.statusCode, STATUS_CODES[response.statusCode]),
    }, response);
  }

  if (body && !response.body) {
    throw new OPError({
      error: format('expected %i %s with body but no body was returned', statusCode, STATUS_CODES[statusCode]),
    }, response);
  }

  return response.body;
}

module.exports = processResponse;


/***/ }),

/***/ "X3uD":
/***/ (function(module, exports, __webpack_require__) {

const { randomBytes } = __webpack_require__("PJMN")

const { IVLENGTHS } = __webpack_require__("N+nT")

module.exports = alg => randomBytes(IVLENGTHS.get(alg) / 8)


/***/ }),

/***/ "XPeR":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

module.exports = Yallist

Yallist.Node = Node
Yallist.create = Yallist

function Yallist (list) {
  var self = this
  if (!(self instanceof Yallist)) {
    self = new Yallist()
  }

  self.tail = null
  self.head = null
  self.length = 0

  if (list && typeof list.forEach === 'function') {
    list.forEach(function (item) {
      self.push(item)
    })
  } else if (arguments.length > 0) {
    for (var i = 0, l = arguments.length; i < l; i++) {
      self.push(arguments[i])
    }
  }

  return self
}

Yallist.prototype.removeNode = function (node) {
  if (node.list !== this) {
    throw new Error('removing node which does not belong to this list')
  }

  var next = node.next
  var prev = node.prev

  if (next) {
    next.prev = prev
  }

  if (prev) {
    prev.next = next
  }

  if (node === this.head) {
    this.head = next
  }
  if (node === this.tail) {
    this.tail = prev
  }

  node.list.length--
  node.next = null
  node.prev = null
  node.list = null

  return next
}

Yallist.prototype.unshiftNode = function (node) {
  if (node === this.head) {
    return
  }

  if (node.list) {
    node.list.removeNode(node)
  }

  var head = this.head
  node.list = this
  node.next = head
  if (head) {
    head.prev = node
  }

  this.head = node
  if (!this.tail) {
    this.tail = node
  }
  this.length++
}

Yallist.prototype.pushNode = function (node) {
  if (node === this.tail) {
    return
  }

  if (node.list) {
    node.list.removeNode(node)
  }

  var tail = this.tail
  node.list = this
  node.prev = tail
  if (tail) {
    tail.next = node
  }

  this.tail = node
  if (!this.head) {
    this.head = node
  }
  this.length++
}

Yallist.prototype.push = function () {
  for (var i = 0, l = arguments.length; i < l; i++) {
    push(this, arguments[i])
  }
  return this.length
}

Yallist.prototype.unshift = function () {
  for (var i = 0, l = arguments.length; i < l; i++) {
    unshift(this, arguments[i])
  }
  return this.length
}

Yallist.prototype.pop = function () {
  if (!this.tail) {
    return undefined
  }

  var res = this.tail.value
  this.tail = this.tail.prev
  if (this.tail) {
    this.tail.next = null
  } else {
    this.head = null
  }
  this.length--
  return res
}

Yallist.prototype.shift = function () {
  if (!this.head) {
    return undefined
  }

  var res = this.head.value
  this.head = this.head.next
  if (this.head) {
    this.head.prev = null
  } else {
    this.tail = null
  }
  this.length--
  return res
}

Yallist.prototype.forEach = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this.head, i = 0; walker !== null; i++) {
    fn.call(thisp, walker.value, i, this)
    walker = walker.next
  }
}

Yallist.prototype.forEachReverse = function (fn, thisp) {
  thisp = thisp || this
  for (var walker = this.tail, i = this.length - 1; walker !== null; i--) {
    fn.call(thisp, walker.value, i, this)
    walker = walker.prev
  }
}

Yallist.prototype.get = function (n) {
  for (var i = 0, walker = this.head; walker !== null && i < n; i++) {
    // abort out of the list early if we hit a cycle
    walker = walker.next
  }
  if (i === n && walker !== null) {
    return walker.value
  }
}

Yallist.prototype.getReverse = function (n) {
  for (var i = 0, walker = this.tail; walker !== null && i < n; i++) {
    // abort out of the list early if we hit a cycle
    walker = walker.prev
  }
  if (i === n && walker !== null) {
    return walker.value
  }
}

Yallist.prototype.map = function (fn, thisp) {
  thisp = thisp || this
  var res = new Yallist()
  for (var walker = this.head; walker !== null;) {
    res.push(fn.call(thisp, walker.value, this))
    walker = walker.next
  }
  return res
}

Yallist.prototype.mapReverse = function (fn, thisp) {
  thisp = thisp || this
  var res = new Yallist()
  for (var walker = this.tail; walker !== null;) {
    res.push(fn.call(thisp, walker.value, this))
    walker = walker.prev
  }
  return res
}

Yallist.prototype.reduce = function (fn, initial) {
  var acc
  var walker = this.head
  if (arguments.length > 1) {
    acc = initial
  } else if (this.head) {
    walker = this.head.next
    acc = this.head.value
  } else {
    throw new TypeError('Reduce of empty list with no initial value')
  }

  for (var i = 0; walker !== null; i++) {
    acc = fn(acc, walker.value, i)
    walker = walker.next
  }

  return acc
}

Yallist.prototype.reduceReverse = function (fn, initial) {
  var acc
  var walker = this.tail
  if (arguments.length > 1) {
    acc = initial
  } else if (this.tail) {
    walker = this.tail.prev
    acc = this.tail.value
  } else {
    throw new TypeError('Reduce of empty list with no initial value')
  }

  for (var i = this.length - 1; walker !== null; i--) {
    acc = fn(acc, walker.value, i)
    walker = walker.prev
  }

  return acc
}

Yallist.prototype.toArray = function () {
  var arr = new Array(this.length)
  for (var i = 0, walker = this.head; walker !== null; i++) {
    arr[i] = walker.value
    walker = walker.next
  }
  return arr
}

Yallist.prototype.toArrayReverse = function () {
  var arr = new Array(this.length)
  for (var i = 0, walker = this.tail; walker !== null; i++) {
    arr[i] = walker.value
    walker = walker.prev
  }
  return arr
}

Yallist.prototype.slice = function (from, to) {
  to = to || this.length
  if (to < 0) {
    to += this.length
  }
  from = from || 0
  if (from < 0) {
    from += this.length
  }
  var ret = new Yallist()
  if (to < from || to < 0) {
    return ret
  }
  if (from < 0) {
    from = 0
  }
  if (to > this.length) {
    to = this.length
  }
  for (var i = 0, walker = this.head; walker !== null && i < from; i++) {
    walker = walker.next
  }
  for (; walker !== null && i < to; i++, walker = walker.next) {
    ret.push(walker.value)
  }
  return ret
}

Yallist.prototype.sliceReverse = function (from, to) {
  to = to || this.length
  if (to < 0) {
    to += this.length
  }
  from = from || 0
  if (from < 0) {
    from += this.length
  }
  var ret = new Yallist()
  if (to < from || to < 0) {
    return ret
  }
  if (from < 0) {
    from = 0
  }
  if (to > this.length) {
    to = this.length
  }
  for (var i = this.length, walker = this.tail; walker !== null && i > to; i--) {
    walker = walker.prev
  }
  for (; walker !== null && i > from; i--, walker = walker.prev) {
    ret.push(walker.value)
  }
  return ret
}

Yallist.prototype.splice = function (start, deleteCount, ...nodes) {
  if (start > this.length) {
    start = this.length - 1
  }
  if (start < 0) {
    start = this.length + start;
  }

  for (var i = 0, walker = this.head; walker !== null && i < start; i++) {
    walker = walker.next
  }

  var ret = []
  for (var i = 0; walker && i < deleteCount; i++) {
    ret.push(walker.value)
    walker = this.removeNode(walker)
  }
  if (walker === null) {
    walker = this.tail
  }

  if (walker !== this.head && walker !== this.tail) {
    walker = walker.prev
  }

  for (var i = 0; i < nodes.length; i++) {
    walker = insert(this, walker, nodes[i])
  }
  return ret;
}

Yallist.prototype.reverse = function () {
  var head = this.head
  var tail = this.tail
  for (var walker = head; walker !== null; walker = walker.prev) {
    var p = walker.prev
    walker.prev = walker.next
    walker.next = p
  }
  this.head = tail
  this.tail = head
  return this
}

function insert (self, node, value) {
  var inserted = node === self.head ?
    new Node(value, null, node, self) :
    new Node(value, node, node.next, self)

  if (inserted.next === null) {
    self.tail = inserted
  }
  if (inserted.prev === null) {
    self.head = inserted
  }

  self.length++

  return inserted
}

function push (self, item) {
  self.tail = new Node(item, self.tail, null, self)
  if (!self.head) {
    self.head = self.tail
  }
  self.length++
}

function unshift (self, item) {
  self.head = new Node(item, null, self.head, self)
  if (!self.tail) {
    self.tail = self.head
  }
  self.length++
}

function Node (value, prev, next, list) {
  if (!(this instanceof Node)) {
    return new Node(value, prev, next, list)
  }

  this.list = list
  this.value = value

  if (prev) {
    prev.next = this
    this.prev = prev
  } else {
    this.prev = null
  }

  if (next) {
    next.prev = this
    this.next = next
  } else {
    this.next = null
  }
}

try {
  // add if support for Symbol.iterator is present
  __webpack_require__("HwNo")(Yallist)
} catch (er) {}


/***/ }),

/***/ "XUic":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var _auth0_nextjs_auth0__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("qwdb");
/* harmony import */ var _auth0_nextjs_auth0__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_auth0_nextjs_auth0__WEBPACK_IMPORTED_MODULE_0__);

/* harmony default export */ __webpack_exports__["a"] = (Object(_auth0_nextjs_auth0__WEBPACK_IMPORTED_MODULE_0__["initAuth0"])({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  scope: "openid email profile",
  redirectUri: false ? undefined : "https://dashboard.aircards.co/api/callback",
  postLogoutRedirectUri: false ? undefined : "https://dashboard.aircards.co/",
  session: {
    // The secret used to encrypt the cookie.
    cookieSecret: process.env.COOKIE_SECRET,
    // The cookie lifetime (expiration) in seconds. Set to 8 hours by default.
    cookieLifetime: 60 * 60 * 8,
    // (Optional) SameSite configuration for the session cookie. Defaults to 'lax', but can be changed to 'strict' or 'none'. Set it to false if you want to disable the SameSite setting.
    cookieSameSite: "lax",
    // (Optional) Store the id_token in the session. Defaults to false.
    storeIdToken: false,
    // (Optional) Store the access_token in the session. Defaults to false.
    storeAccessToken: false,
    // (Optional) Store the refresh_token in the session. Defaults to false.
    storeRefreshToken: false
  },
  oidcClient: {
    // (Optional) Configure the timeout in milliseconds for HTTP requests to Auth0.
    httpTimeout: 2500,
    // (Optional) Configure the clock tolerance in milliseconds, if the time on your server is running behind.
    clockTolerance: 10000
  }
}));

/***/ }),

/***/ "XZo7":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = {
    applyToDefaults: __webpack_require__("JC5t"),
    assert: __webpack_require__("xG1e"),
    Bench: __webpack_require__("Cr4G"),
    block: __webpack_require__("qI4P"),
    clone: __webpack_require__("E9YA"),
    contain: __webpack_require__("NjLM"),
    deepEqual: __webpack_require__("MuTT"),
    Error: __webpack_require__("DWQ6"),
    escapeHeaderAttribute: __webpack_require__("ESNE"),
    escapeHtml: __webpack_require__("jVnL"),
    escapeJson: __webpack_require__("KQmy"),
    escapeRegex: __webpack_require__("Efly"),
    flatten: __webpack_require__("uJ/c"),
    ignore: __webpack_require__("gJmk"),
    intersect: __webpack_require__("K29m"),
    isPromise: __webpack_require__("8qAF"),
    merge: __webpack_require__("6HRL"),
    once: __webpack_require__("sesp"),
    reach: __webpack_require__("0LeV"),
    reachTemplate: __webpack_require__("j5q1"),
    stringify: __webpack_require__("Y7By"),
    wait: __webpack_require__("tIIU")
};


/***/ }),

/***/ "Xab3":
/***/ (function(module, exports) {

/* global BigInt */

const fromBase64 = (base64) => {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

const encode = (input, encoding = 'utf8') => {
  return fromBase64(Buffer.from(input, encoding).toString('base64'))
}

const encodeBuffer = (buf) => {
  return fromBase64(buf.toString('base64'))
}

const decodeToBuffer = (input) => {
  return Buffer.from(input, 'base64')
}

const decode = (input, encoding = 'utf8') => {
  return decodeToBuffer(input).toString(encoding)
}

const b64uJSON = {
  encode: (input) => {
    return encode(JSON.stringify(input))
  },
  decode: (input, encoding = 'utf8') => {
    return JSON.parse(decode(input, encoding))
  }
}

b64uJSON.decode.try = (input, encoding = 'utf8') => {
  try {
    return b64uJSON.decode(input, encoding)
  } catch (err) {
    return decode(input, encoding)
  }
}

const bnToBuf = (bn) => {
  let hex = BigInt(bn).toString(16)
  if (hex.length % 2) {
    hex = `0${hex}`
  }

  const len = hex.length / 2
  const u8 = new Uint8Array(len)

  let i = 0
  let j = 0
  while (i < len) {
    u8[i] = parseInt(hex.slice(j, j + 2), 16)
    i += 1
    j += 2
  }

  return u8
}

const encodeBigInt = (bn) => encodeBuffer(Buffer.from(bnToBuf(bn)))

module.exports.decode = decode
module.exports.decodeToBuffer = decodeToBuffer
module.exports.encode = encode
module.exports.encodeBuffer = encodeBuffer
module.exports.JSON = b64uJSON
module.exports.encodeBigInt = encodeBigInt


/***/ }),

/***/ "Y7By":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (...args) {

    try {
        return JSON.stringify.apply(null, args);
    }
    catch (err) {
        return '[Cannot display object: ' + err.message + ']';
    }
};


/***/ }),

/***/ "YFSu":
/***/ (function(module, exports) {

module.exports = function () {
  this.octstr().contains().obj(
    this.key('privateKey').octstr()
  )
}


/***/ }),

/***/ "YNnK":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const PassThrough = __webpack_require__("msIP").PassThrough;
const zlib = __webpack_require__("FMKJ");
const mimicResponse = __webpack_require__("qsvm");

module.exports = response => {
	// TODO: Use Array#includes when targeting Node.js 6
	if (['gzip', 'deflate'].indexOf(response.headers['content-encoding']) === -1) {
		return response;
	}

	const unzip = zlib.createUnzip();
	const stream = new PassThrough();

	mimicResponse(response, stream);

	unzip.on('error', err => {
		if (err.code === 'Z_BUF_ERROR') {
			stream.end();
			return;
		}

		stream.emit('error', err);
	});

	response.pipe(unzip).pipe(stream);

	return stream;
};


/***/ }),

/***/ "YTOW":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (method) {

    if (method._hoekOnce) {
        return method;
    }

    let once = false;
    const wrapped = function (...args) {

        if (!once) {
            once = true;
            method(...args);
        }
    };

    wrapped._hoekOnce = true;
    return wrapped;
};


/***/ }),

/***/ "YUvC":
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,t){"use strict";var n={};function __webpack_require__(t){if(n[t]){return n[t].exports}var i=n[t]={i:t,l:false,exports:{}};e[t].call(i.exports,i,i.exports,__webpack_require__);i.l=true;return i.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(170)}return startup()}({42:function(e){e.exports=[["0","\0",127],["8ea1","｡",62],["a1a1","　、。，．・：；？！゛゜´｀¨＾￣＿ヽヾゝゞ〃仝々〆〇ー―‐／＼～∥｜…‥‘’“”（）〔〕［］｛｝〈",9,"＋－±×÷＝≠＜＞≦≧∞∴♂♀°′″℃￥＄￠￡％＃＆＊＠§☆★○●◎◇"],["a2a1","◆□■△▲▽▼※〒→←↑↓〓"],["a2ba","∈∋⊆⊇⊂⊃∪∩"],["a2ca","∧∨￢⇒⇔∀∃"],["a2dc","∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬"],["a2f2","Å‰♯♭♪†‡¶"],["a2fe","◯"],["a3b0","０",9],["a3c1","Ａ",25],["a3e1","ａ",25],["a4a1","ぁ",82],["a5a1","ァ",85],["a6a1","Α",16,"Σ",6],["a6c1","α",16,"σ",6],["a7a1","А",5,"ЁЖ",25],["a7d1","а",5,"ёж",25],["a8a1","─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂"],["ada1","①",19,"Ⅰ",9],["adc0","㍉㌔㌢㍍㌘㌧㌃㌶㍑㍗㌍㌦㌣㌫㍊㌻㎜㎝㎞㎎㎏㏄㎡"],["addf","㍻〝〟№㏍℡㊤",4,"㈱㈲㈹㍾㍽㍼≒≡∫∮∑√⊥∠∟⊿∵∩∪"],["b0a1","亜唖娃阿哀愛挨姶逢葵茜穐悪握渥旭葦芦鯵梓圧斡扱宛姐虻飴絢綾鮎或粟袷安庵按暗案闇鞍杏以伊位依偉囲夷委威尉惟意慰易椅為畏異移維緯胃萎衣謂違遺医井亥域育郁磯一壱溢逸稲茨芋鰯允印咽員因姻引飲淫胤蔭"],["b1a1","院陰隠韻吋右宇烏羽迂雨卯鵜窺丑碓臼渦嘘唄欝蔚鰻姥厩浦瓜閏噂云運雲荏餌叡営嬰影映曳栄永泳洩瑛盈穎頴英衛詠鋭液疫益駅悦謁越閲榎厭円園堰奄宴延怨掩援沿演炎焔煙燕猿縁艶苑薗遠鉛鴛塩於汚甥凹央奥往応"],["b2a1","押旺横欧殴王翁襖鴬鴎黄岡沖荻億屋憶臆桶牡乙俺卸恩温穏音下化仮何伽価佳加可嘉夏嫁家寡科暇果架歌河火珂禍禾稼箇花苛茄荷華菓蝦課嘩貨迦過霞蚊俄峨我牙画臥芽蛾賀雅餓駕介会解回塊壊廻快怪悔恢懐戒拐改"],["b3a1","魁晦械海灰界皆絵芥蟹開階貝凱劾外咳害崖慨概涯碍蓋街該鎧骸浬馨蛙垣柿蛎鈎劃嚇各廓拡撹格核殻獲確穫覚角赫較郭閣隔革学岳楽額顎掛笠樫橿梶鰍潟割喝恰括活渇滑葛褐轄且鰹叶椛樺鞄株兜竃蒲釜鎌噛鴨栢茅萱"],["b4a1","粥刈苅瓦乾侃冠寒刊勘勧巻喚堪姦完官寛干幹患感慣憾換敢柑桓棺款歓汗漢澗潅環甘監看竿管簡緩缶翰肝艦莞観諌貫還鑑間閑関陥韓館舘丸含岸巌玩癌眼岩翫贋雁頑顔願企伎危喜器基奇嬉寄岐希幾忌揮机旗既期棋棄"],["b5a1","機帰毅気汽畿祈季稀紀徽規記貴起軌輝飢騎鬼亀偽儀妓宜戯技擬欺犠疑祇義蟻誼議掬菊鞠吉吃喫桔橘詰砧杵黍却客脚虐逆丘久仇休及吸宮弓急救朽求汲泣灸球究窮笈級糾給旧牛去居巨拒拠挙渠虚許距鋸漁禦魚亨享京"],["b6a1","供侠僑兇競共凶協匡卿叫喬境峡強彊怯恐恭挟教橋況狂狭矯胸脅興蕎郷鏡響饗驚仰凝尭暁業局曲極玉桐粁僅勤均巾錦斤欣欽琴禁禽筋緊芹菌衿襟謹近金吟銀九倶句区狗玖矩苦躯駆駈駒具愚虞喰空偶寓遇隅串櫛釧屑屈"],["b7a1","掘窟沓靴轡窪熊隈粂栗繰桑鍬勲君薫訓群軍郡卦袈祁係傾刑兄啓圭珪型契形径恵慶慧憩掲携敬景桂渓畦稽系経継繋罫茎荊蛍計詣警軽頚鶏芸迎鯨劇戟撃激隙桁傑欠決潔穴結血訣月件倹倦健兼券剣喧圏堅嫌建憲懸拳捲"],["b8a1","検権牽犬献研硯絹県肩見謙賢軒遣鍵険顕験鹸元原厳幻弦減源玄現絃舷言諺限乎個古呼固姑孤己庫弧戸故枯湖狐糊袴股胡菰虎誇跨鈷雇顧鼓五互伍午呉吾娯後御悟梧檎瑚碁語誤護醐乞鯉交佼侯候倖光公功効勾厚口向"],["b9a1","后喉坑垢好孔孝宏工巧巷幸広庚康弘恒慌抗拘控攻昂晃更杭校梗構江洪浩港溝甲皇硬稿糠紅紘絞綱耕考肯肱腔膏航荒行衡講貢購郊酵鉱砿鋼閤降項香高鴻剛劫号合壕拷濠豪轟麹克刻告国穀酷鵠黒獄漉腰甑忽惚骨狛込"],["baa1","此頃今困坤墾婚恨懇昏昆根梱混痕紺艮魂些佐叉唆嵯左差査沙瑳砂詐鎖裟坐座挫債催再最哉塞妻宰彩才採栽歳済災采犀砕砦祭斎細菜裁載際剤在材罪財冴坂阪堺榊肴咲崎埼碕鷺作削咋搾昨朔柵窄策索錯桜鮭笹匙冊刷"],["bba1","察拶撮擦札殺薩雑皐鯖捌錆鮫皿晒三傘参山惨撒散桟燦珊産算纂蚕讃賛酸餐斬暫残仕仔伺使刺司史嗣四士始姉姿子屍市師志思指支孜斯施旨枝止死氏獅祉私糸紙紫肢脂至視詞詩試誌諮資賜雌飼歯事似侍児字寺慈持時"],["bca1","次滋治爾璽痔磁示而耳自蒔辞汐鹿式識鴫竺軸宍雫七叱執失嫉室悉湿漆疾質実蔀篠偲柴芝屡蕊縞舎写射捨赦斜煮社紗者謝車遮蛇邪借勺尺杓灼爵酌釈錫若寂弱惹主取守手朱殊狩珠種腫趣酒首儒受呪寿授樹綬需囚収周"],["bda1","宗就州修愁拾洲秀秋終繍習臭舟蒐衆襲讐蹴輯週酋酬集醜什住充十従戎柔汁渋獣縦重銃叔夙宿淑祝縮粛塾熟出術述俊峻春瞬竣舜駿准循旬楯殉淳準潤盾純巡遵醇順処初所暑曙渚庶緒署書薯藷諸助叙女序徐恕鋤除傷償"],["bea1","勝匠升召哨商唱嘗奨妾娼宵将小少尚庄床廠彰承抄招掌捷昇昌昭晶松梢樟樵沼消渉湘焼焦照症省硝礁祥称章笑粧紹肖菖蒋蕉衝裳訟証詔詳象賞醤鉦鍾鐘障鞘上丈丞乗冗剰城場壌嬢常情擾条杖浄状畳穣蒸譲醸錠嘱埴飾"],["bfa1","拭植殖燭織職色触食蝕辱尻伸信侵唇娠寝審心慎振新晋森榛浸深申疹真神秦紳臣芯薪親診身辛進針震人仁刃塵壬尋甚尽腎訊迅陣靭笥諏須酢図厨逗吹垂帥推水炊睡粋翠衰遂酔錐錘随瑞髄崇嵩数枢趨雛据杉椙菅頗雀裾"],["c0a1","澄摺寸世瀬畝是凄制勢姓征性成政整星晴棲栖正清牲生盛精聖声製西誠誓請逝醒青静斉税脆隻席惜戚斥昔析石積籍績脊責赤跡蹟碩切拙接摂折設窃節説雪絶舌蝉仙先千占宣専尖川戦扇撰栓栴泉浅洗染潜煎煽旋穿箭線"],["c1a1","繊羨腺舛船薦詮賎践選遷銭銑閃鮮前善漸然全禅繕膳糎噌塑岨措曾曽楚狙疏疎礎祖租粗素組蘇訴阻遡鼠僧創双叢倉喪壮奏爽宋層匝惣想捜掃挿掻操早曹巣槍槽漕燥争痩相窓糟総綜聡草荘葬蒼藻装走送遭鎗霜騒像増憎"],["c2a1","臓蔵贈造促側則即息捉束測足速俗属賊族続卒袖其揃存孫尊損村遜他多太汰詑唾堕妥惰打柁舵楕陀駄騨体堆対耐岱帯待怠態戴替泰滞胎腿苔袋貸退逮隊黛鯛代台大第醍題鷹滝瀧卓啄宅托択拓沢濯琢託鐸濁諾茸凧蛸只"],["c3a1","叩但達辰奪脱巽竪辿棚谷狸鱈樽誰丹単嘆坦担探旦歎淡湛炭短端箪綻耽胆蛋誕鍛団壇弾断暖檀段男談値知地弛恥智池痴稚置致蜘遅馳築畜竹筑蓄逐秩窒茶嫡着中仲宙忠抽昼柱注虫衷註酎鋳駐樗瀦猪苧著貯丁兆凋喋寵"],["c4a1","帖帳庁弔張彫徴懲挑暢朝潮牒町眺聴脹腸蝶調諜超跳銚長頂鳥勅捗直朕沈珍賃鎮陳津墜椎槌追鎚痛通塚栂掴槻佃漬柘辻蔦綴鍔椿潰坪壷嬬紬爪吊釣鶴亭低停偵剃貞呈堤定帝底庭廷弟悌抵挺提梯汀碇禎程締艇訂諦蹄逓"],["c5a1","邸鄭釘鼎泥摘擢敵滴的笛適鏑溺哲徹撤轍迭鉄典填天展店添纏甜貼転顛点伝殿澱田電兎吐堵塗妬屠徒斗杜渡登菟賭途都鍍砥砺努度土奴怒倒党冬凍刀唐塔塘套宕島嶋悼投搭東桃梼棟盗淘湯涛灯燈当痘祷等答筒糖統到"],["c6a1","董蕩藤討謄豆踏逃透鐙陶頭騰闘働動同堂導憧撞洞瞳童胴萄道銅峠鴇匿得徳涜特督禿篤毒独読栃橡凸突椴届鳶苫寅酉瀞噸屯惇敦沌豚遁頓呑曇鈍奈那内乍凪薙謎灘捺鍋楢馴縄畷南楠軟難汝二尼弐迩匂賑肉虹廿日乳入"],["c7a1","如尿韮任妊忍認濡禰祢寧葱猫熱年念捻撚燃粘乃廼之埜嚢悩濃納能脳膿農覗蚤巴把播覇杷波派琶破婆罵芭馬俳廃拝排敗杯盃牌背肺輩配倍培媒梅楳煤狽買売賠陪這蝿秤矧萩伯剥博拍柏泊白箔粕舶薄迫曝漠爆縛莫駁麦"],["c8a1","函箱硲箸肇筈櫨幡肌畑畠八鉢溌発醗髪伐罰抜筏閥鳩噺塙蛤隼伴判半反叛帆搬斑板氾汎版犯班畔繁般藩販範釆煩頒飯挽晩番盤磐蕃蛮匪卑否妃庇彼悲扉批披斐比泌疲皮碑秘緋罷肥被誹費避非飛樋簸備尾微枇毘琵眉美"],["c9a1","鼻柊稗匹疋髭彦膝菱肘弼必畢筆逼桧姫媛紐百謬俵彪標氷漂瓢票表評豹廟描病秒苗錨鋲蒜蛭鰭品彬斌浜瀕貧賓頻敏瓶不付埠夫婦富冨布府怖扶敷斧普浮父符腐膚芙譜負賦赴阜附侮撫武舞葡蕪部封楓風葺蕗伏副復幅服"],["caa1","福腹複覆淵弗払沸仏物鮒分吻噴墳憤扮焚奮粉糞紛雰文聞丙併兵塀幣平弊柄並蔽閉陛米頁僻壁癖碧別瞥蔑箆偏変片篇編辺返遍便勉娩弁鞭保舗鋪圃捕歩甫補輔穂募墓慕戊暮母簿菩倣俸包呆報奉宝峰峯崩庖抱捧放方朋"],["cba1","法泡烹砲縫胞芳萌蓬蜂褒訪豊邦鋒飽鳳鵬乏亡傍剖坊妨帽忘忙房暴望某棒冒紡肪膨謀貌貿鉾防吠頬北僕卜墨撲朴牧睦穆釦勃没殆堀幌奔本翻凡盆摩磨魔麻埋妹昧枚毎哩槙幕膜枕鮪柾鱒桝亦俣又抹末沫迄侭繭麿万慢満"],["cca1","漫蔓味未魅巳箕岬密蜜湊蓑稔脈妙粍民眠務夢無牟矛霧鵡椋婿娘冥名命明盟迷銘鳴姪牝滅免棉綿緬面麺摸模茂妄孟毛猛盲網耗蒙儲木黙目杢勿餅尤戻籾貰問悶紋門匁也冶夜爺耶野弥矢厄役約薬訳躍靖柳薮鑓愉愈油癒"],["cda1","諭輸唯佑優勇友宥幽悠憂揖有柚湧涌猶猷由祐裕誘遊邑郵雄融夕予余与誉輿預傭幼妖容庸揚揺擁曜楊様洋溶熔用窯羊耀葉蓉要謡踊遥陽養慾抑欲沃浴翌翼淀羅螺裸来莱頼雷洛絡落酪乱卵嵐欄濫藍蘭覧利吏履李梨理璃"],["cea1","痢裏裡里離陸律率立葎掠略劉流溜琉留硫粒隆竜龍侶慮旅虜了亮僚両凌寮料梁涼猟療瞭稜糧良諒遼量陵領力緑倫厘林淋燐琳臨輪隣鱗麟瑠塁涙累類令伶例冷励嶺怜玲礼苓鈴隷零霊麗齢暦歴列劣烈裂廉恋憐漣煉簾練聯"],["cfa1","蓮連錬呂魯櫓炉賂路露労婁廊弄朗楼榔浪漏牢狼篭老聾蝋郎六麓禄肋録論倭和話歪賄脇惑枠鷲亙亘鰐詫藁蕨椀湾碗腕"],["d0a1","弌丐丕个丱丶丼丿乂乖乘亂亅豫亊舒弍于亞亟亠亢亰亳亶从仍仄仆仂仗仞仭仟价伉佚估佛佝佗佇佶侈侏侘佻佩佰侑佯來侖儘俔俟俎俘俛俑俚俐俤俥倚倨倔倪倥倅伜俶倡倩倬俾俯們倆偃假會偕偐偈做偖偬偸傀傚傅傴傲"],["d1a1","僉僊傳僂僖僞僥僭僣僮價僵儉儁儂儖儕儔儚儡儺儷儼儻儿兀兒兌兔兢竸兩兪兮冀冂囘册冉冏冑冓冕冖冤冦冢冩冪冫决冱冲冰况冽凅凉凛几處凩凭凰凵凾刄刋刔刎刧刪刮刳刹剏剄剋剌剞剔剪剴剩剳剿剽劍劔劒剱劈劑辨"],["d2a1","辧劬劭劼劵勁勍勗勞勣勦飭勠勳勵勸勹匆匈甸匍匐匏匕匚匣匯匱匳匸區卆卅丗卉卍凖卞卩卮夘卻卷厂厖厠厦厥厮厰厶參簒雙叟曼燮叮叨叭叺吁吽呀听吭吼吮吶吩吝呎咏呵咎呟呱呷呰咒呻咀呶咄咐咆哇咢咸咥咬哄哈咨"],["d3a1","咫哂咤咾咼哘哥哦唏唔哽哮哭哺哢唹啀啣啌售啜啅啖啗唸唳啝喙喀咯喊喟啻啾喘喞單啼喃喩喇喨嗚嗅嗟嗄嗜嗤嗔嘔嗷嘖嗾嗽嘛嗹噎噐營嘴嘶嘲嘸噫噤嘯噬噪嚆嚀嚊嚠嚔嚏嚥嚮嚶嚴囂嚼囁囃囀囈囎囑囓囗囮囹圀囿圄圉"],["d4a1","圈國圍圓團圖嗇圜圦圷圸坎圻址坏坩埀垈坡坿垉垓垠垳垤垪垰埃埆埔埒埓堊埖埣堋堙堝塲堡塢塋塰毀塒堽塹墅墹墟墫墺壞墻墸墮壅壓壑壗壙壘壥壜壤壟壯壺壹壻壼壽夂夊夐夛梦夥夬夭夲夸夾竒奕奐奎奚奘奢奠奧奬奩"],["d5a1","奸妁妝佞侫妣妲姆姨姜妍姙姚娥娟娑娜娉娚婀婬婉娵娶婢婪媚媼媾嫋嫂媽嫣嫗嫦嫩嫖嫺嫻嬌嬋嬖嬲嫐嬪嬶嬾孃孅孀孑孕孚孛孥孩孰孳孵學斈孺宀它宦宸寃寇寉寔寐寤實寢寞寥寫寰寶寳尅將專對尓尠尢尨尸尹屁屆屎屓"],["d6a1","屐屏孱屬屮乢屶屹岌岑岔妛岫岻岶岼岷峅岾峇峙峩峽峺峭嶌峪崋崕崗嵜崟崛崑崔崢崚崙崘嵌嵒嵎嵋嵬嵳嵶嶇嶄嶂嶢嶝嶬嶮嶽嶐嶷嶼巉巍巓巒巖巛巫已巵帋帚帙帑帛帶帷幄幃幀幎幗幔幟幢幤幇幵并幺麼广庠廁廂廈廐廏"],["d7a1","廖廣廝廚廛廢廡廨廩廬廱廳廰廴廸廾弃弉彝彜弋弑弖弩弭弸彁彈彌彎弯彑彖彗彙彡彭彳彷徃徂彿徊很徑徇從徙徘徠徨徭徼忖忻忤忸忱忝悳忿怡恠怙怐怩怎怱怛怕怫怦怏怺恚恁恪恷恟恊恆恍恣恃恤恂恬恫恙悁悍惧悃悚"],["d8a1","悄悛悖悗悒悧悋惡悸惠惓悴忰悽惆悵惘慍愕愆惶惷愀惴惺愃愡惻惱愍愎慇愾愨愧慊愿愼愬愴愽慂慄慳慷慘慙慚慫慴慯慥慱慟慝慓慵憙憖憇憬憔憚憊憑憫憮懌懊應懷懈懃懆憺懋罹懍懦懣懶懺懴懿懽懼懾戀戈戉戍戌戔戛"],["d9a1","戞戡截戮戰戲戳扁扎扞扣扛扠扨扼抂抉找抒抓抖拔抃抔拗拑抻拏拿拆擔拈拜拌拊拂拇抛拉挌拮拱挧挂挈拯拵捐挾捍搜捏掖掎掀掫捶掣掏掉掟掵捫捩掾揩揀揆揣揉插揶揄搖搴搆搓搦搶攝搗搨搏摧摯摶摎攪撕撓撥撩撈撼"],["daa1","據擒擅擇撻擘擂擱擧舉擠擡抬擣擯攬擶擴擲擺攀擽攘攜攅攤攣攫攴攵攷收攸畋效敖敕敍敘敞敝敲數斂斃變斛斟斫斷旃旆旁旄旌旒旛旙无旡旱杲昊昃旻杳昵昶昴昜晏晄晉晁晞晝晤晧晨晟晢晰暃暈暎暉暄暘暝曁暹曉暾暼"],["dba1","曄暸曖曚曠昿曦曩曰曵曷朏朖朞朦朧霸朮朿朶杁朸朷杆杞杠杙杣杤枉杰枩杼杪枌枋枦枡枅枷柯枴柬枳柩枸柤柞柝柢柮枹柎柆柧檜栞框栩桀桍栲桎梳栫桙档桷桿梟梏梭梔條梛梃檮梹桴梵梠梺椏梍桾椁棊椈棘椢椦棡椌棍"],["dca1","棔棧棕椶椒椄棗棣椥棹棠棯椨椪椚椣椡棆楹楷楜楸楫楔楾楮椹楴椽楙椰楡楞楝榁楪榲榮槐榿槁槓榾槎寨槊槝榻槃榧樮榑榠榜榕榴槞槨樂樛槿權槹槲槧樅榱樞槭樔槫樊樒櫁樣樓橄樌橲樶橸橇橢橙橦橈樸樢檐檍檠檄檢檣"],["dda1","檗蘗檻櫃櫂檸檳檬櫞櫑櫟檪櫚櫪櫻欅蘖櫺欒欖鬱欟欸欷盜欹飮歇歃歉歐歙歔歛歟歡歸歹歿殀殄殃殍殘殕殞殤殪殫殯殲殱殳殷殼毆毋毓毟毬毫毳毯麾氈氓气氛氤氣汞汕汢汪沂沍沚沁沛汾汨汳沒沐泄泱泓沽泗泅泝沮沱沾"],["dea1","沺泛泯泙泪洟衍洶洫洽洸洙洵洳洒洌浣涓浤浚浹浙涎涕濤涅淹渕渊涵淇淦涸淆淬淞淌淨淒淅淺淙淤淕淪淮渭湮渮渙湲湟渾渣湫渫湶湍渟湃渺湎渤滿渝游溂溪溘滉溷滓溽溯滄溲滔滕溏溥滂溟潁漑灌滬滸滾漿滲漱滯漲滌"],["dfa1","漾漓滷澆潺潸澁澀潯潛濳潭澂潼潘澎澑濂潦澳澣澡澤澹濆澪濟濕濬濔濘濱濮濛瀉瀋濺瀑瀁瀏濾瀛瀚潴瀝瀘瀟瀰瀾瀲灑灣炙炒炯烱炬炸炳炮烟烋烝烙焉烽焜焙煥煕熈煦煢煌煖煬熏燻熄熕熨熬燗熹熾燒燉燔燎燠燬燧燵燼"],["e0a1","燹燿爍爐爛爨爭爬爰爲爻爼爿牀牆牋牘牴牾犂犁犇犒犖犢犧犹犲狃狆狄狎狒狢狠狡狹狷倏猗猊猜猖猝猴猯猩猥猾獎獏默獗獪獨獰獸獵獻獺珈玳珎玻珀珥珮珞璢琅瑯琥珸琲琺瑕琿瑟瑙瑁瑜瑩瑰瑣瑪瑶瑾璋璞璧瓊瓏瓔珱"],["e1a1","瓠瓣瓧瓩瓮瓲瓰瓱瓸瓷甄甃甅甌甎甍甕甓甞甦甬甼畄畍畊畉畛畆畚畩畤畧畫畭畸當疆疇畴疊疉疂疔疚疝疥疣痂疳痃疵疽疸疼疱痍痊痒痙痣痞痾痿痼瘁痰痺痲痳瘋瘍瘉瘟瘧瘠瘡瘢瘤瘴瘰瘻癇癈癆癜癘癡癢癨癩癪癧癬癰"],["e2a1","癲癶癸發皀皃皈皋皎皖皓皙皚皰皴皸皹皺盂盍盖盒盞盡盥盧盪蘯盻眈眇眄眩眤眞眥眦眛眷眸睇睚睨睫睛睥睿睾睹瞎瞋瞑瞠瞞瞰瞶瞹瞿瞼瞽瞻矇矍矗矚矜矣矮矼砌砒礦砠礪硅碎硴碆硼碚碌碣碵碪碯磑磆磋磔碾碼磅磊磬"],["e3a1","磧磚磽磴礇礒礑礙礬礫祀祠祗祟祚祕祓祺祿禊禝禧齋禪禮禳禹禺秉秕秧秬秡秣稈稍稘稙稠稟禀稱稻稾稷穃穗穉穡穢穩龝穰穹穽窈窗窕窘窖窩竈窰窶竅竄窿邃竇竊竍竏竕竓站竚竝竡竢竦竭竰笂笏笊笆笳笘笙笞笵笨笶筐"],["e4a1","筺笄筍笋筌筅筵筥筴筧筰筱筬筮箝箘箟箍箜箚箋箒箏筝箙篋篁篌篏箴篆篝篩簑簔篦篥籠簀簇簓篳篷簗簍篶簣簧簪簟簷簫簽籌籃籔籏籀籐籘籟籤籖籥籬籵粃粐粤粭粢粫粡粨粳粲粱粮粹粽糀糅糂糘糒糜糢鬻糯糲糴糶糺紆"],["e5a1","紂紜紕紊絅絋紮紲紿紵絆絳絖絎絲絨絮絏絣經綉絛綏絽綛綺綮綣綵緇綽綫總綢綯緜綸綟綰緘緝緤緞緻緲緡縅縊縣縡縒縱縟縉縋縢繆繦縻縵縹繃縷縲縺繧繝繖繞繙繚繹繪繩繼繻纃緕繽辮繿纈纉續纒纐纓纔纖纎纛纜缸缺"],["e6a1","罅罌罍罎罐网罕罔罘罟罠罨罩罧罸羂羆羃羈羇羌羔羞羝羚羣羯羲羹羮羶羸譱翅翆翊翕翔翡翦翩翳翹飜耆耄耋耒耘耙耜耡耨耿耻聊聆聒聘聚聟聢聨聳聲聰聶聹聽聿肄肆肅肛肓肚肭冐肬胛胥胙胝胄胚胖脉胯胱脛脩脣脯腋"],["e7a1","隋腆脾腓腑胼腱腮腥腦腴膃膈膊膀膂膠膕膤膣腟膓膩膰膵膾膸膽臀臂膺臉臍臑臙臘臈臚臟臠臧臺臻臾舁舂舅與舊舍舐舖舩舫舸舳艀艙艘艝艚艟艤艢艨艪艫舮艱艷艸艾芍芒芫芟芻芬苡苣苟苒苴苳苺莓范苻苹苞茆苜茉苙"],["e8a1","茵茴茖茲茱荀茹荐荅茯茫茗茘莅莚莪莟莢莖茣莎莇莊荼莵荳荵莠莉莨菴萓菫菎菽萃菘萋菁菷萇菠菲萍萢萠莽萸蔆菻葭萪萼蕚蒄葷葫蒭葮蒂葩葆萬葯葹萵蓊葢蒹蒿蒟蓙蓍蒻蓚蓐蓁蓆蓖蒡蔡蓿蓴蔗蔘蔬蔟蔕蔔蓼蕀蕣蕘蕈"],["e9a1","蕁蘂蕋蕕薀薤薈薑薊薨蕭薔薛藪薇薜蕷蕾薐藉薺藏薹藐藕藝藥藜藹蘊蘓蘋藾藺蘆蘢蘚蘰蘿虍乕虔號虧虱蚓蚣蚩蚪蚋蚌蚶蚯蛄蛆蚰蛉蠣蚫蛔蛞蛩蛬蛟蛛蛯蜒蜆蜈蜀蜃蛻蜑蜉蜍蛹蜊蜴蜿蜷蜻蜥蜩蜚蝠蝟蝸蝌蝎蝴蝗蝨蝮蝙"],["eaa1","蝓蝣蝪蠅螢螟螂螯蟋螽蟀蟐雖螫蟄螳蟇蟆螻蟯蟲蟠蠏蠍蟾蟶蟷蠎蟒蠑蠖蠕蠢蠡蠱蠶蠹蠧蠻衄衂衒衙衞衢衫袁衾袞衵衽袵衲袂袗袒袮袙袢袍袤袰袿袱裃裄裔裘裙裝裹褂裼裴裨裲褄褌褊褓襃褞褥褪褫襁襄褻褶褸襌褝襠襞"],["eba1","襦襤襭襪襯襴襷襾覃覈覊覓覘覡覩覦覬覯覲覺覽覿觀觚觜觝觧觴觸訃訖訐訌訛訝訥訶詁詛詒詆詈詼詭詬詢誅誂誄誨誡誑誥誦誚誣諄諍諂諚諫諳諧諤諱謔諠諢諷諞諛謌謇謚諡謖謐謗謠謳鞫謦謫謾謨譁譌譏譎證譖譛譚譫"],["eca1","譟譬譯譴譽讀讌讎讒讓讖讙讚谺豁谿豈豌豎豐豕豢豬豸豺貂貉貅貊貍貎貔豼貘戝貭貪貽貲貳貮貶賈賁賤賣賚賽賺賻贄贅贊贇贏贍贐齎贓賍贔贖赧赭赱赳趁趙跂趾趺跏跚跖跌跛跋跪跫跟跣跼踈踉跿踝踞踐踟蹂踵踰踴蹊"],["eda1","蹇蹉蹌蹐蹈蹙蹤蹠踪蹣蹕蹶蹲蹼躁躇躅躄躋躊躓躑躔躙躪躡躬躰軆躱躾軅軈軋軛軣軼軻軫軾輊輅輕輒輙輓輜輟輛輌輦輳輻輹轅轂輾轌轉轆轎轗轜轢轣轤辜辟辣辭辯辷迚迥迢迪迯邇迴逅迹迺逑逕逡逍逞逖逋逧逶逵逹迸"],["eea1","遏遐遑遒逎遉逾遖遘遞遨遯遶隨遲邂遽邁邀邊邉邏邨邯邱邵郢郤扈郛鄂鄒鄙鄲鄰酊酖酘酣酥酩酳酲醋醉醂醢醫醯醪醵醴醺釀釁釉釋釐釖釟釡釛釼釵釶鈞釿鈔鈬鈕鈑鉞鉗鉅鉉鉤鉈銕鈿鉋鉐銜銖銓銛鉚鋏銹銷鋩錏鋺鍄錮"],["efa1","錙錢錚錣錺錵錻鍜鍠鍼鍮鍖鎰鎬鎭鎔鎹鏖鏗鏨鏥鏘鏃鏝鏐鏈鏤鐚鐔鐓鐃鐇鐐鐶鐫鐵鐡鐺鑁鑒鑄鑛鑠鑢鑞鑪鈩鑰鑵鑷鑽鑚鑼鑾钁鑿閂閇閊閔閖閘閙閠閨閧閭閼閻閹閾闊濶闃闍闌闕闔闖關闡闥闢阡阨阮阯陂陌陏陋陷陜陞"],["f0a1","陝陟陦陲陬隍隘隕隗險隧隱隲隰隴隶隸隹雎雋雉雍襍雜霍雕雹霄霆霈霓霎霑霏霖霙霤霪霰霹霽霾靄靆靈靂靉靜靠靤靦靨勒靫靱靹鞅靼鞁靺鞆鞋鞏鞐鞜鞨鞦鞣鞳鞴韃韆韈韋韜韭齏韲竟韶韵頏頌頸頤頡頷頽顆顏顋顫顯顰"],["f1a1","顱顴顳颪颯颱颶飄飃飆飩飫餃餉餒餔餘餡餝餞餤餠餬餮餽餾饂饉饅饐饋饑饒饌饕馗馘馥馭馮馼駟駛駝駘駑駭駮駱駲駻駸騁騏騅駢騙騫騷驅驂驀驃騾驕驍驛驗驟驢驥驤驩驫驪骭骰骼髀髏髑髓體髞髟髢髣髦髯髫髮髴髱髷"],["f2a1","髻鬆鬘鬚鬟鬢鬣鬥鬧鬨鬩鬪鬮鬯鬲魄魃魏魍魎魑魘魴鮓鮃鮑鮖鮗鮟鮠鮨鮴鯀鯊鮹鯆鯏鯑鯒鯣鯢鯤鯔鯡鰺鯲鯱鯰鰕鰔鰉鰓鰌鰆鰈鰒鰊鰄鰮鰛鰥鰤鰡鰰鱇鰲鱆鰾鱚鱠鱧鱶鱸鳧鳬鳰鴉鴈鳫鴃鴆鴪鴦鶯鴣鴟鵄鴕鴒鵁鴿鴾鵆鵈"],["f3a1","鵝鵞鵤鵑鵐鵙鵲鶉鶇鶫鵯鵺鶚鶤鶩鶲鷄鷁鶻鶸鶺鷆鷏鷂鷙鷓鷸鷦鷭鷯鷽鸚鸛鸞鹵鹹鹽麁麈麋麌麒麕麑麝麥麩麸麪麭靡黌黎黏黐黔黜點黝黠黥黨黯黴黶黷黹黻黼黽鼇鼈皷鼕鼡鼬鼾齊齒齔齣齟齠齡齦齧齬齪齷齲齶龕龜龠"],["f4a1","堯槇遙瑤凜熙"],["f9a1","纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德"],["faa1","忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱"],["fba1","犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚"],["fca1","釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"],["fcf1","ⅰ",9,"￢￤＇＂"],["8fa2af","˘ˇ¸˙˝¯˛˚～΄΅"],["8fa2c2","¡¦¿"],["8fa2eb","ºª©®™¤№"],["8fa6e1","ΆΈΉΊΪ"],["8fa6e7","Ό"],["8fa6e9","ΎΫ"],["8fa6ec","Ώ"],["8fa6f1","άέήίϊΐόςύϋΰώ"],["8fa7c2","Ђ",10,"ЎЏ"],["8fa7f2","ђ",10,"ўџ"],["8fa9a1","ÆĐ"],["8fa9a4","Ħ"],["8fa9a6","Ĳ"],["8fa9a8","ŁĿ"],["8fa9ab","ŊØŒ"],["8fa9af","ŦÞ"],["8fa9c1","æđðħıĳĸłŀŉŋøœßŧþ"],["8faaa1","ÁÀÄÂĂǍĀĄÅÃĆĈČÇĊĎÉÈËÊĚĖĒĘ"],["8faaba","ĜĞĢĠĤÍÌÏÎǏİĪĮĨĴĶĹĽĻŃŇŅÑÓÒÖÔǑŐŌÕŔŘŖŚŜŠŞŤŢÚÙÜÛŬǓŰŪŲŮŨǗǛǙǕŴÝŸŶŹŽŻ"],["8faba1","áàäâăǎāąåãćĉčçċďéèëêěėēęǵĝğ"],["8fabbd","ġĥíìïîǐ"],["8fabc5","īįĩĵķĺľļńňņñóòöôǒőōõŕřŗśŝšşťţúùüûŭǔűūųůũǘǜǚǖŵýÿŷźžż"],["8fb0a1","丂丄丅丌丒丟丣两丨丫丮丯丰丵乀乁乄乇乑乚乜乣乨乩乴乵乹乿亍亖亗亝亯亹仃仐仚仛仠仡仢仨仯仱仳仵份仾仿伀伂伃伈伋伌伒伕伖众伙伮伱你伳伵伷伹伻伾佀佂佈佉佋佌佒佔佖佘佟佣佪佬佮佱佷佸佹佺佽佾侁侂侄"],["8fb1a1","侅侉侊侌侎侐侒侓侔侗侙侚侞侟侲侷侹侻侼侽侾俀俁俅俆俈俉俋俌俍俏俒俜俠俢俰俲俼俽俿倀倁倄倇倊倌倎倐倓倗倘倛倜倝倞倢倧倮倰倲倳倵偀偁偂偅偆偊偌偎偑偒偓偗偙偟偠偢偣偦偧偪偭偰偱倻傁傃傄傆傊傎傏傐"],["8fb2a1","傒傓傔傖傛傜傞",4,"傪傯傰傹傺傽僀僃僄僇僌僎僐僓僔僘僜僝僟僢僤僦僨僩僯僱僶僺僾儃儆儇儈儋儌儍儎僲儐儗儙儛儜儝儞儣儧儨儬儭儯儱儳儴儵儸儹兂兊兏兓兕兗兘兟兤兦兾冃冄冋冎冘冝冡冣冭冸冺冼冾冿凂"],["8fb3a1","凈减凑凒凓凕凘凞凢凥凮凲凳凴凷刁刂刅划刓刕刖刘刢刨刱刲刵刼剅剉剕剗剘剚剜剟剠剡剦剮剷剸剹劀劂劅劊劌劓劕劖劗劘劚劜劤劥劦劧劯劰劶劷劸劺劻劽勀勄勆勈勌勏勑勔勖勛勜勡勥勨勩勪勬勰勱勴勶勷匀匃匊匋"],["8fb4a1","匌匑匓匘匛匜匞匟匥匧匨匩匫匬匭匰匲匵匼匽匾卂卌卋卙卛卡卣卥卬卭卲卹卾厃厇厈厎厓厔厙厝厡厤厪厫厯厲厴厵厷厸厺厽叀叅叏叒叓叕叚叝叞叠另叧叵吂吓吚吡吧吨吪启吱吴吵呃呄呇呍呏呞呢呤呦呧呩呫呭呮呴呿"],["8fb5a1","咁咃咅咈咉咍咑咕咖咜咟咡咦咧咩咪咭咮咱咷咹咺咻咿哆哊响哎哠哪哬哯哶哼哾哿唀唁唅唈唉唌唍唎唕唪唫唲唵唶唻唼唽啁啇啉啊啍啐啑啘啚啛啞啠啡啤啦啿喁喂喆喈喎喏喑喒喓喔喗喣喤喭喲喿嗁嗃嗆嗉嗋嗌嗎嗑嗒"],["8fb6a1","嗓嗗嗘嗛嗞嗢嗩嗶嗿嘅嘈嘊嘍",5,"嘙嘬嘰嘳嘵嘷嘹嘻嘼嘽嘿噀噁噃噄噆噉噋噍噏噔噞噠噡噢噣噦噩噭噯噱噲噵嚄嚅嚈嚋嚌嚕嚙嚚嚝嚞嚟嚦嚧嚨嚩嚫嚬嚭嚱嚳嚷嚾囅囉囊囋囏囐囌囍囙囜囝囟囡囤",4,"囱囫园"],["8fb7a1","囶囷圁圂圇圊圌圑圕圚圛圝圠圢圣圤圥圩圪圬圮圯圳圴圽圾圿坅坆坌坍坒坢坥坧坨坫坭",4,"坳坴坵坷坹坺坻坼坾垁垃垌垔垗垙垚垜垝垞垟垡垕垧垨垩垬垸垽埇埈埌埏埕埝埞埤埦埧埩埭埰埵埶埸埽埾埿堃堄堈堉埡"],["8fb8a1","堌堍堛堞堟堠堦堧堭堲堹堿塉塌塍塏塐塕塟塡塤塧塨塸塼塿墀墁墇墈墉墊墌墍墏墐墔墖墝墠墡墢墦墩墱墲壄墼壂壈壍壎壐壒壔壖壚壝壡壢壩壳夅夆夋夌夒夓夔虁夝夡夣夤夨夯夰夳夵夶夿奃奆奒奓奙奛奝奞奟奡奣奫奭"],["8fb9a1","奯奲奵奶她奻奼妋妌妎妒妕妗妟妤妧妭妮妯妰妳妷妺妼姁姃姄姈姊姍姒姝姞姟姣姤姧姮姯姱姲姴姷娀娄娌娍娎娒娓娞娣娤娧娨娪娭娰婄婅婇婈婌婐婕婞婣婥婧婭婷婺婻婾媋媐媓媖媙媜媞媟媠媢媧媬媱媲媳媵媸媺媻媿"],["8fbaa1","嫄嫆嫈嫏嫚嫜嫠嫥嫪嫮嫵嫶嫽嬀嬁嬈嬗嬴嬙嬛嬝嬡嬥嬭嬸孁孋孌孒孖孞孨孮孯孼孽孾孿宁宄宆宊宎宐宑宓宔宖宨宩宬宭宯宱宲宷宺宼寀寁寍寏寖",4,"寠寯寱寴寽尌尗尞尟尣尦尩尫尬尮尰尲尵尶屙屚屜屢屣屧屨屩"],["8fbba1","屭屰屴屵屺屻屼屽岇岈岊岏岒岝岟岠岢岣岦岪岲岴岵岺峉峋峒峝峗峮峱峲峴崁崆崍崒崫崣崤崦崧崱崴崹崽崿嵂嵃嵆嵈嵕嵑嵙嵊嵟嵠嵡嵢嵤嵪嵭嵰嵹嵺嵾嵿嶁嶃嶈嶊嶒嶓嶔嶕嶙嶛嶟嶠嶧嶫嶰嶴嶸嶹巃巇巋巐巎巘巙巠巤"],["8fbca1","巩巸巹帀帇帍帒帔帕帘帟帠帮帨帲帵帾幋幐幉幑幖幘幛幜幞幨幪",4,"幰庀庋庎庢庤庥庨庪庬庱庳庽庾庿廆廌廋廎廑廒廔廕廜廞廥廫异弆弇弈弎弙弜弝弡弢弣弤弨弫弬弮弰弴弶弻弽弿彀彄彅彇彍彐彔彘彛彠彣彤彧"],["8fbda1","彯彲彴彵彸彺彽彾徉徍徏徖徜徝徢徧徫徤徬徯徰徱徸忄忇忈忉忋忐",4,"忞忡忢忨忩忪忬忭忮忯忲忳忶忺忼怇怊怍怓怔怗怘怚怟怤怭怳怵恀恇恈恉恌恑恔恖恗恝恡恧恱恾恿悂悆悈悊悎悑悓悕悘悝悞悢悤悥您悰悱悷"],["8fbea1","悻悾惂惄惈惉惊惋惎惏惔惕惙惛惝惞惢惥惲惵惸惼惽愂愇愊愌愐",4,"愖愗愙愜愞愢愪愫愰愱愵愶愷愹慁慅慆慉慞慠慬慲慸慻慼慿憀憁憃憄憋憍憒憓憗憘憜憝憟憠憥憨憪憭憸憹憼懀懁懂懎懏懕懜懝懞懟懡懢懧懩懥"],["8fbfa1","懬懭懯戁戃戄戇戓戕戜戠戢戣戧戩戫戹戽扂扃扄扆扌扐扑扒扔扖扚扜扤扭扯扳扺扽抍抎抏抐抦抨抳抶抷抺抾抿拄拎拕拖拚拪拲拴拼拽挃挄挊挋挍挐挓挖挘挩挪挭挵挶挹挼捁捂捃捄捆捊捋捎捒捓捔捘捛捥捦捬捭捱捴捵"],["8fc0a1","捸捼捽捿掂掄掇掊掐掔掕掙掚掞掤掦掭掮掯掽揁揅揈揎揑揓揔揕揜揠揥揪揬揲揳揵揸揹搉搊搐搒搔搘搞搠搢搤搥搩搪搯搰搵搽搿摋摏摑摒摓摔摚摛摜摝摟摠摡摣摭摳摴摻摽撅撇撏撐撑撘撙撛撝撟撡撣撦撨撬撳撽撾撿"],["8fc1a1","擄擉擊擋擌擎擐擑擕擗擤擥擩擪擭擰擵擷擻擿攁攄攈攉攊攏攓攔攖攙攛攞攟攢攦攩攮攱攺攼攽敃敇敉敐敒敔敟敠敧敫敺敽斁斅斊斒斕斘斝斠斣斦斮斲斳斴斿旂旈旉旎旐旔旖旘旟旰旲旴旵旹旾旿昀昄昈昉昍昑昒昕昖昝"],["8fc2a1","昞昡昢昣昤昦昩昪昫昬昮昰昱昳昹昷晀晅晆晊晌晑晎晗晘晙晛晜晠晡曻晪晫晬晾晳晵晿晷晸晹晻暀晼暋暌暍暐暒暙暚暛暜暟暠暤暭暱暲暵暻暿曀曂曃曈曌曎曏曔曛曟曨曫曬曮曺朅朇朎朓朙朜朠朢朳朾杅杇杈杌杔杕杝"],["8fc3a1","杦杬杮杴杶杻极构枎枏枑枓枖枘枙枛枰枱枲枵枻枼枽柹柀柂柃柅柈柉柒柗柙柜柡柦柰柲柶柷桒栔栙栝栟栨栧栬栭栯栰栱栳栻栿桄桅桊桌桕桗桘桛桫桮",4,"桵桹桺桻桼梂梄梆梈梖梘梚梜梡梣梥梩梪梮梲梻棅棈棌棏"],["8fc4a1","棐棑棓棖棙棜棝棥棨棪棫棬棭棰棱棵棶棻棼棽椆椉椊椐椑椓椖椗椱椳椵椸椻楂楅楉楎楗楛楣楤楥楦楨楩楬楰楱楲楺楻楿榀榍榒榖榘榡榥榦榨榫榭榯榷榸榺榼槅槈槑槖槗槢槥槮槯槱槳槵槾樀樁樃樏樑樕樚樝樠樤樨樰樲"],["8fc5a1","樴樷樻樾樿橅橆橉橊橎橐橑橒橕橖橛橤橧橪橱橳橾檁檃檆檇檉檋檑檛檝檞檟檥檫檯檰檱檴檽檾檿櫆櫉櫈櫌櫐櫔櫕櫖櫜櫝櫤櫧櫬櫰櫱櫲櫼櫽欂欃欆欇欉欏欐欑欗欛欞欤欨欫欬欯欵欶欻欿歆歊歍歒歖歘歝歠歧歫歮歰歵歽"],["8fc6a1","歾殂殅殗殛殟殠殢殣殨殩殬殭殮殰殸殹殽殾毃毄毉毌毖毚毡毣毦毧毮毱毷毹毿氂氄氅氉氍氎氐氒氙氟氦氧氨氬氮氳氵氶氺氻氿汊汋汍汏汒汔汙汛汜汫汭汯汴汶汸汹汻沅沆沇沉沔沕沗沘沜沟沰沲沴泂泆泍泏泐泑泒泔泖"],["8fc7a1","泚泜泠泧泩泫泬泮泲泴洄洇洊洎洏洑洓洚洦洧洨汧洮洯洱洹洼洿浗浞浟浡浥浧浯浰浼涂涇涑涒涔涖涗涘涪涬涴涷涹涽涿淄淈淊淎淏淖淛淝淟淠淢淥淩淯淰淴淶淼渀渄渞渢渧渲渶渹渻渼湄湅湈湉湋湏湑湒湓湔湗湜湝湞"],["8fc8a1","湢湣湨湳湻湽溍溓溙溠溧溭溮溱溳溻溿滀滁滃滇滈滊滍滎滏滫滭滮滹滻滽漄漈漊漌漍漖漘漚漛漦漩漪漯漰漳漶漻漼漭潏潑潒潓潗潙潚潝潞潡潢潨潬潽潾澃澇澈澋澌澍澐澒澓澔澖澚澟澠澥澦澧澨澮澯澰澵澶澼濅濇濈濊"],["8fc9a1","濚濞濨濩濰濵濹濼濽瀀瀅瀆瀇瀍瀗瀠瀣瀯瀴瀷瀹瀼灃灄灈灉灊灋灔灕灝灞灎灤灥灬灮灵灶灾炁炅炆炔",4,"炛炤炫炰炱炴炷烊烑烓烔烕烖烘烜烤烺焃",4,"焋焌焏焞焠焫焭焯焰焱焸煁煅煆煇煊煋煐煒煗煚煜煞煠"],["8fcaa1","煨煹熀熅熇熌熒熚熛熠熢熯熰熲熳熺熿燀燁燄燋燌燓燖燙燚燜燸燾爀爇爈爉爓爗爚爝爟爤爫爯爴爸爹牁牂牃牅牎牏牐牓牕牖牚牜牞牠牣牨牫牮牯牱牷牸牻牼牿犄犉犍犎犓犛犨犭犮犱犴犾狁狇狉狌狕狖狘狟狥狳狴狺狻"],["8fcba1","狾猂猄猅猇猋猍猒猓猘猙猞猢猤猧猨猬猱猲猵猺猻猽獃獍獐獒獖獘獝獞獟獠獦獧獩獫獬獮獯獱獷獹獼玀玁玃玅玆玎玐玓玕玗玘玜玞玟玠玢玥玦玪玫玭玵玷玹玼玽玿珅珆珉珋珌珏珒珓珖珙珝珡珣珦珧珩珴珵珷珹珺珻珽"],["8fcca1","珿琀琁琄琇琊琑琚琛琤琦琨",9,"琹瑀瑃瑄瑆瑇瑋瑍瑑瑒瑗瑝瑢瑦瑧瑨瑫瑭瑮瑱瑲璀璁璅璆璇璉璏璐璑璒璘璙璚璜璟璠璡璣璦璨璩璪璫璮璯璱璲璵璹璻璿瓈瓉瓌瓐瓓瓘瓚瓛瓞瓟瓤瓨瓪瓫瓯瓴瓺瓻瓼瓿甆"],["8fcda1","甒甖甗甠甡甤甧甩甪甯甶甹甽甾甿畀畃畇畈畎畐畒畗畞畟畡畯畱畹",5,"疁疅疐疒疓疕疙疜疢疤疴疺疿痀痁痄痆痌痎痏痗痜痟痠痡痤痧痬痮痯痱痹瘀瘂瘃瘄瘇瘈瘊瘌瘏瘒瘓瘕瘖瘙瘛瘜瘝瘞瘣瘥瘦瘩瘭瘲瘳瘵瘸瘹"],["8fcea1","瘺瘼癊癀癁癃癄癅癉癋癕癙癟癤癥癭癮癯癱癴皁皅皌皍皕皛皜皝皟皠皢",6,"皪皭皽盁盅盉盋盌盎盔盙盠盦盨盬盰盱盶盹盼眀眆眊眎眒眔眕眗眙眚眜眢眨眭眮眯眴眵眶眹眽眾睂睅睆睊睍睎睏睒睖睗睜睞睟睠睢"],["8fcfa1","睤睧睪睬睰睲睳睴睺睽瞀瞄瞌瞍瞔瞕瞖瞚瞟瞢瞧瞪瞮瞯瞱瞵瞾矃矉矑矒矕矙矞矟矠矤矦矪矬矰矱矴矸矻砅砆砉砍砎砑砝砡砢砣砭砮砰砵砷硃硄硇硈硌硎硒硜硞硠硡硣硤硨硪确硺硾碊碏碔碘碡碝碞碟碤碨碬碭碰碱碲碳"],["8fd0a1","碻碽碿磇磈磉磌磎磒磓磕磖磤磛磟磠磡磦磪磲磳礀磶磷磺磻磿礆礌礐礚礜礞礟礠礥礧礩礭礱礴礵礻礽礿祄祅祆祊祋祏祑祔祘祛祜祧祩祫祲祹祻祼祾禋禌禑禓禔禕禖禘禛禜禡禨禩禫禯禱禴禸离秂秄秇秈秊秏秔秖秚秝秞"],["8fd1a1","秠秢秥秪秫秭秱秸秼稂稃稇稉稊稌稑稕稛稞稡稧稫稭稯稰稴稵稸稹稺穄穅穇穈穌穕穖穙穜穝穟穠穥穧穪穭穵穸穾窀窂窅窆窊窋窐窑窔窞窠窣窬窳窵窹窻窼竆竉竌竎竑竛竨竩竫竬竱竴竻竽竾笇笔笟笣笧笩笪笫笭笮笯笰"],["8fd2a1","笱笴笽笿筀筁筇筎筕筠筤筦筩筪筭筯筲筳筷箄箉箎箐箑箖箛箞箠箥箬箯箰箲箵箶箺箻箼箽篂篅篈篊篔篖篗篙篚篛篨篪篲篴篵篸篹篺篼篾簁簂簃簄簆簉簋簌簎簏簙簛簠簥簦簨簬簱簳簴簶簹簺籆籊籕籑籒籓籙",5],["8fd3a1","籡籣籧籩籭籮籰籲籹籼籽粆粇粏粔粞粠粦粰粶粷粺粻粼粿糄糇糈糉糍糏糓糔糕糗糙糚糝糦糩糫糵紃紇紈紉紏紑紒紓紖紝紞紣紦紪紭紱紼紽紾絀絁絇絈絍絑絓絗絙絚絜絝絥絧絪絰絸絺絻絿綁綂綃綅綆綈綋綌綍綑綖綗綝"],["8fd4a1","綞綦綧綪綳綶綷綹緂",4,"緌緍緎緗緙縀緢緥緦緪緫緭緱緵緶緹緺縈縐縑縕縗縜縝縠縧縨縬縭縯縳縶縿繄繅繇繎繐繒繘繟繡繢繥繫繮繯繳繸繾纁纆纇纊纍纑纕纘纚纝纞缼缻缽缾缿罃罄罇罏罒罓罛罜罝罡罣罤罥罦罭"],["8fd5a1","罱罽罾罿羀羋羍羏羐羑羖羗羜羡羢羦羪羭羴羼羿翀翃翈翎翏翛翟翣翥翨翬翮翯翲翺翽翾翿耇耈耊耍耎耏耑耓耔耖耝耞耟耠耤耦耬耮耰耴耵耷耹耺耼耾聀聄聠聤聦聭聱聵肁肈肎肜肞肦肧肫肸肹胈胍胏胒胔胕胗胘胠胭胮"],["8fd6a1","胰胲胳胶胹胺胾脃脋脖脗脘脜脞脠脤脧脬脰脵脺脼腅腇腊腌腒腗腠腡腧腨腩腭腯腷膁膐膄膅膆膋膎膖膘膛膞膢膮膲膴膻臋臃臅臊臎臏臕臗臛臝臞臡臤臫臬臰臱臲臵臶臸臹臽臿舀舃舏舓舔舙舚舝舡舢舨舲舴舺艃艄艅艆"],["8fd7a1","艋艎艏艑艖艜艠艣艧艭艴艻艽艿芀芁芃芄芇芉芊芎芑芔芖芘芚芛芠芡芣芤芧芨芩芪芮芰芲芴芷芺芼芾芿苆苐苕苚苠苢苤苨苪苭苯苶苷苽苾茀茁茇茈茊茋荔茛茝茞茟茡茢茬茭茮茰茳茷茺茼茽荂荃荄荇荍荎荑荕荖荗荰荸"],["8fd8a1","荽荿莀莂莄莆莍莒莔莕莘莙莛莜莝莦莧莩莬莾莿菀菇菉菏菐菑菔菝荓菨菪菶菸菹菼萁萆萊萏萑萕萙莭萯萹葅葇葈葊葍葏葑葒葖葘葙葚葜葠葤葥葧葪葰葳葴葶葸葼葽蒁蒅蒒蒓蒕蒞蒦蒨蒩蒪蒯蒱蒴蒺蒽蒾蓀蓂蓇蓈蓌蓏蓓"],["8fd9a1","蓜蓧蓪蓯蓰蓱蓲蓷蔲蓺蓻蓽蔂蔃蔇蔌蔎蔐蔜蔞蔢蔣蔤蔥蔧蔪蔫蔯蔳蔴蔶蔿蕆蕏",4,"蕖蕙蕜",6,"蕤蕫蕯蕹蕺蕻蕽蕿薁薅薆薉薋薌薏薓薘薝薟薠薢薥薧薴薶薷薸薼薽薾薿藂藇藊藋藎薭藘藚藟藠藦藨藭藳藶藼"],["8fdaa1","藿蘀蘄蘅蘍蘎蘐蘑蘒蘘蘙蘛蘞蘡蘧蘩蘶蘸蘺蘼蘽虀虂虆虒虓虖虗虘虙虝虠",4,"虩虬虯虵虶虷虺蚍蚑蚖蚘蚚蚜蚡蚦蚧蚨蚭蚱蚳蚴蚵蚷蚸蚹蚿蛀蛁蛃蛅蛑蛒蛕蛗蛚蛜蛠蛣蛥蛧蚈蛺蛼蛽蜄蜅蜇蜋蜎蜏蜐蜓蜔蜙蜞蜟蜡蜣"],["8fdba1","蜨蜮蜯蜱蜲蜹蜺蜼蜽蜾蝀蝃蝅蝍蝘蝝蝡蝤蝥蝯蝱蝲蝻螃",6,"螋螌螐螓螕螗螘螙螞螠螣螧螬螭螮螱螵螾螿蟁蟈蟉蟊蟎蟕蟖蟙蟚蟜蟟蟢蟣蟤蟪蟫蟭蟱蟳蟸蟺蟿蠁蠃蠆蠉蠊蠋蠐蠙蠒蠓蠔蠘蠚蠛蠜蠞蠟蠨蠭蠮蠰蠲蠵"],["8fdca1","蠺蠼衁衃衅衈衉衊衋衎衑衕衖衘衚衜衟衠衤衩衱衹衻袀袘袚袛袜袟袠袨袪袺袽袾裀裊",4,"裑裒裓裛裞裧裯裰裱裵裷褁褆褍褎褏褕褖褘褙褚褜褠褦褧褨褰褱褲褵褹褺褾襀襂襅襆襉襏襒襗襚襛襜襡襢襣襫襮襰襳襵襺"],["8fdda1","襻襼襽覉覍覐覔覕覛覜覟覠覥覰覴覵覶覷覼觔",4,"觥觩觫觭觱觳觶觹觽觿訄訅訇訏訑訒訔訕訞訠訢訤訦訫訬訯訵訷訽訾詀詃詅詇詉詍詎詓詖詗詘詜詝詡詥詧詵詶詷詹詺詻詾詿誀誃誆誋誏誐誒誖誗誙誟誧誩誮誯誳"],["8fdea1","誶誷誻誾諃諆諈諉諊諑諓諔諕諗諝諟諬諰諴諵諶諼諿謅謆謋謑謜謞謟謊謭謰謷謼譂",4,"譈譒譓譔譙譍譞譣譭譶譸譹譼譾讁讄讅讋讍讏讔讕讜讞讟谸谹谽谾豅豇豉豋豏豑豓豔豗豘豛豝豙豣豤豦豨豩豭豳豵豶豻豾貆"],["8fdfa1","貇貋貐貒貓貙貛貜貤貹貺賅賆賉賋賏賖賕賙賝賡賨賬賯賰賲賵賷賸賾賿贁贃贉贒贗贛赥赩赬赮赿趂趄趈趍趐趑趕趞趟趠趦趫趬趯趲趵趷趹趻跀跅跆跇跈跊跎跑跔跕跗跙跤跥跧跬跰趼跱跲跴跽踁踄踅踆踋踑踔踖踠踡踢"],["8fe0a1","踣踦踧踱踳踶踷踸踹踽蹀蹁蹋蹍蹎蹏蹔蹛蹜蹝蹞蹡蹢蹩蹬蹭蹯蹰蹱蹹蹺蹻躂躃躉躐躒躕躚躛躝躞躢躧躩躭躮躳躵躺躻軀軁軃軄軇軏軑軔軜軨軮軰軱軷軹軺軭輀輂輇輈輏輐輖輗輘輞輠輡輣輥輧輨輬輭輮輴輵輶輷輺轀轁"],["8fe1a1","轃轇轏轑",4,"轘轝轞轥辝辠辡辤辥辦辵辶辸达迀迁迆迊迋迍运迒迓迕迠迣迤迨迮迱迵迶迻迾适逄逈逌逘逛逨逩逯逪逬逭逳逴逷逿遃遄遌遛遝遢遦遧遬遰遴遹邅邈邋邌邎邐邕邗邘邙邛邠邡邢邥邰邲邳邴邶邽郌邾郃"],["8fe2a1","郄郅郇郈郕郗郘郙郜郝郟郥郒郶郫郯郰郴郾郿鄀鄄鄅鄆鄈鄍鄐鄔鄖鄗鄘鄚鄜鄞鄠鄥鄢鄣鄧鄩鄮鄯鄱鄴鄶鄷鄹鄺鄼鄽酃酇酈酏酓酗酙酚酛酡酤酧酭酴酹酺酻醁醃醅醆醊醎醑醓醔醕醘醞醡醦醨醬醭醮醰醱醲醳醶醻醼醽醿"],["8fe3a1","釂釃釅釓釔釗釙釚釞釤釥釩釪釬",5,"釷釹釻釽鈀鈁鈄鈅鈆鈇鈉鈊鈌鈐鈒鈓鈖鈘鈜鈝鈣鈤鈥鈦鈨鈮鈯鈰鈳鈵鈶鈸鈹鈺鈼鈾鉀鉂鉃鉆鉇鉊鉍鉎鉏鉑鉘鉙鉜鉝鉠鉡鉥鉧鉨鉩鉮鉯鉰鉵",4,"鉻鉼鉽鉿銈銉銊銍銎銒銗"],["8fe4a1","銙銟銠銤銥銧銨銫銯銲銶銸銺銻銼銽銿",4,"鋅鋆鋇鋈鋋鋌鋍鋎鋐鋓鋕鋗鋘鋙鋜鋝鋟鋠鋡鋣鋥鋧鋨鋬鋮鋰鋹鋻鋿錀錂錈錍錑錔錕錜錝錞錟錡錤錥錧錩錪錳錴錶錷鍇鍈鍉鍐鍑鍒鍕鍗鍘鍚鍞鍤鍥鍧鍩鍪鍭鍯鍰鍱鍳鍴鍶"],["8fe5a1","鍺鍽鍿鎀鎁鎂鎈鎊鎋鎍鎏鎒鎕鎘鎛鎞鎡鎣鎤鎦鎨鎫鎴鎵鎶鎺鎩鏁鏄鏅鏆鏇鏉",4,"鏓鏙鏜鏞鏟鏢鏦鏧鏹鏷鏸鏺鏻鏽鐁鐂鐄鐈鐉鐍鐎鐏鐕鐖鐗鐟鐮鐯鐱鐲鐳鐴鐻鐿鐽鑃鑅鑈鑊鑌鑕鑙鑜鑟鑡鑣鑨鑫鑭鑮鑯鑱鑲钄钃镸镹"],["8fe6a1","镾閄閈閌閍閎閝閞閟閡閦閩閫閬閴閶閺閽閿闆闈闉闋闐闑闒闓闙闚闝闞闟闠闤闦阝阞阢阤阥阦阬阱阳阷阸阹阺阼阽陁陒陔陖陗陘陡陮陴陻陼陾陿隁隂隃隄隉隑隖隚隝隟隤隥隦隩隮隯隳隺雊雒嶲雘雚雝雞雟雩雯雱雺霂"],["8fe7a1","霃霅霉霚霛霝霡霢霣霨霱霳靁靃靊靎靏靕靗靘靚靛靣靧靪靮靳靶靷靸靻靽靿鞀鞉鞕鞖鞗鞙鞚鞞鞟鞢鞬鞮鞱鞲鞵鞶鞸鞹鞺鞼鞾鞿韁韄韅韇韉韊韌韍韎韐韑韔韗韘韙韝韞韠韛韡韤韯韱韴韷韸韺頇頊頙頍頎頔頖頜頞頠頣頦"],["8fe8a1","頫頮頯頰頲頳頵頥頾顄顇顊顑顒顓顖顗顙顚顢顣顥顦顪顬颫颭颮颰颴颷颸颺颻颿飂飅飈飌飡飣飥飦飧飪飳飶餂餇餈餑餕餖餗餚餛餜餟餢餦餧餫餱",4,"餹餺餻餼饀饁饆饇饈饍饎饔饘饙饛饜饞饟饠馛馝馟馦馰馱馲馵"],["8fe9a1","馹馺馽馿駃駉駓駔駙駚駜駞駧駪駫駬駰駴駵駹駽駾騂騃騄騋騌騐騑騖騞騠騢騣騤騧騭騮騳騵騶騸驇驁驄驊驋驌驎驑驔驖驝骪骬骮骯骲骴骵骶骹骻骾骿髁髃髆髈髎髐髒髕髖髗髛髜髠髤髥髧髩髬髲髳髵髹髺髽髿",4],["8feaa1","鬄鬅鬈鬉鬋鬌鬍鬎鬐鬒鬖鬙鬛鬜鬠鬦鬫鬭鬳鬴鬵鬷鬹鬺鬽魈魋魌魕魖魗魛魞魡魣魥魦魨魪",4,"魳魵魷魸魹魿鮀鮄鮅鮆鮇鮉鮊鮋鮍鮏鮐鮔鮚鮝鮞鮦鮧鮩鮬鮰鮱鮲鮷鮸鮻鮼鮾鮿鯁鯇鯈鯎鯐鯗鯘鯝鯟鯥鯧鯪鯫鯯鯳鯷鯸"],["8feba1","鯹鯺鯽鯿鰀鰂鰋鰏鰑鰖鰘鰙鰚鰜鰞鰢鰣鰦",4,"鰱鰵鰶鰷鰽鱁鱃鱄鱅鱉鱊鱎鱏鱐鱓鱔鱖鱘鱛鱝鱞鱟鱣鱩鱪鱜鱫鱨鱮鱰鱲鱵鱷鱻鳦鳲鳷鳹鴋鴂鴑鴗鴘鴜鴝鴞鴯鴰鴲鴳鴴鴺鴼鵅鴽鵂鵃鵇鵊鵓鵔鵟鵣鵢鵥鵩鵪鵫鵰鵶鵷鵻"],["8feca1","鵼鵾鶃鶄鶆鶊鶍鶎鶒鶓鶕鶖鶗鶘鶡鶪鶬鶮鶱鶵鶹鶼鶿鷃鷇鷉鷊鷔鷕鷖鷗鷚鷞鷟鷠鷥鷧鷩鷫鷮鷰鷳鷴鷾鸊鸂鸇鸎鸐鸑鸒鸕鸖鸙鸜鸝鹺鹻鹼麀麂麃麄麅麇麎麏麖麘麛麞麤麨麬麮麯麰麳麴麵黆黈黋黕黟黤黧黬黭黮黰黱黲黵"],["8feda1","黸黿鼂鼃鼉鼏鼐鼑鼒鼔鼖鼗鼙鼚鼛鼟鼢鼦鼪鼫鼯鼱鼲鼴鼷鼹鼺鼼鼽鼿齁齃",4,"齓齕齖齗齘齚齝齞齨齩齭",4,"齳齵齺齽龏龐龑龒龔龖龗龞龡龢龣龥"]]},48:function(e){e.exports=[["0","\0",127],["a140","　，、。．‧；：？！︰…‥﹐﹑﹒·﹔﹕﹖﹗｜–︱—︳╴︴﹏（）︵︶｛｝︷︸〔〕︹︺【】︻︼《》︽︾〈〉︿﹀「」﹁﹂『』﹃﹄﹙﹚"],["a1a1","﹛﹜﹝﹞‘’“”〝〞‵′＃＆＊※§〃○●△▲◎☆★◇◆□■▽▼㊣℅¯￣＿ˍ﹉﹊﹍﹎﹋﹌﹟﹠﹡＋－×÷±√＜＞＝≦≧≠∞≒≡﹢",4,"～∩∪⊥∠∟⊿㏒㏑∫∮∵∴♀♂⊕⊙↑↓←→↖↗↙↘∥∣／"],["a240","＼∕﹨＄￥〒￠￡％＠℃℉﹩﹪﹫㏕㎜㎝㎞㏎㎡㎎㎏㏄°兙兛兞兝兡兣嗧瓩糎▁",7,"▏▎▍▌▋▊▉┼┴┬┤├▔─│▕┌┐└┘╭"],["a2a1","╮╰╯═╞╪╡◢◣◥◤╱╲╳０",9,"Ⅰ",9,"〡",8,"十卄卅Ａ",25,"ａ",21],["a340","ｗｘｙｚΑ",16,"Σ",6,"α",16,"σ",6,"ㄅ",10],["a3a1","ㄐ",25,"˙ˉˊˇˋ"],["a3e1","€"],["a440","一乙丁七乃九了二人儿入八几刀刁力匕十卜又三下丈上丫丸凡久么也乞于亡兀刃勺千叉口土士夕大女子孑孓寸小尢尸山川工己已巳巾干廾弋弓才"],["a4a1","丑丐不中丰丹之尹予云井互五亢仁什仃仆仇仍今介仄元允內六兮公冗凶分切刈勻勾勿化匹午升卅卞厄友及反壬天夫太夭孔少尤尺屯巴幻廿弔引心戈戶手扎支文斗斤方日曰月木欠止歹毋比毛氏水火爪父爻片牙牛犬王丙"],["a540","世丕且丘主乍乏乎以付仔仕他仗代令仙仞充兄冉冊冬凹出凸刊加功包匆北匝仟半卉卡占卯卮去可古右召叮叩叨叼司叵叫另只史叱台句叭叻四囚外"],["a5a1","央失奴奶孕它尼巨巧左市布平幼弁弘弗必戊打扔扒扑斥旦朮本未末札正母民氐永汁汀氾犯玄玉瓜瓦甘生用甩田由甲申疋白皮皿目矛矢石示禾穴立丞丟乒乓乩亙交亦亥仿伉伙伊伕伍伐休伏仲件任仰仳份企伋光兇兆先全"],["a640","共再冰列刑划刎刖劣匈匡匠印危吉吏同吊吐吁吋各向名合吃后吆吒因回囝圳地在圭圬圯圩夙多夷夸妄奸妃好她如妁字存宇守宅安寺尖屹州帆并年"],["a6a1","式弛忙忖戎戌戍成扣扛托收早旨旬旭曲曳有朽朴朱朵次此死氖汝汗汙江池汐汕污汛汍汎灰牟牝百竹米糸缶羊羽老考而耒耳聿肉肋肌臣自至臼舌舛舟艮色艾虫血行衣西阡串亨位住佇佗佞伴佛何估佐佑伽伺伸佃佔似但佣"],["a740","作你伯低伶余佝佈佚兌克免兵冶冷別判利刪刨劫助努劬匣即卵吝吭吞吾否呎吧呆呃吳呈呂君吩告吹吻吸吮吵吶吠吼呀吱含吟听囪困囤囫坊坑址坍"],["a7a1","均坎圾坐坏圻壯夾妝妒妨妞妣妙妖妍妤妓妊妥孝孜孚孛完宋宏尬局屁尿尾岐岑岔岌巫希序庇床廷弄弟彤形彷役忘忌志忍忱快忸忪戒我抄抗抖技扶抉扭把扼找批扳抒扯折扮投抓抑抆改攻攸旱更束李杏材村杜杖杞杉杆杠"],["a840","杓杗步每求汞沙沁沈沉沅沛汪決沐汰沌汨沖沒汽沃汲汾汴沆汶沍沔沘沂灶灼災灸牢牡牠狄狂玖甬甫男甸皂盯矣私秀禿究系罕肖肓肝肘肛肚育良芒"],["a8a1","芋芍見角言谷豆豕貝赤走足身車辛辰迂迆迅迄巡邑邢邪邦那酉釆里防阮阱阪阬並乖乳事些亞享京佯依侍佳使佬供例來侃佰併侈佩佻侖佾侏侑佺兔兒兕兩具其典冽函刻券刷刺到刮制剁劾劻卒協卓卑卦卷卸卹取叔受味呵"],["a940","咖呸咕咀呻呷咄咒咆呼咐呱呶和咚呢周咋命咎固垃坷坪坩坡坦坤坼夜奉奇奈奄奔妾妻委妹妮姑姆姐姍始姓姊妯妳姒姅孟孤季宗定官宜宙宛尚屈居"],["a9a1","屆岷岡岸岩岫岱岳帘帚帖帕帛帑幸庚店府底庖延弦弧弩往征彿彼忝忠忽念忿怏怔怯怵怖怪怕怡性怩怫怛或戕房戾所承拉拌拄抿拂抹拒招披拓拔拋拈抨抽押拐拙拇拍抵拚抱拘拖拗拆抬拎放斧於旺昔易昌昆昂明昀昏昕昊"],["aa40","昇服朋杭枋枕東果杳杷枇枝林杯杰板枉松析杵枚枓杼杪杲欣武歧歿氓氛泣注泳沱泌泥河沽沾沼波沫法泓沸泄油況沮泗泅泱沿治泡泛泊沬泯泜泖泠"],["aaa1","炕炎炒炊炙爬爭爸版牧物狀狎狙狗狐玩玨玟玫玥甽疝疙疚的盂盲直知矽社祀祁秉秈空穹竺糾罔羌羋者肺肥肢肱股肫肩肴肪肯臥臾舍芳芝芙芭芽芟芹花芬芥芯芸芣芰芾芷虎虱初表軋迎返近邵邸邱邶采金長門阜陀阿阻附"],["ab40","陂隹雨青非亟亭亮信侵侯便俠俑俏保促侶俘俟俊俗侮俐俄係俚俎俞侷兗冒冑冠剎剃削前剌剋則勇勉勃勁匍南卻厚叛咬哀咨哎哉咸咦咳哇哂咽咪品"],["aba1","哄哈咯咫咱咻咩咧咿囿垂型垠垣垢城垮垓奕契奏奎奐姜姘姿姣姨娃姥姪姚姦威姻孩宣宦室客宥封屎屏屍屋峙峒巷帝帥帟幽庠度建弈弭彥很待徊律徇後徉怒思怠急怎怨恍恰恨恢恆恃恬恫恪恤扁拜挖按拼拭持拮拽指拱拷"],["ac40","拯括拾拴挑挂政故斫施既春昭映昧是星昨昱昤曷柿染柱柔某柬架枯柵柩柯柄柑枴柚查枸柏柞柳枰柙柢柝柒歪殃殆段毒毗氟泉洋洲洪流津洌洱洞洗"],["aca1","活洽派洶洛泵洹洧洸洩洮洵洎洫炫為炳炬炯炭炸炮炤爰牲牯牴狩狠狡玷珊玻玲珍珀玳甚甭畏界畎畋疫疤疥疢疣癸皆皇皈盈盆盃盅省盹相眉看盾盼眇矜砂研砌砍祆祉祈祇禹禺科秒秋穿突竿竽籽紂紅紀紉紇約紆缸美羿耄"],["ad40","耐耍耑耶胖胥胚胃胄背胡胛胎胞胤胝致舢苧范茅苣苛苦茄若茂茉苒苗英茁苜苔苑苞苓苟苯茆虐虹虻虺衍衫要觔計訂訃貞負赴赳趴軍軌述迦迢迪迥"],["ada1","迭迫迤迨郊郎郁郃酋酊重閂限陋陌降面革韋韭音頁風飛食首香乘亳倌倍倣俯倦倥俸倩倖倆值借倚倒們俺倀倔倨俱倡個候倘俳修倭倪俾倫倉兼冤冥冢凍凌准凋剖剜剔剛剝匪卿原厝叟哨唐唁唷哼哥哲唆哺唔哩哭員唉哮哪"],["ae40","哦唧唇哽唏圃圄埂埔埋埃堉夏套奘奚娑娘娜娟娛娓姬娠娣娩娥娌娉孫屘宰害家宴宮宵容宸射屑展屐峭峽峻峪峨峰島崁峴差席師庫庭座弱徒徑徐恙"],["aea1","恣恥恐恕恭恩息悄悟悚悍悔悌悅悖扇拳挈拿捎挾振捕捂捆捏捉挺捐挽挪挫挨捍捌效敉料旁旅時晉晏晃晒晌晅晁書朔朕朗校核案框桓根桂桔栩梳栗桌桑栽柴桐桀格桃株桅栓栘桁殊殉殷氣氧氨氦氤泰浪涕消涇浦浸海浙涓"],["af40","浬涉浮浚浴浩涌涊浹涅浥涔烊烘烤烙烈烏爹特狼狹狽狸狷玆班琉珮珠珪珞畔畝畜畚留疾病症疲疳疽疼疹痂疸皋皰益盍盎眩真眠眨矩砰砧砸砝破砷"],["afa1","砥砭砠砟砲祕祐祠祟祖神祝祗祚秤秣秧租秦秩秘窄窈站笆笑粉紡紗紋紊素索純紐紕級紜納紙紛缺罟羔翅翁耆耘耕耙耗耽耿胱脂胰脅胭胴脆胸胳脈能脊胼胯臭臬舀舐航舫舨般芻茫荒荔荊茸荐草茵茴荏茲茹茶茗荀茱茨荃"],["b040","虔蚊蚪蚓蚤蚩蚌蚣蚜衰衷袁袂衽衹記訐討訌訕訊託訓訖訏訑豈豺豹財貢起躬軒軔軏辱送逆迷退迺迴逃追逅迸邕郡郝郢酒配酌釘針釗釜釙閃院陣陡"],["b0a1","陛陝除陘陞隻飢馬骨高鬥鬲鬼乾偺偽停假偃偌做偉健偶偎偕偵側偷偏倏偯偭兜冕凰剪副勒務勘動匐匏匙匿區匾參曼商啪啦啄啞啡啃啊唱啖問啕唯啤唸售啜唬啣唳啁啗圈國圉域堅堊堆埠埤基堂堵執培夠奢娶婁婉婦婪婀"],["b140","娼婢婚婆婊孰寇寅寄寂宿密尉專將屠屜屝崇崆崎崛崖崢崑崩崔崙崤崧崗巢常帶帳帷康庸庶庵庾張強彗彬彩彫得徙從徘御徠徜恿患悉悠您惋悴惦悽"],["b1a1","情悻悵惜悼惘惕惆惟悸惚惇戚戛扈掠控捲掖探接捷捧掘措捱掩掉掃掛捫推掄授掙採掬排掏掀捻捩捨捺敝敖救教敗啟敏敘敕敔斜斛斬族旋旌旎晝晚晤晨晦晞曹勗望梁梯梢梓梵桿桶梱梧梗械梃棄梭梆梅梔條梨梟梡梂欲殺"],["b240","毫毬氫涎涼淳淙液淡淌淤添淺清淇淋涯淑涮淞淹涸混淵淅淒渚涵淚淫淘淪深淮淨淆淄涪淬涿淦烹焉焊烽烯爽牽犁猜猛猖猓猙率琅琊球理現琍瓠瓶"],["b2a1","瓷甜產略畦畢異疏痔痕疵痊痍皎盔盒盛眷眾眼眶眸眺硫硃硎祥票祭移窒窕笠笨笛第符笙笞笮粒粗粕絆絃統紮紹紼絀細紳組累終紲紱缽羞羚翌翎習耜聊聆脯脖脣脫脩脰脤舂舵舷舶船莎莞莘荸莢莖莽莫莒莊莓莉莠荷荻荼"],["b340","莆莧處彪蛇蛀蚶蛄蚵蛆蛋蚱蚯蛉術袞袈被袒袖袍袋覓規訪訝訣訥許設訟訛訢豉豚販責貫貨貪貧赧赦趾趺軛軟這逍通逗連速逝逐逕逞造透逢逖逛途"],["b3a1","部郭都酗野釵釦釣釧釭釩閉陪陵陳陸陰陴陶陷陬雀雪雩章竟頂頃魚鳥鹵鹿麥麻傢傍傅備傑傀傖傘傚最凱割剴創剩勞勝勛博厥啻喀喧啼喊喝喘喂喜喪喔喇喋喃喳單喟唾喲喚喻喬喱啾喉喫喙圍堯堪場堤堰報堡堝堠壹壺奠"],["b440","婷媚婿媒媛媧孳孱寒富寓寐尊尋就嵌嵐崴嵇巽幅帽幀幃幾廊廁廂廄弼彭復循徨惑惡悲悶惠愜愣惺愕惰惻惴慨惱愎惶愉愀愒戟扉掣掌描揀揩揉揆揍"],["b4a1","插揣提握揖揭揮捶援揪換摒揚揹敞敦敢散斑斐斯普晰晴晶景暑智晾晷曾替期朝棺棕棠棘棗椅棟棵森棧棹棒棲棣棋棍植椒椎棉棚楮棻款欺欽殘殖殼毯氮氯氬港游湔渡渲湧湊渠渥渣減湛湘渤湖湮渭渦湯渴湍渺測湃渝渾滋"],["b540","溉渙湎湣湄湲湩湟焙焚焦焰無然煮焜牌犄犀猶猥猴猩琺琪琳琢琥琵琶琴琯琛琦琨甥甦畫番痢痛痣痙痘痞痠登發皖皓皴盜睏短硝硬硯稍稈程稅稀窘"],["b5a1","窗窖童竣等策筆筐筒答筍筋筏筑粟粥絞結絨絕紫絮絲絡給絢絰絳善翔翕耋聒肅腕腔腋腑腎脹腆脾腌腓腴舒舜菩萃菸萍菠菅萋菁華菱菴著萊菰萌菌菽菲菊萸萎萄菜萇菔菟虛蛟蛙蛭蛔蛛蛤蛐蛞街裁裂袱覃視註詠評詞証詁"],["b640","詔詛詐詆訴診訶詖象貂貯貼貳貽賁費賀貴買貶貿貸越超趁跎距跋跚跑跌跛跆軻軸軼辜逮逵週逸進逶鄂郵鄉郾酣酥量鈔鈕鈣鈉鈞鈍鈐鈇鈑閔閏開閑"],["b6a1","間閒閎隊階隋陽隅隆隍陲隄雁雅雄集雇雯雲韌項順須飧飪飯飩飲飭馮馭黃黍黑亂傭債傲傳僅傾催傷傻傯僇剿剷剽募勦勤勢勣匯嗟嗨嗓嗦嗎嗜嗇嗑嗣嗤嗯嗚嗡嗅嗆嗥嗉園圓塞塑塘塗塚塔填塌塭塊塢塒塋奧嫁嫉嫌媾媽媼"],["b740","媳嫂媲嵩嵯幌幹廉廈弒彙徬微愚意慈感想愛惹愁愈慎慌慄慍愾愴愧愍愆愷戡戢搓搾搞搪搭搽搬搏搜搔損搶搖搗搆敬斟新暗暉暇暈暖暄暘暍會榔業"],["b7a1","楚楷楠楔極椰概楊楨楫楞楓楹榆楝楣楛歇歲毀殿毓毽溢溯滓溶滂源溝滇滅溥溘溼溺溫滑準溜滄滔溪溧溴煎煙煩煤煉照煜煬煦煌煥煞煆煨煖爺牒猷獅猿猾瑯瑚瑕瑟瑞瑁琿瑙瑛瑜當畸瘀痰瘁痲痱痺痿痴痳盞盟睛睫睦睞督"],["b840","睹睪睬睜睥睨睢矮碎碰碗碘碌碉硼碑碓硿祺祿禁萬禽稜稚稠稔稟稞窟窠筷節筠筮筧粱粳粵經絹綑綁綏絛置罩罪署義羨群聖聘肆肄腱腰腸腥腮腳腫"],["b8a1","腹腺腦舅艇蒂葷落萱葵葦葫葉葬葛萼萵葡董葩葭葆虞虜號蛹蜓蜈蜇蜀蛾蛻蜂蜃蜆蜊衙裟裔裙補裘裝裡裊裕裒覜解詫該詳試詩詰誇詼詣誠話誅詭詢詮詬詹詻訾詨豢貊貉賊資賈賄貲賃賂賅跡跟跨路跳跺跪跤跦躲較載軾輊"],["b940","辟農運遊道遂達逼違遐遇遏過遍遑逾遁鄒鄗酬酪酩釉鈷鉗鈸鈽鉀鈾鉛鉋鉤鉑鈴鉉鉍鉅鈹鈿鉚閘隘隔隕雍雋雉雊雷電雹零靖靴靶預頑頓頊頒頌飼飴"],["b9a1","飽飾馳馱馴髡鳩麂鼎鼓鼠僧僮僥僖僭僚僕像僑僱僎僩兢凳劃劂匱厭嗾嘀嘛嘗嗽嘔嘆嘉嘍嘎嗷嘖嘟嘈嘐嗶團圖塵塾境墓墊塹墅塽壽夥夢夤奪奩嫡嫦嫩嫗嫖嫘嫣孵寞寧寡寥實寨寢寤察對屢嶄嶇幛幣幕幗幔廓廖弊彆彰徹慇"],["ba40","愿態慷慢慣慟慚慘慵截撇摘摔撤摸摟摺摑摧搴摭摻敲斡旗旖暢暨暝榜榨榕槁榮槓構榛榷榻榫榴槐槍榭槌榦槃榣歉歌氳漳演滾漓滴漩漾漠漬漏漂漢"],["baa1","滿滯漆漱漸漲漣漕漫漯澈漪滬漁滲滌滷熔熙煽熊熄熒爾犒犖獄獐瑤瑣瑪瑰瑭甄疑瘧瘍瘋瘉瘓盡監瞄睽睿睡磁碟碧碳碩碣禎福禍種稱窪窩竭端管箕箋筵算箝箔箏箸箇箄粹粽精綻綰綜綽綾綠緊綴網綱綺綢綿綵綸維緒緇綬"],["bb40","罰翠翡翟聞聚肇腐膀膏膈膊腿膂臧臺與舔舞艋蓉蒿蓆蓄蒙蒞蒲蒜蓋蒸蓀蓓蒐蒼蓑蓊蜿蜜蜻蜢蜥蜴蜘蝕蜷蜩裳褂裴裹裸製裨褚裯誦誌語誣認誡誓誤"],["bba1","說誥誨誘誑誚誧豪貍貌賓賑賒赫趙趕跼輔輒輕輓辣遠遘遜遣遙遞遢遝遛鄙鄘鄞酵酸酷酴鉸銀銅銘銖鉻銓銜銨鉼銑閡閨閩閣閥閤隙障際雌雒需靼鞅韶頗領颯颱餃餅餌餉駁骯骰髦魁魂鳴鳶鳳麼鼻齊億儀僻僵價儂儈儉儅凜"],["bc40","劇劈劉劍劊勰厲嘮嘻嘹嘲嘿嘴嘩噓噎噗噴嘶嘯嘰墀墟增墳墜墮墩墦奭嬉嫻嬋嫵嬌嬈寮寬審寫層履嶝嶔幢幟幡廢廚廟廝廣廠彈影德徵慶慧慮慝慕憂"],["bca1","慼慰慫慾憧憐憫憎憬憚憤憔憮戮摩摯摹撞撲撈撐撰撥撓撕撩撒撮播撫撚撬撙撢撳敵敷數暮暫暴暱樣樟槨樁樞標槽模樓樊槳樂樅槭樑歐歎殤毅毆漿潼澄潑潦潔澆潭潛潸潮澎潺潰潤澗潘滕潯潠潟熟熬熱熨牖犛獎獗瑩璋璃"],["bd40","瑾璀畿瘠瘩瘟瘤瘦瘡瘢皚皺盤瞎瞇瞌瞑瞋磋磅確磊碾磕碼磐稿稼穀稽稷稻窯窮箭箱範箴篆篇篁箠篌糊締練緯緻緘緬緝編緣線緞緩綞緙緲緹罵罷羯"],["bda1","翩耦膛膜膝膠膚膘蔗蔽蔚蓮蔬蔭蔓蔑蔣蔡蔔蓬蔥蓿蔆螂蝴蝶蝠蝦蝸蝨蝙蝗蝌蝓衛衝褐複褒褓褕褊誼諒談諄誕請諸課諉諂調誰論諍誶誹諛豌豎豬賠賞賦賤賬賭賢賣賜質賡赭趟趣踫踐踝踢踏踩踟踡踞躺輝輛輟輩輦輪輜輞"],["be40","輥適遮遨遭遷鄰鄭鄧鄱醇醉醋醃鋅銻銷鋪銬鋤鋁銳銼鋒鋇鋰銲閭閱霄霆震霉靠鞍鞋鞏頡頫頜颳養餓餒餘駝駐駟駛駑駕駒駙骷髮髯鬧魅魄魷魯鴆鴉"],["bea1","鴃麩麾黎墨齒儒儘儔儐儕冀冪凝劑劓勳噙噫噹噩噤噸噪器噥噱噯噬噢噶壁墾壇壅奮嬝嬴學寰導彊憲憑憩憊懍憶憾懊懈戰擅擁擋撻撼據擄擇擂操撿擒擔撾整曆曉暹曄曇暸樽樸樺橙橫橘樹橄橢橡橋橇樵機橈歙歷氅濂澱澡"],["bf40","濃澤濁澧澳激澹澶澦澠澴熾燉燐燒燈燕熹燎燙燜燃燄獨璜璣璘璟璞瓢甌甍瘴瘸瘺盧盥瞠瞞瞟瞥磨磚磬磧禦積穎穆穌穋窺篙簑築篤篛篡篩篦糕糖縊"],["bfa1","縑縈縛縣縞縝縉縐罹羲翰翱翮耨膳膩膨臻興艘艙蕊蕙蕈蕨蕩蕃蕉蕭蕪蕞螃螟螞螢融衡褪褲褥褫褡親覦諦諺諫諱謀諜諧諮諾謁謂諷諭諳諶諼豫豭貓賴蹄踱踴蹂踹踵輻輯輸輳辨辦遵遴選遲遼遺鄴醒錠錶鋸錳錯錢鋼錫錄錚"],["c040","錐錦錡錕錮錙閻隧隨險雕霎霑霖霍霓霏靛靜靦鞘頰頸頻頷頭頹頤餐館餞餛餡餚駭駢駱骸骼髻髭鬨鮑鴕鴣鴦鴨鴒鴛默黔龍龜優償儡儲勵嚎嚀嚐嚅嚇"],["c0a1","嚏壕壓壑壎嬰嬪嬤孺尷屨嶼嶺嶽嶸幫彌徽應懂懇懦懋戲戴擎擊擘擠擰擦擬擱擢擭斂斃曙曖檀檔檄檢檜櫛檣橾檗檐檠歜殮毚氈濘濱濟濠濛濤濫濯澀濬濡濩濕濮濰燧營燮燦燥燭燬燴燠爵牆獰獲璩環璦璨癆療癌盪瞳瞪瞰瞬"],["c140","瞧瞭矯磷磺磴磯礁禧禪穗窿簇簍篾篷簌篠糠糜糞糢糟糙糝縮績繆縷縲繃縫總縱繅繁縴縹繈縵縿縯罄翳翼聱聲聰聯聳臆臃膺臂臀膿膽臉膾臨舉艱薪"],["c1a1","薄蕾薜薑薔薯薛薇薨薊虧蟀蟑螳蟒蟆螫螻螺蟈蟋褻褶襄褸褽覬謎謗謙講謊謠謝謄謐豁谿豳賺賽購賸賻趨蹉蹋蹈蹊轄輾轂轅輿避遽還邁邂邀鄹醣醞醜鍍鎂錨鍵鍊鍥鍋錘鍾鍬鍛鍰鍚鍔闊闋闌闈闆隱隸雖霜霞鞠韓顆颶餵騁"],["c240","駿鮮鮫鮪鮭鴻鴿麋黏點黜黝黛鼾齋叢嚕嚮壙壘嬸彝懣戳擴擲擾攆擺擻擷斷曜朦檳檬櫃檻檸櫂檮檯歟歸殯瀉瀋濾瀆濺瀑瀏燻燼燾燸獷獵璧璿甕癖癘"],["c2a1","癒瞽瞿瞻瞼礎禮穡穢穠竄竅簫簧簪簞簣簡糧織繕繞繚繡繒繙罈翹翻職聶臍臏舊藏薩藍藐藉薰薺薹薦蟯蟬蟲蟠覆覲觴謨謹謬謫豐贅蹙蹣蹦蹤蹟蹕軀轉轍邇邃邈醫醬釐鎔鎊鎖鎢鎳鎮鎬鎰鎘鎚鎗闔闖闐闕離雜雙雛雞霤鞣鞦"],["c340","鞭韹額顏題顎顓颺餾餿餽餮馥騎髁鬃鬆魏魎魍鯊鯉鯽鯈鯀鵑鵝鵠黠鼕鼬儳嚥壞壟壢寵龐廬懲懷懶懵攀攏曠曝櫥櫝櫚櫓瀛瀟瀨瀚瀝瀕瀘爆爍牘犢獸"],["c3a1","獺璽瓊瓣疇疆癟癡矇礙禱穫穩簾簿簸簽簷籀繫繭繹繩繪羅繳羶羹羸臘藩藝藪藕藤藥藷蟻蠅蠍蟹蟾襠襟襖襞譁譜識證譚譎譏譆譙贈贊蹼蹲躇蹶蹬蹺蹴轔轎辭邊邋醱醮鏡鏑鏟鏃鏈鏜鏝鏖鏢鏍鏘鏤鏗鏨關隴難霪霧靡韜韻類"],["c440","願顛颼饅饉騖騙鬍鯨鯧鯖鯛鶉鵡鵲鵪鵬麒麗麓麴勸嚨嚷嚶嚴嚼壤孀孃孽寶巉懸懺攘攔攙曦朧櫬瀾瀰瀲爐獻瓏癢癥礦礪礬礫竇競籌籃籍糯糰辮繽繼"],["c4a1","纂罌耀臚艦藻藹蘑藺蘆蘋蘇蘊蠔蠕襤覺觸議譬警譯譟譫贏贍躉躁躅躂醴釋鐘鐃鏽闡霰飄饒饑馨騫騰騷騵鰓鰍鹹麵黨鼯齟齣齡儷儸囁囀囂夔屬巍懼懾攝攜斕曩櫻欄櫺殲灌爛犧瓖瓔癩矓籐纏續羼蘗蘭蘚蠣蠢蠡蠟襪襬覽譴"],["c540","護譽贓躊躍躋轟辯醺鐮鐳鐵鐺鐸鐲鐫闢霸霹露響顧顥饗驅驃驀騾髏魔魑鰭鰥鶯鶴鷂鶸麝黯鼙齜齦齧儼儻囈囊囉孿巔巒彎懿攤權歡灑灘玀瓤疊癮癬"],["c5a1","禳籠籟聾聽臟襲襯觼讀贖贗躑躓轡酈鑄鑑鑒霽霾韃韁顫饕驕驍髒鬚鱉鰱鰾鰻鷓鷗鼴齬齪龔囌巖戀攣攫攪曬欐瓚竊籤籣籥纓纖纔臢蘸蘿蠱變邐邏鑣鑠鑤靨顯饜驚驛驗髓體髑鱔鱗鱖鷥麟黴囑壩攬灞癱癲矗罐羈蠶蠹衢讓讒"],["c640","讖艷贛釀鑪靂靈靄韆顰驟鬢魘鱟鷹鷺鹼鹽鼇齷齲廳欖灣籬籮蠻觀躡釁鑲鑰顱饞髖鬣黌灤矚讚鑷韉驢驥纜讜躪釅鑽鑾鑼鱷鱸黷豔鑿鸚爨驪鬱鸛鸞籲"],["c940","乂乜凵匚厂万丌乇亍囗兀屮彳丏冇与丮亓仂仉仈冘勼卬厹圠夃夬尐巿旡殳毌气爿丱丼仨仜仩仡仝仚刌匜卌圢圣夗夯宁宄尒尻屴屳帄庀庂忉戉扐氕"],["c9a1","氶汃氿氻犮犰玊禸肊阞伎优伬仵伔仱伀价伈伝伂伅伢伓伄仴伒冱刓刉刐劦匢匟卍厊吇囡囟圮圪圴夼妀奼妅奻奾奷奿孖尕尥屼屺屻屾巟幵庄异弚彴忕忔忏扜扞扤扡扦扢扙扠扚扥旯旮朾朹朸朻机朿朼朳氘汆汒汜汏汊汔汋"],["ca40","汌灱牞犴犵玎甪癿穵网艸艼芀艽艿虍襾邙邗邘邛邔阢阤阠阣佖伻佢佉体佤伾佧佒佟佁佘伭伳伿佡冏冹刜刞刡劭劮匉卣卲厎厏吰吷吪呔呅吙吜吥吘"],["caa1","吽呏呁吨吤呇囮囧囥坁坅坌坉坋坒夆奀妦妘妠妗妎妢妐妏妧妡宎宒尨尪岍岏岈岋岉岒岊岆岓岕巠帊帎庋庉庌庈庍弅弝彸彶忒忑忐忭忨忮忳忡忤忣忺忯忷忻怀忴戺抃抌抎抏抔抇扱扻扺扰抁抈扷扽扲扴攷旰旴旳旲旵杅杇"],["cb40","杙杕杌杈杝杍杚杋毐氙氚汸汧汫沄沋沏汱汯汩沚汭沇沕沜汦汳汥汻沎灴灺牣犿犽狃狆狁犺狅玕玗玓玔玒町甹疔疕皁礽耴肕肙肐肒肜芐芏芅芎芑芓"],["cba1","芊芃芄豸迉辿邟邡邥邞邧邠阰阨阯阭丳侘佼侅佽侀侇佶佴侉侄佷佌侗佪侚佹侁佸侐侜侔侞侒侂侕佫佮冞冼冾刵刲刳剆刱劼匊匋匼厒厔咇呿咁咑咂咈呫呺呾呥呬呴呦咍呯呡呠咘呣呧呤囷囹坯坲坭坫坱坰坶垀坵坻坳坴坢"],["cc40","坨坽夌奅妵妺姏姎妲姌姁妶妼姃姖妱妽姀姈妴姇孢孥宓宕屄屇岮岤岠岵岯岨岬岟岣岭岢岪岧岝岥岶岰岦帗帔帙弨弢弣弤彔徂彾彽忞忥怭怦怙怲怋"],["cca1","怴怊怗怳怚怞怬怢怍怐怮怓怑怌怉怜戔戽抭抴拑抾抪抶拊抮抳抯抻抩抰抸攽斨斻昉旼昄昒昈旻昃昋昍昅旽昑昐曶朊枅杬枎枒杶杻枘枆构杴枍枌杺枟枑枙枃杽极杸杹枔欥殀歾毞氝沓泬泫泮泙沶泔沭泧沷泐泂沺泃泆泭泲"],["cd40","泒泝沴沊沝沀泞泀洰泍泇沰泹泏泩泑炔炘炅炓炆炄炑炖炂炚炃牪狖狋狘狉狜狒狔狚狌狑玤玡玭玦玢玠玬玝瓝瓨甿畀甾疌疘皯盳盱盰盵矸矼矹矻矺"],["cda1","矷祂礿秅穸穻竻籵糽耵肏肮肣肸肵肭舠芠苀芫芚芘芛芵芧芮芼芞芺芴芨芡芩苂芤苃芶芢虰虯虭虮豖迒迋迓迍迖迕迗邲邴邯邳邰阹阽阼阺陃俍俅俓侲俉俋俁俔俜俙侻侳俛俇俖侺俀侹俬剄剉勀勂匽卼厗厖厙厘咺咡咭咥哏"],["ce40","哃茍咷咮哖咶哅哆咠呰咼咢咾呲哞咰垵垞垟垤垌垗垝垛垔垘垏垙垥垚垕壴复奓姡姞姮娀姱姝姺姽姼姶姤姲姷姛姩姳姵姠姾姴姭宨屌峐峘峌峗峋峛"],["cea1","峞峚峉峇峊峖峓峔峏峈峆峎峟峸巹帡帢帣帠帤庰庤庢庛庣庥弇弮彖徆怷怹恔恲恞恅恓恇恉恛恌恀恂恟怤恄恘恦恮扂扃拏挍挋拵挎挃拫拹挏挌拸拶挀挓挔拺挕拻拰敁敃斪斿昶昡昲昵昜昦昢昳昫昺昝昴昹昮朏朐柁柲柈枺"],["cf40","柜枻柸柘柀枷柅柫柤柟枵柍枳柷柶柮柣柂枹柎柧柰枲柼柆柭柌枮柦柛柺柉柊柃柪柋欨殂殄殶毖毘毠氠氡洨洴洭洟洼洿洒洊泚洳洄洙洺洚洑洀洝浂"],["cfa1","洁洘洷洃洏浀洇洠洬洈洢洉洐炷炟炾炱炰炡炴炵炩牁牉牊牬牰牳牮狊狤狨狫狟狪狦狣玅珌珂珈珅玹玶玵玴珫玿珇玾珃珆玸珋瓬瓮甮畇畈疧疪癹盄眈眃眄眅眊盷盻盺矧矨砆砑砒砅砐砏砎砉砃砓祊祌祋祅祄秕种秏秖秎窀"],["d040","穾竑笀笁籺籸籹籿粀粁紃紈紁罘羑羍羾耇耎耏耔耷胘胇胠胑胈胂胐胅胣胙胜胊胕胉胏胗胦胍臿舡芔苙苾苹茇苨茀苕茺苫苖苴苬苡苲苵茌苻苶苰苪"],["d0a1","苤苠苺苳苭虷虴虼虳衁衎衧衪衩觓訄訇赲迣迡迮迠郱邽邿郕郅邾郇郋郈釔釓陔陏陑陓陊陎倞倅倇倓倢倰倛俵俴倳倷倬俶俷倗倜倠倧倵倯倱倎党冔冓凊凄凅凈凎剡剚剒剞剟剕剢勍匎厞唦哢唗唒哧哳哤唚哿唄唈哫唑唅哱"],["d140","唊哻哷哸哠唎唃唋圁圂埌堲埕埒垺埆垽垼垸垶垿埇埐垹埁夎奊娙娖娭娮娕娏娗娊娞娳孬宧宭宬尃屖屔峬峿峮峱峷崀峹帩帨庨庮庪庬弳弰彧恝恚恧"],["d1a1","恁悢悈悀悒悁悝悃悕悛悗悇悜悎戙扆拲挐捖挬捄捅挶捃揤挹捋捊挼挩捁挴捘捔捙挭捇挳捚捑挸捗捀捈敊敆旆旃旄旂晊晟晇晑朒朓栟栚桉栲栳栻桋桏栖栱栜栵栫栭栯桎桄栴栝栒栔栦栨栮桍栺栥栠欬欯欭欱欴歭肂殈毦毤"],["d240","毨毣毢毧氥浺浣浤浶洍浡涒浘浢浭浯涑涍淯浿涆浞浧浠涗浰浼浟涂涘洯浨涋浾涀涄洖涃浻浽浵涐烜烓烑烝烋缹烢烗烒烞烠烔烍烅烆烇烚烎烡牂牸"],["d2a1","牷牶猀狺狴狾狶狳狻猁珓珙珥珖玼珧珣珩珜珒珛珔珝珚珗珘珨瓞瓟瓴瓵甡畛畟疰痁疻痄痀疿疶疺皊盉眝眛眐眓眒眣眑眕眙眚眢眧砣砬砢砵砯砨砮砫砡砩砳砪砱祔祛祏祜祓祒祑秫秬秠秮秭秪秜秞秝窆窉窅窋窌窊窇竘笐"],["d340","笄笓笅笏笈笊笎笉笒粄粑粊粌粈粍粅紞紝紑紎紘紖紓紟紒紏紌罜罡罞罠罝罛羖羒翃翂翀耖耾耹胺胲胹胵脁胻脀舁舯舥茳茭荄茙荑茥荖茿荁茦茜茢"],["d3a1","荂荎茛茪茈茼荍茖茤茠茷茯茩荇荅荌荓茞茬荋茧荈虓虒蚢蚨蚖蚍蚑蚞蚇蚗蚆蚋蚚蚅蚥蚙蚡蚧蚕蚘蚎蚝蚐蚔衃衄衭衵衶衲袀衱衿衯袃衾衴衼訒豇豗豻貤貣赶赸趵趷趶軑軓迾迵适迿迻逄迼迶郖郠郙郚郣郟郥郘郛郗郜郤酐"],["d440","酎酏釕釢釚陜陟隼飣髟鬯乿偰偪偡偞偠偓偋偝偲偈偍偁偛偊偢倕偅偟偩偫偣偤偆偀偮偳偗偑凐剫剭剬剮勖勓匭厜啵啶唼啍啐唴唪啑啢唶唵唰啒啅"],["d4a1","唌唲啥啎唹啈唭唻啀啋圊圇埻堔埢埶埜埴堀埭埽堈埸堋埳埏堇埮埣埲埥埬埡堎埼堐埧堁堌埱埩埰堍堄奜婠婘婕婧婞娸娵婭婐婟婥婬婓婤婗婃婝婒婄婛婈媎娾婍娹婌婰婩婇婑婖婂婜孲孮寁寀屙崞崋崝崚崠崌崨崍崦崥崏"],["d540","崰崒崣崟崮帾帴庱庴庹庲庳弶弸徛徖徟悊悐悆悾悰悺惓惔惏惤惙惝惈悱惛悷惊悿惃惍惀挲捥掊掂捽掽掞掭掝掗掫掎捯掇掐据掯捵掜捭掮捼掤挻掟"],["d5a1","捸掅掁掑掍捰敓旍晥晡晛晙晜晢朘桹梇梐梜桭桮梮梫楖桯梣梬梩桵桴梲梏桷梒桼桫桲梪梀桱桾梛梖梋梠梉梤桸桻梑梌梊桽欶欳欷欸殑殏殍殎殌氪淀涫涴涳湴涬淩淢涷淶淔渀淈淠淟淖涾淥淜淝淛淴淊涽淭淰涺淕淂淏淉"],["d640","淐淲淓淽淗淍淣涻烺焍烷焗烴焌烰焄烳焐烼烿焆焓焀烸烶焋焂焎牾牻牼牿猝猗猇猑猘猊猈狿猏猞玈珶珸珵琄琁珽琇琀珺珼珿琌琋珴琈畤畣痎痒痏"],["d6a1","痋痌痑痐皏皉盓眹眯眭眱眲眴眳眽眥眻眵硈硒硉硍硊硌砦硅硐祤祧祩祪祣祫祡离秺秸秶秷窏窔窐笵筇笴笥笰笢笤笳笘笪笝笱笫笭笯笲笸笚笣粔粘粖粣紵紽紸紶紺絅紬紩絁絇紾紿絊紻紨罣羕羜羝羛翊翋翍翐翑翇翏翉耟"],["d740","耞耛聇聃聈脘脥脙脛脭脟脬脞脡脕脧脝脢舑舸舳舺舴舲艴莐莣莨莍荺荳莤荴莏莁莕莙荵莔莩荽莃莌莝莛莪莋荾莥莯莈莗莰荿莦莇莮荶莚虙虖蚿蚷"],["d7a1","蛂蛁蛅蚺蚰蛈蚹蚳蚸蛌蚴蚻蚼蛃蚽蚾衒袉袕袨袢袪袚袑袡袟袘袧袙袛袗袤袬袌袓袎覂觖觙觕訰訧訬訞谹谻豜豝豽貥赽赻赹趼跂趹趿跁軘軞軝軜軗軠軡逤逋逑逜逌逡郯郪郰郴郲郳郔郫郬郩酖酘酚酓酕釬釴釱釳釸釤釹釪"],["d840","釫釷釨釮镺閆閈陼陭陫陱陯隿靪頄飥馗傛傕傔傞傋傣傃傌傎傝偨傜傒傂傇兟凔匒匑厤厧喑喨喥喭啷噅喢喓喈喏喵喁喣喒喤啽喌喦啿喕喡喎圌堩堷"],["d8a1","堙堞堧堣堨埵塈堥堜堛堳堿堶堮堹堸堭堬堻奡媯媔媟婺媢媞婸媦婼媥媬媕媮娷媄媊媗媃媋媩婻婽媌媜媏媓媝寪寍寋寔寑寊寎尌尰崷嵃嵫嵁嵋崿崵嵑嵎嵕崳崺嵒崽崱嵙嵂崹嵉崸崼崲崶嵀嵅幄幁彘徦徥徫惉悹惌惢惎惄愔"],["d940","惲愊愖愅惵愓惸惼惾惁愃愘愝愐惿愄愋扊掔掱掰揎揥揨揯揃撝揳揊揠揶揕揲揵摡揟掾揝揜揄揘揓揂揇揌揋揈揰揗揙攲敧敪敤敜敨敥斌斝斞斮旐旒"],["d9a1","晼晬晻暀晱晹晪晲朁椌棓椄棜椪棬棪棱椏棖棷棫棤棶椓椐棳棡椇棌椈楰梴椑棯棆椔棸棐棽棼棨椋椊椗棎棈棝棞棦棴棑椆棔棩椕椥棇欹欻欿欼殔殗殙殕殽毰毲毳氰淼湆湇渟湉溈渼渽湅湢渫渿湁湝湳渜渳湋湀湑渻渃渮湞"],["da40","湨湜湡渱渨湠湱湫渹渢渰湓湥渧湸湤湷湕湹湒湦渵渶湚焠焞焯烻焮焱焣焥焢焲焟焨焺焛牋牚犈犉犆犅犋猒猋猰猢猱猳猧猲猭猦猣猵猌琮琬琰琫琖"],["daa1","琚琡琭琱琤琣琝琩琠琲瓻甯畯畬痧痚痡痦痝痟痤痗皕皒盚睆睇睄睍睅睊睎睋睌矞矬硠硤硥硜硭硱硪确硰硩硨硞硢祴祳祲祰稂稊稃稌稄窙竦竤筊笻筄筈筌筎筀筘筅粢粞粨粡絘絯絣絓絖絧絪絏絭絜絫絒絔絩絑絟絎缾缿罥"],["db40","罦羢羠羡翗聑聏聐胾胔腃腊腒腏腇脽腍脺臦臮臷臸臹舄舼舽舿艵茻菏菹萣菀菨萒菧菤菼菶萐菆菈菫菣莿萁菝菥菘菿菡菋菎菖菵菉萉萏菞萑萆菂菳"],["dba1","菕菺菇菑菪萓菃菬菮菄菻菗菢萛菛菾蛘蛢蛦蛓蛣蛚蛪蛝蛫蛜蛬蛩蛗蛨蛑衈衖衕袺裗袹袸裀袾袶袼袷袽袲褁裉覕覘覗觝觚觛詎詍訹詙詀詗詘詄詅詒詈詑詊詌詏豟貁貀貺貾貰貹貵趄趀趉跘跓跍跇跖跜跏跕跙跈跗跅軯軷軺"],["dc40","軹軦軮軥軵軧軨軶軫軱軬軴軩逭逴逯鄆鄬鄄郿郼鄈郹郻鄁鄀鄇鄅鄃酡酤酟酢酠鈁鈊鈥鈃鈚鈦鈏鈌鈀鈒釿釽鈆鈄鈧鈂鈜鈤鈙鈗鈅鈖镻閍閌閐隇陾隈"],["dca1","隉隃隀雂雈雃雱雰靬靰靮頇颩飫鳦黹亃亄亶傽傿僆傮僄僊傴僈僂傰僁傺傱僋僉傶傸凗剺剸剻剼嗃嗛嗌嗐嗋嗊嗝嗀嗔嗄嗩喿嗒喍嗏嗕嗢嗖嗈嗲嗍嗙嗂圔塓塨塤塏塍塉塯塕塎塝塙塥塛堽塣塱壼嫇嫄嫋媺媸媱媵媰媿嫈媻嫆"],["dd40","媷嫀嫊媴媶嫍媹媐寖寘寙尟尳嵱嵣嵊嵥嵲嵬嵞嵨嵧嵢巰幏幎幊幍幋廅廌廆廋廇彀徯徭惷慉慊愫慅愶愲愮慆愯慏愩慀戠酨戣戥戤揅揱揫搐搒搉搠搤"],["dda1","搳摃搟搕搘搹搷搢搣搌搦搰搨摁搵搯搊搚摀搥搧搋揧搛搮搡搎敯斒旓暆暌暕暐暋暊暙暔晸朠楦楟椸楎楢楱椿楅楪椹楂楗楙楺楈楉椵楬椳椽楥棰楸椴楩楀楯楄楶楘楁楴楌椻楋椷楜楏楑椲楒椯楻椼歆歅歃歂歈歁殛嗀毻毼"],["de40","毹毷毸溛滖滈溏滀溟溓溔溠溱溹滆滒溽滁溞滉溷溰滍溦滏溲溾滃滜滘溙溒溎溍溤溡溿溳滐滊溗溮溣煇煔煒煣煠煁煝煢煲煸煪煡煂煘煃煋煰煟煐煓"],["dea1","煄煍煚牏犍犌犑犐犎猼獂猻猺獀獊獉瑄瑊瑋瑒瑑瑗瑀瑏瑐瑎瑂瑆瑍瑔瓡瓿瓾瓽甝畹畷榃痯瘏瘃痷痾痼痹痸瘐痻痶痭痵痽皙皵盝睕睟睠睒睖睚睩睧睔睙睭矠碇碚碔碏碄碕碅碆碡碃硹碙碀碖硻祼禂祽祹稑稘稙稒稗稕稢稓"],["df40","稛稐窣窢窞竫筦筤筭筴筩筲筥筳筱筰筡筸筶筣粲粴粯綈綆綀綍絿綅絺綎絻綃絼綌綔綄絽綒罭罫罧罨罬羦羥羧翛翜耡腤腠腷腜腩腛腢腲朡腞腶腧腯"],["dfa1","腄腡舝艉艄艀艂艅蓱萿葖葶葹蒏蒍葥葑葀蒆葧萰葍葽葚葙葴葳葝蔇葞萷萺萴葺葃葸萲葅萩菙葋萯葂萭葟葰萹葎葌葒葯蓅蒎萻葇萶萳葨葾葄萫葠葔葮葐蜋蜄蛷蜌蛺蛖蛵蝍蛸蜎蜉蜁蛶蜍蜅裖裋裍裎裞裛裚裌裐覅覛觟觥觤"],["e040","觡觠觢觜触詶誆詿詡訿詷誂誄詵誃誁詴詺谼豋豊豥豤豦貆貄貅賌赨赩趑趌趎趏趍趓趔趐趒跰跠跬跱跮跐跩跣跢跧跲跫跴輆軿輁輀輅輇輈輂輋遒逿"],["e0a1","遄遉逽鄐鄍鄏鄑鄖鄔鄋鄎酮酯鉈鉒鈰鈺鉦鈳鉥鉞銃鈮鉊鉆鉭鉬鉏鉠鉧鉯鈶鉡鉰鈱鉔鉣鉐鉲鉎鉓鉌鉖鈲閟閜閞閛隒隓隑隗雎雺雽雸雵靳靷靸靲頏頍頎颬飶飹馯馲馰馵骭骫魛鳪鳭鳧麀黽僦僔僗僨僳僛僪僝僤僓僬僰僯僣僠"],["e140","凘劀劁勩勫匰厬嘧嘕嘌嘒嗼嘏嘜嘁嘓嘂嗺嘝嘄嗿嗹墉塼墐墘墆墁塿塴墋塺墇墑墎塶墂墈塻墔墏壾奫嫜嫮嫥嫕嫪嫚嫭嫫嫳嫢嫠嫛嫬嫞嫝嫙嫨嫟孷寠"],["e1a1","寣屣嶂嶀嵽嶆嵺嶁嵷嶊嶉嶈嵾嵼嶍嵹嵿幘幙幓廘廑廗廎廜廕廙廒廔彄彃彯徶愬愨慁慞慱慳慒慓慲慬憀慴慔慺慛慥愻慪慡慖戩戧戫搫摍摛摝摴摶摲摳摽摵摦撦摎撂摞摜摋摓摠摐摿搿摬摫摙摥摷敳斠暡暠暟朅朄朢榱榶槉"],["e240","榠槎榖榰榬榼榑榙榎榧榍榩榾榯榿槄榽榤槔榹槊榚槏榳榓榪榡榞槙榗榐槂榵榥槆歊歍歋殞殟殠毃毄毾滎滵滱漃漥滸漷滻漮漉潎漙漚漧漘漻漒滭漊"],["e2a1","漶潳滹滮漭潀漰漼漵滫漇漎潃漅滽滶漹漜滼漺漟漍漞漈漡熇熐熉熀熅熂熏煻熆熁熗牄牓犗犕犓獃獍獑獌瑢瑳瑱瑵瑲瑧瑮甀甂甃畽疐瘖瘈瘌瘕瘑瘊瘔皸瞁睼瞅瞂睮瞀睯睾瞃碲碪碴碭碨硾碫碞碥碠碬碢碤禘禊禋禖禕禔禓"],["e340","禗禈禒禐稫穊稰稯稨稦窨窫窬竮箈箜箊箑箐箖箍箌箛箎箅箘劄箙箤箂粻粿粼粺綧綷緂綣綪緁緀緅綝緎緄緆緋緌綯綹綖綼綟綦綮綩綡緉罳翢翣翥翞"],["e3a1","耤聝聜膉膆膃膇膍膌膋舕蒗蒤蒡蒟蒺蓎蓂蒬蒮蒫蒹蒴蓁蓍蒪蒚蒱蓐蒝蒧蒻蒢蒔蓇蓌蒛蒩蒯蒨蓖蒘蒶蓏蒠蓗蓔蓒蓛蒰蒑虡蜳蜣蜨蝫蝀蜮蜞蜡蜙蜛蝃蜬蝁蜾蝆蜠蜲蜪蜭蜼蜒蜺蜱蜵蝂蜦蜧蜸蜤蜚蜰蜑裷裧裱裲裺裾裮裼裶裻"],["e440","裰裬裫覝覡覟覞觩觫觨誫誙誋誒誏誖谽豨豩賕賏賗趖踉踂跿踍跽踊踃踇踆踅跾踀踄輐輑輎輍鄣鄜鄠鄢鄟鄝鄚鄤鄡鄛酺酲酹酳銥銤鉶銛鉺銠銔銪銍"],["e4a1","銦銚銫鉹銗鉿銣鋮銎銂銕銢鉽銈銡銊銆銌銙銧鉾銇銩銝銋鈭隞隡雿靘靽靺靾鞃鞀鞂靻鞄鞁靿韎韍頖颭颮餂餀餇馝馜駃馹馻馺駂馽駇骱髣髧鬾鬿魠魡魟鳱鳲鳵麧僿儃儰僸儆儇僶僾儋儌僽儊劋劌勱勯噈噂噌嘵噁噊噉噆噘"],["e540","噚噀嘳嘽嘬嘾嘸嘪嘺圚墫墝墱墠墣墯墬墥墡壿嫿嫴嫽嫷嫶嬃嫸嬂嫹嬁嬇嬅嬏屧嶙嶗嶟嶒嶢嶓嶕嶠嶜嶡嶚嶞幩幝幠幜緳廛廞廡彉徲憋憃慹憱憰憢憉"],["e5a1","憛憓憯憭憟憒憪憡憍慦憳戭摮摰撖撠撅撗撜撏撋撊撌撣撟摨撱撘敶敺敹敻斲斳暵暰暩暲暷暪暯樀樆樗槥槸樕槱槤樠槿槬槢樛樝槾樧槲槮樔槷槧橀樈槦槻樍槼槫樉樄樘樥樏槶樦樇槴樖歑殥殣殢殦氁氀毿氂潁漦潾澇濆澒"],["e640","澍澉澌潢潏澅潚澖潶潬澂潕潲潒潐潗澔澓潝漀潡潫潽潧澐潓澋潩潿澕潣潷潪潻熲熯熛熰熠熚熩熵熝熥熞熤熡熪熜熧熳犘犚獘獒獞獟獠獝獛獡獚獙"],["e6a1","獢璇璉璊璆璁瑽璅璈瑼瑹甈甇畾瘥瘞瘙瘝瘜瘣瘚瘨瘛皜皝皞皛瞍瞏瞉瞈磍碻磏磌磑磎磔磈磃磄磉禚禡禠禜禢禛歶稹窲窴窳箷篋箾箬篎箯箹篊箵糅糈糌糋緷緛緪緧緗緡縃緺緦緶緱緰緮緟罶羬羰羭翭翫翪翬翦翨聤聧膣膟"],["e740","膞膕膢膙膗舖艏艓艒艐艎艑蔤蔻蔏蔀蔩蔎蔉蔍蔟蔊蔧蔜蓻蔫蓺蔈蔌蓴蔪蓲蔕蓷蓫蓳蓼蔒蓪蓩蔖蓾蔨蔝蔮蔂蓽蔞蓶蔱蔦蓧蓨蓰蓯蓹蔘蔠蔰蔋蔙蔯虢"],["e7a1","蝖蝣蝤蝷蟡蝳蝘蝔蝛蝒蝡蝚蝑蝞蝭蝪蝐蝎蝟蝝蝯蝬蝺蝮蝜蝥蝏蝻蝵蝢蝧蝩衚褅褌褔褋褗褘褙褆褖褑褎褉覢覤覣觭觰觬諏諆誸諓諑諔諕誻諗誾諀諅諘諃誺誽諙谾豍貏賥賟賙賨賚賝賧趠趜趡趛踠踣踥踤踮踕踛踖踑踙踦踧"],["e840","踔踒踘踓踜踗踚輬輤輘輚輠輣輖輗遳遰遯遧遫鄯鄫鄩鄪鄲鄦鄮醅醆醊醁醂醄醀鋐鋃鋄鋀鋙銶鋏鋱鋟鋘鋩鋗鋝鋌鋯鋂鋨鋊鋈鋎鋦鋍鋕鋉鋠鋞鋧鋑鋓"],["e8a1","銵鋡鋆銴镼閬閫閮閰隤隢雓霅霈霂靚鞊鞎鞈韐韏頞頝頦頩頨頠頛頧颲餈飺餑餔餖餗餕駜駍駏駓駔駎駉駖駘駋駗駌骳髬髫髳髲髱魆魃魧魴魱魦魶魵魰魨魤魬鳼鳺鳽鳿鳷鴇鴀鳹鳻鴈鴅鴄麃黓鼏鼐儜儓儗儚儑凞匴叡噰噠噮"],["e940","噳噦噣噭噲噞噷圜圛壈墽壉墿墺壂墼壆嬗嬙嬛嬡嬔嬓嬐嬖嬨嬚嬠嬞寯嶬嶱嶩嶧嶵嶰嶮嶪嶨嶲嶭嶯嶴幧幨幦幯廩廧廦廨廥彋徼憝憨憖懅憴懆懁懌憺"],["e9a1","憿憸憌擗擖擐擏擉撽撉擃擛擳擙攳敿敼斢曈暾曀曊曋曏暽暻暺曌朣樴橦橉橧樲橨樾橝橭橶橛橑樨橚樻樿橁橪橤橐橏橔橯橩橠樼橞橖橕橍橎橆歕歔歖殧殪殫毈毇氄氃氆澭濋澣濇澼濎濈潞濄澽澞濊澨瀄澥澮澺澬澪濏澿澸"],["ea40","澢濉澫濍澯澲澰燅燂熿熸燖燀燁燋燔燊燇燏熽燘熼燆燚燛犝犞獩獦獧獬獥獫獪瑿璚璠璔璒璕璡甋疀瘯瘭瘱瘽瘳瘼瘵瘲瘰皻盦瞚瞝瞡瞜瞛瞢瞣瞕瞙"],["eaa1","瞗磝磩磥磪磞磣磛磡磢磭磟磠禤穄穈穇窶窸窵窱窷篞篣篧篝篕篥篚篨篹篔篪篢篜篫篘篟糒糔糗糐糑縒縡縗縌縟縠縓縎縜縕縚縢縋縏縖縍縔縥縤罃罻罼罺羱翯耪耩聬膱膦膮膹膵膫膰膬膴膲膷膧臲艕艖艗蕖蕅蕫蕍蕓蕡蕘"],["eb40","蕀蕆蕤蕁蕢蕄蕑蕇蕣蔾蕛蕱蕎蕮蕵蕕蕧蕠薌蕦蕝蕔蕥蕬虣虥虤螛螏螗螓螒螈螁螖螘蝹螇螣螅螐螑螝螄螔螜螚螉褞褦褰褭褮褧褱褢褩褣褯褬褟觱諠"],["eba1","諢諲諴諵諝謔諤諟諰諈諞諡諨諿諯諻貑貒貐賵賮賱賰賳赬赮趥趧踳踾踸蹀蹅踶踼踽蹁踰踿躽輶輮輵輲輹輷輴遶遹遻邆郺鄳鄵鄶醓醐醑醍醏錧錞錈錟錆錏鍺錸錼錛錣錒錁鍆錭錎錍鋋錝鋺錥錓鋹鋷錴錂錤鋿錩錹錵錪錔錌"],["ec40","錋鋾錉錀鋻錖閼闍閾閹閺閶閿閵閽隩雔霋霒霐鞙鞗鞔韰韸頵頯頲餤餟餧餩馞駮駬駥駤駰駣駪駩駧骹骿骴骻髶髺髹髷鬳鮀鮅鮇魼魾魻鮂鮓鮒鮐魺鮕"],["eca1","魽鮈鴥鴗鴠鴞鴔鴩鴝鴘鴢鴐鴙鴟麈麆麇麮麭黕黖黺鼒鼽儦儥儢儤儠儩勴嚓嚌嚍嚆嚄嚃噾嚂噿嚁壖壔壏壒嬭嬥嬲嬣嬬嬧嬦嬯嬮孻寱寲嶷幬幪徾徻懃憵憼懧懠懥懤懨懞擯擩擣擫擤擨斁斀斶旚曒檍檖檁檥檉檟檛檡檞檇檓檎"],["ed40","檕檃檨檤檑橿檦檚檅檌檒歛殭氉濌澩濴濔濣濜濭濧濦濞濲濝濢濨燡燱燨燲燤燰燢獳獮獯璗璲璫璐璪璭璱璥璯甐甑甒甏疄癃癈癉癇皤盩瞵瞫瞲瞷瞶"],["eda1","瞴瞱瞨矰磳磽礂磻磼磲礅磹磾礄禫禨穜穛穖穘穔穚窾竀竁簅簏篲簀篿篻簎篴簋篳簂簉簃簁篸篽簆篰篱簐簊糨縭縼繂縳顈縸縪繉繀繇縩繌縰縻縶繄縺罅罿罾罽翴翲耬膻臄臌臊臅臇膼臩艛艚艜薃薀薏薧薕薠薋薣蕻薤薚薞"],["ee40","蕷蕼薉薡蕺蕸蕗薎薖薆薍薙薝薁薢薂薈薅蕹蕶薘薐薟虨螾螪螭蟅螰螬螹螵螼螮蟉蟃蟂蟌螷螯蟄蟊螴螶螿螸螽蟞螲褵褳褼褾襁襒褷襂覭覯覮觲觳謞"],["eea1","謘謖謑謅謋謢謏謒謕謇謍謈謆謜謓謚豏豰豲豱豯貕貔賹赯蹎蹍蹓蹐蹌蹇轃轀邅遾鄸醚醢醛醙醟醡醝醠鎡鎃鎯鍤鍖鍇鍼鍘鍜鍶鍉鍐鍑鍠鍭鎏鍌鍪鍹鍗鍕鍒鍏鍱鍷鍻鍡鍞鍣鍧鎀鍎鍙闇闀闉闃闅閷隮隰隬霠霟霘霝霙鞚鞡鞜"],["ef40","鞞鞝韕韔韱顁顄顊顉顅顃餥餫餬餪餳餲餯餭餱餰馘馣馡騂駺駴駷駹駸駶駻駽駾駼騃骾髾髽鬁髼魈鮚鮨鮞鮛鮦鮡鮥鮤鮆鮢鮠鮯鴳鵁鵧鴶鴮鴯鴱鴸鴰"],["efa1","鵅鵂鵃鴾鴷鵀鴽翵鴭麊麉麍麰黈黚黻黿鼤鼣鼢齔龠儱儭儮嚘嚜嚗嚚嚝嚙奰嬼屩屪巀幭幮懘懟懭懮懱懪懰懫懖懩擿攄擽擸攁攃擼斔旛曚曛曘櫅檹檽櫡櫆檺檶檷櫇檴檭歞毉氋瀇瀌瀍瀁瀅瀔瀎濿瀀濻瀦濼濷瀊爁燿燹爃燽獶"],["f040","璸瓀璵瓁璾璶璻瓂甔甓癜癤癙癐癓癗癚皦皽盬矂瞺磿礌礓礔礉礐礒礑禭禬穟簜簩簙簠簟簭簝簦簨簢簥簰繜繐繖繣繘繢繟繑繠繗繓羵羳翷翸聵臑臒"],["f0a1","臐艟艞薴藆藀藃藂薳薵薽藇藄薿藋藎藈藅薱薶藒蘤薸薷薾虩蟧蟦蟢蟛蟫蟪蟥蟟蟳蟤蟔蟜蟓蟭蟘蟣螤蟗蟙蠁蟴蟨蟝襓襋襏襌襆襐襑襉謪謧謣謳謰謵譇謯謼謾謱謥謷謦謶謮謤謻謽謺豂豵貙貘貗賾贄贂贀蹜蹢蹠蹗蹖蹞蹥蹧"],["f140","蹛蹚蹡蹝蹩蹔轆轇轈轋鄨鄺鄻鄾醨醥醧醯醪鎵鎌鎒鎷鎛鎝鎉鎧鎎鎪鎞鎦鎕鎈鎙鎟鎍鎱鎑鎲鎤鎨鎴鎣鎥闒闓闑隳雗雚巂雟雘雝霣霢霥鞬鞮鞨鞫鞤鞪"],["f1a1","鞢鞥韗韙韖韘韺顐顑顒颸饁餼餺騏騋騉騍騄騑騊騅騇騆髀髜鬈鬄鬅鬩鬵魊魌魋鯇鯆鯃鮿鯁鮵鮸鯓鮶鯄鮹鮽鵜鵓鵏鵊鵛鵋鵙鵖鵌鵗鵒鵔鵟鵘鵚麎麌黟鼁鼀鼖鼥鼫鼪鼩鼨齌齕儴儵劖勷厴嚫嚭嚦嚧嚪嚬壚壝壛夒嬽嬾嬿巃幰"],["f240","徿懻攇攐攍攉攌攎斄旞旝曞櫧櫠櫌櫑櫙櫋櫟櫜櫐櫫櫏櫍櫞歠殰氌瀙瀧瀠瀖瀫瀡瀢瀣瀩瀗瀤瀜瀪爌爊爇爂爅犥犦犤犣犡瓋瓅璷瓃甖癠矉矊矄矱礝礛"],["f2a1","礡礜礗礞禰穧穨簳簼簹簬簻糬糪繶繵繸繰繷繯繺繲繴繨罋罊羃羆羷翽翾聸臗臕艤艡艣藫藱藭藙藡藨藚藗藬藲藸藘藟藣藜藑藰藦藯藞藢蠀蟺蠃蟶蟷蠉蠌蠋蠆蟼蠈蟿蠊蠂襢襚襛襗襡襜襘襝襙覈覷覶觶譐譈譊譀譓譖譔譋譕"],["f340","譑譂譒譗豃豷豶貚贆贇贉趬趪趭趫蹭蹸蹳蹪蹯蹻軂轒轑轏轐轓辴酀鄿醰醭鏞鏇鏏鏂鏚鏐鏹鏬鏌鏙鎩鏦鏊鏔鏮鏣鏕鏄鏎鏀鏒鏧镽闚闛雡霩霫霬霨霦"],["f3a1","鞳鞷鞶韝韞韟顜顙顝顗颿颽颻颾饈饇饃馦馧騚騕騥騝騤騛騢騠騧騣騞騜騔髂鬋鬊鬎鬌鬷鯪鯫鯠鯞鯤鯦鯢鯰鯔鯗鯬鯜鯙鯥鯕鯡鯚鵷鶁鶊鶄鶈鵱鶀鵸鶆鶋鶌鵽鵫鵴鵵鵰鵩鶅鵳鵻鶂鵯鵹鵿鶇鵨麔麑黀黼鼭齀齁齍齖齗齘匷嚲"],["f440","嚵嚳壣孅巆巇廮廯忀忁懹攗攖攕攓旟曨曣曤櫳櫰櫪櫨櫹櫱櫮櫯瀼瀵瀯瀷瀴瀱灂瀸瀿瀺瀹灀瀻瀳灁爓爔犨獽獼璺皫皪皾盭矌矎矏矍矲礥礣礧礨礤礩"],["f4a1","禲穮穬穭竷籉籈籊籇籅糮繻繾纁纀羺翿聹臛臙舋艨艩蘢藿蘁藾蘛蘀藶蘄蘉蘅蘌藽蠙蠐蠑蠗蠓蠖襣襦覹觷譠譪譝譨譣譥譧譭趮躆躈躄轙轖轗轕轘轚邍酃酁醷醵醲醳鐋鐓鏻鐠鐏鐔鏾鐕鐐鐨鐙鐍鏵鐀鏷鐇鐎鐖鐒鏺鐉鏸鐊鏿"],["f540","鏼鐌鏶鐑鐆闞闠闟霮霯鞹鞻韽韾顠顢顣顟飁飂饐饎饙饌饋饓騲騴騱騬騪騶騩騮騸騭髇髊髆鬐鬒鬑鰋鰈鯷鰅鰒鯸鱀鰇鰎鰆鰗鰔鰉鶟鶙鶤鶝鶒鶘鶐鶛"],["f5a1","鶠鶔鶜鶪鶗鶡鶚鶢鶨鶞鶣鶿鶩鶖鶦鶧麙麛麚黥黤黧黦鼰鼮齛齠齞齝齙龑儺儹劘劗囃嚽嚾孈孇巋巏廱懽攛欂櫼欃櫸欀灃灄灊灈灉灅灆爝爚爙獾甗癪矐礭礱礯籔籓糲纊纇纈纋纆纍罍羻耰臝蘘蘪蘦蘟蘣蘜蘙蘧蘮蘡蘠蘩蘞蘥"],["f640","蠩蠝蠛蠠蠤蠜蠫衊襭襩襮襫觺譹譸譅譺譻贐贔趯躎躌轞轛轝酆酄酅醹鐿鐻鐶鐩鐽鐼鐰鐹鐪鐷鐬鑀鐱闥闤闣霵霺鞿韡顤飉飆飀饘饖騹騽驆驄驂驁騺"],["f6a1","騿髍鬕鬗鬘鬖鬺魒鰫鰝鰜鰬鰣鰨鰩鰤鰡鶷鶶鶼鷁鷇鷊鷏鶾鷅鷃鶻鶵鷎鶹鶺鶬鷈鶱鶭鷌鶳鷍鶲鹺麜黫黮黭鼛鼘鼚鼱齎齥齤龒亹囆囅囋奱孋孌巕巑廲攡攠攦攢欋欈欉氍灕灖灗灒爞爟犩獿瓘瓕瓙瓗癭皭礵禴穰穱籗籜籙籛籚"],["f740","糴糱纑罏羇臞艫蘴蘵蘳蘬蘲蘶蠬蠨蠦蠪蠥襱覿覾觻譾讄讂讆讅譿贕躕躔躚躒躐躖躗轠轢酇鑌鑐鑊鑋鑏鑇鑅鑈鑉鑆霿韣顪顩飋饔饛驎驓驔驌驏驈驊"],["f7a1","驉驒驐髐鬙鬫鬻魖魕鱆鱈鰿鱄鰹鰳鱁鰼鰷鰴鰲鰽鰶鷛鷒鷞鷚鷋鷐鷜鷑鷟鷩鷙鷘鷖鷵鷕鷝麶黰鼵鼳鼲齂齫龕龢儽劙壨壧奲孍巘蠯彏戁戃戄攩攥斖曫欑欒欏毊灛灚爢玂玁玃癰矔籧籦纕艬蘺虀蘹蘼蘱蘻蘾蠰蠲蠮蠳襶襴襳觾"],["f840","讌讎讋讈豅贙躘轤轣醼鑢鑕鑝鑗鑞韄韅頀驖驙鬞鬟鬠鱒鱘鱐鱊鱍鱋鱕鱙鱌鱎鷻鷷鷯鷣鷫鷸鷤鷶鷡鷮鷦鷲鷰鷢鷬鷴鷳鷨鷭黂黐黲黳鼆鼜鼸鼷鼶齃齏"],["f8a1","齱齰齮齯囓囍孎屭攭曭曮欓灟灡灝灠爣瓛瓥矕礸禷禶籪纗羉艭虃蠸蠷蠵衋讔讕躞躟躠躝醾醽釂鑫鑨鑩雥靆靃靇韇韥驞髕魙鱣鱧鱦鱢鱞鱠鸂鷾鸇鸃鸆鸅鸀鸁鸉鷿鷽鸄麠鼞齆齴齵齶囔攮斸欘欙欗欚灢爦犪矘矙礹籩籫糶纚"],["f940","纘纛纙臠臡虆虇虈襹襺襼襻觿讘讙躥躤躣鑮鑭鑯鑱鑳靉顲饟鱨鱮鱭鸋鸍鸐鸏鸒鸑麡黵鼉齇齸齻齺齹圞灦籯蠼趲躦釃鑴鑸鑶鑵驠鱴鱳鱱鱵鸔鸓黶鼊"],["f9a1","龤灨灥糷虪蠾蠽蠿讞貜躩軉靋顳顴飌饡馫驤驦驧鬤鸕鸗齈戇欞爧虌躨钂钀钁驩驨鬮鸙爩虋讟钃鱹麷癵驫鱺鸝灩灪麤齾齉龘碁銹裏墻恒粧嫺╔╦╗╠╬╣╚╩╝╒╤╕╞╪╡╘╧╛╓╥╖╟╫╢╙╨╜║═╭╮╰╯▓"]]},72:function(e,t,n){"use strict";var i=n(802);var o=n(715);e.exports.convert=convert;function convert(e,t,n,i){n=checkEncoding(n||"UTF-8");t=checkEncoding(t||"UTF-8");e=e||"";var r;if(n!=="UTF-8"&&typeof e==="string"){e=new Buffer(e,"binary")}if(n===t){if(typeof e==="string"){r=new Buffer(e)}else{r=e}}else if(o&&!i){try{r=convertIconv(e,t,n)}catch(i){console.error(i);try{r=convertIconvLite(e,t,n)}catch(t){console.error(t);r=e}}}else{try{r=convertIconvLite(e,t,n)}catch(t){console.error(t);r=e}}if(typeof r==="string"){r=new Buffer(r,"utf-8")}return r}function convertIconv(e,t,n){var i,r;r=new o(n,t+"//TRANSLIT//IGNORE");i=r.convert(e);return i.slice(0,i.length)}function convertIconvLite(e,t,n){if(t==="UTF-8"){return i.decode(e,n)}else if(n==="UTF-8"){return i.encode(e,t)}else{return i.encode(i.decode(e,n),t)}}function checkEncoding(e){return(e||"").toString().trim().replace(/^latin[\-_]?(\d+)$/i,"ISO-8859-$1").replace(/^win(?:dows)?[\-_]?(\d+)$/i,"WINDOWS-$1").replace(/^utf[\-_]?(\d+)$/i,"UTF-$1").replace(/^ks_c_5601\-1987$/i,"CP949").replace(/^us[\-_]?ascii$/i,"ASCII").toUpperCase()}},145:function(e){"use strict";e.exports={437:"cp437",737:"cp737",775:"cp775",850:"cp850",852:"cp852",855:"cp855",856:"cp856",857:"cp857",858:"cp858",860:"cp860",861:"cp861",862:"cp862",863:"cp863",864:"cp864",865:"cp865",866:"cp866",869:"cp869",874:"windows874",922:"cp922",1046:"cp1046",1124:"cp1124",1125:"cp1125",1129:"cp1129",1133:"cp1133",1161:"cp1161",1162:"cp1162",1163:"cp1163",1250:"windows1250",1251:"windows1251",1252:"windows1252",1253:"windows1253",1254:"windows1254",1255:"windows1255",1256:"windows1256",1257:"windows1257",1258:"windows1258",28591:"iso88591",28592:"iso88592",28593:"iso88593",28594:"iso88594",28595:"iso88595",28596:"iso88596",28597:"iso88597",28598:"iso88598",28599:"iso88599",28600:"iso885910",28601:"iso885911",28603:"iso885913",28604:"iso885914",28605:"iso885915",28606:"iso885916",windows874:{type:"_sbcs",chars:"€����…�����������‘’“”•–—�������� กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},win874:"windows874",cp874:"windows874",windows1250:{type:"_sbcs",chars:"€�‚�„…†‡�‰Š‹ŚŤŽŹ�‘’“”•–—�™š›śťžź ˇ˘Ł¤Ą¦§¨©Ş«¬­®Ż°±˛ł´µ¶·¸ąş»Ľ˝ľżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙"},win1250:"windows1250",cp1250:"windows1250",windows1251:{type:"_sbcs",chars:"ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—�™љ›њќћџ ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·ё№є»јЅѕїАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},win1251:"windows1251",cp1251:"windows1251",windows1252:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰Š‹Œ�Ž��‘’“”•–—˜™š›œ�žŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},win1252:"windows1252",cp1252:"windows1252",windows1253:{type:"_sbcs",chars:"€�‚ƒ„…†‡�‰�‹�����‘’“”•–—�™�›���� ΅Ά£¤¥¦§¨©�«¬­®―°±²³΄µ¶·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�"},win1253:"windows1253",cp1253:"windows1253",windows1254:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰Š‹Œ����‘’“”•–—˜™š›œ��Ÿ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ"},win1254:"windows1254",cp1254:"windows1254",windows1255:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰�‹�����‘’“”•–—˜™�›���� ¡¢£₪¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾¿ְֱֲֳִֵֶַָֹֺֻּֽ־ֿ׀ׁׂ׃װױײ׳״�������אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�"},win1255:"windows1255",cp1255:"windows1255",windows1256:{type:"_sbcs",chars:"€پ‚ƒ„…†‡ˆ‰ٹ‹Œچژڈگ‘’“”•–—ک™ڑ›œ‌‍ں ،¢£¤¥¦§¨©ھ«¬­®¯°±²³´µ¶·¸¹؛»¼½¾؟ہءآأؤإئابةتثجحخدذرزسشصض×طظعغـفقكàلâمنهوçèéêëىيîïًٌٍَôُِ÷ّùْûü‎‏ے"},win1256:"windows1256",cp1256:"windows1256",windows1257:{type:"_sbcs",chars:"€�‚�„…†‡�‰�‹�¨ˇ¸�‘’“”•–—�™�›�¯˛� �¢£¤�¦§Ø©Ŗ«¬­®Æ°±²³´µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž˙"},win1257:"windows1257",cp1257:"windows1257",windows1258:{type:"_sbcs",chars:"€�‚ƒ„…†‡ˆ‰�‹Œ����‘’“”•–—˜™�›œ��Ÿ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},win1258:"windows1258",cp1258:"windows1258",iso88591:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},cp28591:"iso88591",iso88592:{type:"_sbcs",chars:" Ą˘Ł¤ĽŚ§¨ŠŞŤŹ­ŽŻ°ą˛ł´ľśˇ¸šşťź˝žżŔÁÂĂÄĹĆÇČÉĘËĚÍÎĎĐŃŇÓÔŐÖ×ŘŮÚŰÜÝŢßŕáâăäĺćçčéęëěíîďđńňóôőö÷řůúűüýţ˙"},cp28592:"iso88592",iso88593:{type:"_sbcs",chars:" Ħ˘£¤�Ĥ§¨İŞĞĴ­�Ż°ħ²³´µĥ·¸ışğĵ½�żÀÁÂ�ÄĊĈÇÈÉÊËÌÍÎÏ�ÑÒÓÔĠÖ×ĜÙÚÛÜŬŜßàáâ�äċĉçèéêëìíîï�ñòóôġö÷ĝùúûüŭŝ˙"},cp28593:"iso88593",iso88594:{type:"_sbcs",chars:" ĄĸŖ¤ĨĻ§¨ŠĒĢŦ­Ž¯°ą˛ŗ´ĩļˇ¸šēģŧŊžŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎĪĐŅŌĶÔÕÖ×ØŲÚÛÜŨŪßāáâãäåæįčéęëėíîīđņōķôõö÷øųúûüũū˙"},cp28594:"iso88594",iso88595:{type:"_sbcs",chars:" ЁЂЃЄЅІЇЈЉЊЋЌ­ЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя№ёђѓєѕіїјљњћќ§ўџ"},cp28595:"iso88595",iso88596:{type:"_sbcs",chars:" ���¤�������،­�������������؛���؟�ءآأؤإئابةتثجحخدذرزسشصضطظعغ�����ـفقكلمنهوىيًٌٍَُِّْ�������������"},cp28596:"iso88596",iso88597:{type:"_sbcs",chars:" ‘’£€₯¦§¨©ͺ«¬­�―°±²³΄΅Ά·ΈΉΊ»Ό½ΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡ�ΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώ�"},cp28597:"iso88597",iso88598:{type:"_sbcs",chars:" �¢£¤¥¦§¨©×«¬­®¯°±²³´µ¶·¸¹÷»¼½¾��������������������������������‗אבגדהוזחטיךכלםמןנסעףפץצקרשת��‎‏�"},cp28598:"iso88598",iso88599:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞßàáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ"},cp28599:"iso88599",iso885910:{type:"_sbcs",chars:" ĄĒĢĪĨĶ§ĻĐŠŦŽ­ŪŊ°ąēģīĩķ·ļđšŧž―ūŋĀÁÂÃÄÅÆĮČÉĘËĖÍÎÏÐŅŌÓÔÕÖŨØŲÚÛÜÝÞßāáâãäåæįčéęëėíîïðņōóôõöũøųúûüýþĸ"},cp28600:"iso885910",iso885911:{type:"_sbcs",chars:" กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},cp28601:"iso885911",iso885913:{type:"_sbcs",chars:" ”¢£¤„¦§Ø©Ŗ«¬­®Æ°±²³“µ¶·ø¹ŗ»¼½¾æĄĮĀĆÄÅĘĒČÉŹĖĢĶĪĻŠŃŅÓŌÕÖ×ŲŁŚŪÜŻŽßąįāćäåęēčéźėģķīļšńņóōõö÷ųłśūüżž’"},cp28603:"iso885913",iso885914:{type:"_sbcs",chars:" Ḃḃ£ĊċḊ§Ẁ©ẂḋỲ­®ŸḞḟĠġṀṁ¶ṖẁṗẃṠỳẄẅṡÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏŴÑÒÓÔÕÖṪØÙÚÛÜÝŶßàáâãäåæçèéêëìíîïŵñòóôõöṫøùúûüýŷÿ"},cp28604:"iso885914",iso885915:{type:"_sbcs",chars:" ¡¢£€¥Š§š©ª«¬­®¯°±²³Žµ¶·ž¹º»ŒœŸ¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},cp28605:"iso885915",iso885916:{type:"_sbcs",chars:" ĄąŁ€„Š§š©Ș«Ź­źŻ°±ČłŽ”¶·žčș»ŒœŸżÀÁÂĂÄĆÆÇÈÉÊËÌÍÎÏĐŃÒÓÔŐÖŚŰÙÚÛÜĘȚßàáâăäćæçèéêëìíîïđńòóôőöśűùúûüęțÿ"},cp28606:"iso885916",cp437:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm437:"cp437",csibm437:"cp437",cp737:{type:"_sbcs",chars:"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀ωάέήϊίόύϋώΆΈΉΊΌΎΏ±≥≤ΪΫ÷≈°∙·√ⁿ²■ "},ibm737:"cp737",csibm737:"cp737",cp775:{type:"_sbcs",chars:"ĆüéāäģåćłēŖŗīŹÄÅÉæÆōöĢ¢ŚśÖÜø£Ø×¤ĀĪóŻżź”¦©®¬½¼Ł«»░▒▓│┤ĄČĘĖ╣║╗╝ĮŠ┐└┴┬├─┼ŲŪ╚╔╩╦╠═╬Žąčęėįšųūž┘┌█▄▌▐▀ÓßŌŃõÕµńĶķĻļņĒŅ’­±“¾¶§÷„°∙·¹³²■ "},ibm775:"cp775",csibm775:"cp775",cp850:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm850:"cp850",csibm850:"cp850",cp852:{type:"_sbcs",chars:"ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁ×čáíóúĄąŽžĘę¬źČş«»░▒▓│┤ÁÂĚŞ╣║╗╝Żż┐└┴┬├─┼Ăă╚╔╩╦╠═╬¤đĐĎËďŇÍÎě┘┌█▄ŢŮ▀ÓßÔŃńňŠšŔÚŕŰýÝţ´­˝˛ˇ˘§÷¸°¨˙űŘř■ "},ibm852:"cp852",csibm852:"cp852",cp855:{type:"_sbcs",chars:"ђЂѓЃёЁєЄѕЅіІїЇјЈљЉњЊћЋќЌўЎџЏюЮъЪаАбБцЦдДеЕфФгГ«»░▒▓│┤хХиИ╣║╗╝йЙ┐└┴┬├─┼кК╚╔╩╦╠═╬¤лЛмМнНоОп┘┌█▄Пя▀ЯрРсСтТуУжЖвВьЬ№­ыЫзЗшШэЭщЩчЧ§■ "},ibm855:"cp855",csibm855:"cp855",cp856:{type:"_sbcs",chars:"אבגדהוזחטיךכלםמןנסעףפץצקרשת�£�×����������®¬½¼�«»░▒▓│┤���©╣║╗╝¢¥┐└┴┬├─┼��╚╔╩╦╠═╬¤���������┘┌█▄¦�▀������µ�������¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm856:"cp856",csibm856:"cp856",cp857:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîıÄÅÉæÆôöòûùİÖÜø£ØŞşáíóúñÑĞğ¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ºªÊËÈ�ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµ�×ÚÛÙìÿ¯´­±�¾¶§÷¸°¨·¹³²■ "},ibm857:"cp857",csibm857:"cp857",cp858:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈ€ÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ "},ibm858:"cp858",csibm858:"cp858",cp860:{type:"_sbcs",chars:"ÇüéâãàÁçêÊèÍÔìÃÂÉÀÈôõòÚùÌÕÜ¢£Ù₧ÓáíóúñÑªº¿Ò¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm860:"cp860",csibm860:"cp860",cp861:{type:"_sbcs",chars:"ÇüéâäàåçêëèÐðÞÄÅÉæÆôöþûÝýÖÜø£Ø₧ƒáíóúÁÍÓÚ¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm861:"cp861",csibm861:"cp861",cp862:{type:"_sbcs",chars:"אבגדהוזחטיךכלםמןנסעףפץצקרשת¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm862:"cp862",csibm862:"cp862",cp863:{type:"_sbcs",chars:"ÇüéâÂà¶çêëèïî‗À§ÉÈÊôËÏûù¤ÔÜ¢£ÙÛƒ¦´óú¨¸³¯Î⌐¬½¼¾«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm863:"cp863",csibm863:"cp863",cp864:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#$٪&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~°·∙√▒─│┼┤┬├┴┐┌└┘β∞φ±½¼≈«»ﻷﻸ��ﻻﻼ� ­ﺂ£¤ﺄ��ﺎﺏﺕﺙ،ﺝﺡﺥ٠١٢٣٤٥٦٧٨٩ﻑ؛ﺱﺵﺹ؟¢ﺀﺁﺃﺅﻊﺋﺍﺑﺓﺗﺛﺟﺣﺧﺩﺫﺭﺯﺳﺷﺻﺿﻁﻅﻋﻏ¦¬÷×ﻉـﻓﻗﻛﻟﻣﻧﻫﻭﻯﻳﺽﻌﻎﻍﻡﹽّﻥﻩﻬﻰﻲﻐﻕﻵﻶﻝﻙﻱ■�"},ibm864:"cp864",csibm864:"cp864",cp865:{type:"_sbcs",chars:"ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø₧ƒáíóúñÑªº¿⌐¬½¼¡«¤░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ibm865:"cp865",csibm865:"cp865",cp866:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■ "},ibm866:"cp866",csibm866:"cp866",cp869:{type:"_sbcs",chars:"������Ά�·¬¦‘’Έ―ΉΊΪΌ��ΎΫ©Ώ²³ά£έήίϊΐόύΑΒΓΔΕΖΗ½ΘΙ«»░▒▓│┤ΚΛΜΝ╣║╗╝ΞΟ┐└┴┬├─┼ΠΡ╚╔╩╦╠═╬ΣΤΥΦΧΨΩαβγ┘┌█▄δε▀ζηθικλμνξοπρσςτ΄­±υφχ§ψ΅°¨ωϋΰώ■ "},ibm869:"cp869",csibm869:"cp869",cp922:{type:"_sbcs",chars:" ¡¢£¤¥¦§¨©ª«¬­®‾°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏŠÑÒÓÔÕÖ×ØÙÚÛÜÝŽßàáâãäåæçèéêëìíîïšñòóôõö÷øùúûüýžÿ"},ibm922:"cp922",csibm922:"cp922",cp1046:{type:"_sbcs",chars:"ﺈ×÷ﹱ■│─┐┌└┘ﹹﹻﹽﹿﹷﺊﻰﻳﻲﻎﻏﻐﻶﻸﻺﻼ ¤ﺋﺑﺗﺛﺟﺣ،­ﺧﺳ٠١٢٣٤٥٦٧٨٩ﺷ؛ﺻﺿﻊ؟ﻋءآأؤإئابةتثجحخدذرزسشصضطﻇعغﻌﺂﺄﺎﻓـفقكلمنهوىيًٌٍَُِّْﻗﻛﻟﻵﻷﻹﻻﻣﻧﻬﻩ�"},ibm1046:"cp1046",csibm1046:"cp1046",cp1124:{type:"_sbcs",chars:" ЁЂҐЄЅІЇЈЉЊЋЌ­ЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя№ёђґєѕіїјљњћќ§ўџ"},ibm1124:"cp1124",csibm1124:"cp1124",cp1125:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёҐґЄєІіЇї·√№¤■ "},ibm1125:"cp1125",csibm1125:"cp1125",cp1129:{type:"_sbcs",chars:" ¡¢£¤¥¦§œ©ª«¬­®¯°±²³Ÿµ¶·Œ¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},ibm1129:"cp1129",csibm1129:"cp1129",cp1133:{type:"_sbcs",chars:" ກຂຄງຈສຊຍດຕຖທນບປຜຝພຟມຢຣລວຫອຮ���ຯະາຳິີຶືຸູຼັົຽ���ເແໂໃໄ່້໊໋໌ໍໆ�ໜໝ₭����������������໐໑໒໓໔໕໖໗໘໙��¢¬¦�"},ibm1133:"cp1133",csibm1133:"cp1133",cp1161:{type:"_sbcs",chars:"��������������������������������่กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู้๊๋€฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛¢¬¦ "},ibm1161:"cp1161",csibm1161:"cp1161",cp1162:{type:"_sbcs",chars:"€…‘’“”•–— กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"},ibm1162:"cp1162",csibm1162:"cp1162",cp1163:{type:"_sbcs",chars:" ¡¢£€¥¦§œ©ª«¬­®¯°±²³Ÿµ¶·Œ¹º»¼½¾¿ÀÁÂĂÄÅÆÇÈÉÊË̀ÍÎÏĐÑ̉ÓÔƠÖ×ØÙÚÛÜỮßàáâăäåæçèéêë́íîïđṇ̃óôơö÷øùúûüư₫ÿ"},ibm1163:"cp1163",csibm1163:"cp1163",maccroatian:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®Š™´¨≠ŽØ∞±≤≥∆µ∂∑∏š∫ªºΩžø¿¡¬√ƒ≈Ć«Č… ÀÃÕŒœĐ—“”‘’÷◊�©⁄¤‹›Æ»–·‚„‰ÂćÁčÈÍÎÏÌÓÔđÒÚÛÙıˆ˜¯πË˚¸Êæˇ"},maccyrillic:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ†°¢£§•¶І®©™Ђђ≠Ѓѓ∞±≤≥іµ∂ЈЄєЇїЉљЊњјЅ¬√ƒ≈∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёяабвгдежзийклмнопрстуфхцчшщъыьэю¤"},macgreek:{type:"_sbcs",chars:"Ä¹²É³ÖÜ΅àâä΄¨çéèêë£™îï•½‰ôö¦­ùûü†ΓΔΘΛΞΠß®©ΣΪ§≠°·Α±≤≥¥ΒΕΖΗΙΚΜΦΫΨΩάΝ¬ΟΡ≈Τ«»… ΥΧΆΈœ–―“”‘’÷ΉΊΌΎέήίόΏύαβψδεφγηιξκλμνοπώρστθωςχυζϊϋΐΰ�"},maciceland:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûüÝ°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤ÐðÞþý·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macroman:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macromania:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ĂŞ∞±≤≥¥µ∂∑∏π∫ªºΩăş¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›Ţţ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},macthai:{type:"_sbcs",chars:"«»…“”�•‘’� กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู\ufeff​–—฿เแโใไๅๆ็่้๊๋์ํ™๏๐๑๒๓๔๕๖๗๘๙®©����"},macturkish:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸĞğİıŞş‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙ�ˆ˜¯˘˙˚¸˝˛ˇ"},macukraine:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ†°Ґ£§•¶І®©™Ђђ≠Ѓѓ∞±≤≥іµґЈЄєЇїЉљЊњјЅ¬√ƒ≈∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёяабвгдежзийклмнопрстуфхцчшщъыьэю¤"},koi8r:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8u:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ёє╔ії╗╘╙╚╛ґ╝╞╟╠╡ЁЄ╣ІЇ╦╧╨╩╪Ґ╬©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8ru:{type:"_sbcs",chars:"─│┌┐└┘├┤┬┴┼▀▄█▌▐░▒▓⌠■∙√≈≤≥ ⌡°²·÷═║╒ёє╔ії╗╘╙╚╛ґў╞╟╠╡ЁЄ╣ІЇ╦╧╨╩╪ҐЎ©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},koi8t:{type:"_sbcs",chars:"қғ‚Ғ„…†‡�‰ҳ‹ҲҷҶ�Қ‘’“”•–—�™�›�����ӯӮё¤ӣ¦§���«¬­®�°±²Ё�Ӣ¶·�№�»���©юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ"},armscii8:{type:"_sbcs",chars:" �և։)(»«—.՝,-֊…՜՛՞ԱաԲբԳգԴդԵեԶզԷէԸըԹթԺժԻիԼլԽխԾծԿկՀհՁձՂղՃճՄմՅյՆնՇշՈոՉչՊպՋջՌռՍսՎվՏտՐրՑցՒւՓփՔքՕօՖֆ՚�"},rk1048:{type:"_sbcs",chars:"ЂЃ‚ѓ„…†‡€‰Љ‹ЊҚҺЏђ‘’“”•–—�™љ›њқһџ ҰұӘ¤Ө¦§Ё©Ғ«¬­®Ү°±Ііөµ¶·ё№ғ»әҢңүАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},tcvn:{type:"_sbcs",chars:"\0ÚỤỪỬỮ\b\t\n\v\f\rỨỰỲỶỸÝỴ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ÀẢÃÁẠẶẬÈẺẼÉẸỆÌỈĨÍỊÒỎÕÓỌỘỜỞỠỚỢÙỦŨ ĂÂÊÔƠƯĐăâêôơưđẶ̀̀̉̃́àảãáạẲằẳẵắẴẮẦẨẪẤỀặầẩẫấậèỂẻẽéẹềểễếệìỉỄẾỒĩíịòỔỏõóọồổỗốộờởỡớợùỖủũúụừửữứựỳỷỹýỵỐ"},georgianacademy:{type:"_sbcs",chars:"‚ƒ„…†‡ˆ‰Š‹Œ‘’“”•–—˜™š›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰჱჲჳჴჵჶçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},georgianps:{type:"_sbcs",chars:"‚ƒ„…†‡ˆ‰Š‹Œ‘’“”•–—˜™š›œŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿აბგდევზჱთიკლმნჲოპჟრსტჳუფქღყშჩცძწჭხჴჯჰჵæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"},pt154:{type:"_sbcs",chars:"ҖҒӮғ„…ҶҮҲүҠӢҢҚҺҸҗ‘’“”•–—ҳҷҡӣңқһҹ ЎўЈӨҘҰ§Ё©Ә«¬ӯ®Ҝ°ұІіҙө¶·ё№ә»јҪҫҝАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"},viscii:{type:"_sbcs",chars:"\0ẲẴẪ\b\t\n\v\f\rỶỸỴ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ẠẮẰẶẤẦẨẬẼẸẾỀỂỄỆỐỒỔỖỘỢỚỜỞỊỎỌỈỦŨỤỲÕắằặấầẩậẽẹếềểễệốồổỗỠƠộờởịỰỨỪỬơớƯÀÁÂÃẢĂẳẵÈÉÊẺÌÍĨỳĐứÒÓÔạỷừửÙÚỹỵÝỡưàáâãảăữẫèéêẻìíĩỉđựòóôõỏọụùúũủýợỮ"},iso646cn:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#¥%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}‾��������������������������������������������������������������������������������������������������������������������������������"},iso646jp:{type:"_sbcs",chars:"\0\b\t\n\v\f\r !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[¥]^_`abcdefghijklmnopqrstuvwxyz{|}‾��������������������������������������������������������������������������������������������������������������������������������"},hproman8:{type:"_sbcs",chars:" ÀÂÈÊËÎÏ´ˋˆ¨˜ÙÛ₤¯Ýý°ÇçÑñ¡¿¤£¥§ƒ¢âêôûáéóúàèòùäëöüÅîØÆåíøæÄìÖÜÉïßÔÁÃãÐðÍÌÓÒÕõŠšÚŸÿÞþ·µ¶¾—¼½ªº«■»±�"},macintosh:{type:"_sbcs",chars:"ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ�ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ"},ascii:{type:"_sbcs",chars:"��������������������������������������������������������������������������������������������������������������������������������"},tis620:{type:"_sbcs",chars:"���������������������������������กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะัาำิีึืฺุู����฿เแโใไๅๆ็่้๊๋์ํ๎๏๐๑๒๓๔๕๖๗๘๙๚๛����"}}},165:function(e,t){"use strict";var n="\ufeff";t.PrependBOM=PrependBOMWrapper;function PrependBOMWrapper(e,t){this.encoder=e;this.addBOM=true}PrependBOMWrapper.prototype.write=function(e){if(this.addBOM){e=n+e;this.addBOM=false}return this.encoder.write(e)};PrependBOMWrapper.prototype.end=function(){return this.encoder.end()};t.StripBOM=StripBOMWrapper;function StripBOMWrapper(e,t){this.decoder=e;this.pass=false;this.options=t||{}}StripBOMWrapper.prototype.write=function(e){var t=this.decoder.write(e);if(this.pass||!t)return t;if(t[0]===n){t=t.slice(1);if(typeof this.options.stripBOM==="function")this.options.stripBOM()}this.pass=true;return t};StripBOMWrapper.prototype.end=function(){return this.decoder.end()}},170:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:true});function _interopDefault(e){return e&&typeof e==="object"&&"default"in e?e["default"]:e}var i=_interopDefault(n(413));var o=_interopDefault(n(605));var r=_interopDefault(n(835));var s=_interopDefault(n(211));var c=_interopDefault(n(761));const a=i.Readable;const f=Symbol("buffer");const h=Symbol("type");class Blob{constructor(){this[h]="";const e=arguments[0];const t=arguments[1];const n=[];let i=0;if(e){const t=e;const o=Number(t.length);for(let e=0;e<o;e++){const o=t[e];let r;if(o instanceof Buffer){r=o}else if(ArrayBuffer.isView(o)){r=Buffer.from(o.buffer,o.byteOffset,o.byteLength)}else if(o instanceof ArrayBuffer){r=Buffer.from(o)}else if(o instanceof Blob){r=o[f]}else{r=Buffer.from(typeof o==="string"?o:String(o))}i+=r.length;n.push(r)}}this[f]=Buffer.concat(n);let o=t&&t.type!==undefined&&String(t.type).toLowerCase();if(o&&!/[^\u0020-\u007E]/.test(o)){this[h]=o}}get size(){return this[f].length}get type(){return this[h]}text(){return Promise.resolve(this[f].toString())}arrayBuffer(){const e=this[f];const t=e.buffer.slice(e.byteOffset,e.byteOffset+e.byteLength);return Promise.resolve(t)}stream(){const e=new a;e._read=function(){};e.push(this[f]);e.push(null);return e}toString(){return"[object Blob]"}slice(){const e=this.size;const t=arguments[0];const n=arguments[1];let i,o;if(t===undefined){i=0}else if(t<0){i=Math.max(e+t,0)}else{i=Math.min(t,e)}if(n===undefined){o=e}else if(n<0){o=Math.max(e+n,0)}else{o=Math.min(n,e)}const r=Math.max(o-i,0);const s=this[f];const c=s.slice(i,i+r);const a=new Blob([],{type:arguments[2]});a[f]=c;return a}}Object.defineProperties(Blob.prototype,{size:{enumerable:true},type:{enumerable:true},slice:{enumerable:true}});Object.defineProperty(Blob.prototype,Symbol.toStringTag,{value:"Blob",writable:false,enumerable:false,configurable:true});function FetchError(e,t,n){Error.call(this,e);this.message=e;this.type=t;if(n){this.code=this.errno=n.code}Error.captureStackTrace(this,this.constructor)}FetchError.prototype=Object.create(Error.prototype);FetchError.prototype.constructor=FetchError;FetchError.prototype.name="FetchError";let p;try{p=n(72).convert}catch(e){}const u=Symbol("Body internals");const l=i.PassThrough;function Body(e){var t=this;var n=arguments.length>1&&arguments[1]!==undefined?arguments[1]:{},o=n.size;let r=o===undefined?0:o;var s=n.timeout;let c=s===undefined?0:s;if(e==null){e=null}else if(isURLSearchParams(e)){e=Buffer.from(e.toString())}else if(isBlob(e))   ;else if(Buffer.isBuffer(e))   ;else if(Object.prototype.toString.call(e)==="[object ArrayBuffer]"){e=Buffer.from(e)}else if(ArrayBuffer.isView(e)){e=Buffer.from(e.buffer,e.byteOffset,e.byteLength)}else if(e instanceof i)   ;else{e=Buffer.from(String(e))}this[u]={body:e,disturbed:false,error:null};this.size=r;this.timeout=c;if(e instanceof i){e.on("error",function(e){const n=e.name==="AbortError"?e:new FetchError(`Invalid response body while trying to fetch ${t.url}: ${e.message}`,"system",e);t[u].error=n})}}Body.prototype={get body(){return this[u].body},get bodyUsed(){return this[u].disturbed},arrayBuffer(){return consumeBody.call(this).then(function(e){return e.buffer.slice(e.byteOffset,e.byteOffset+e.byteLength)})},blob(){let e=this.headers&&this.headers.get("content-type")||"";return consumeBody.call(this).then(function(t){return Object.assign(new Blob([],{type:e.toLowerCase()}),{[f]:t})})},json(){var e=this;return consumeBody.call(this).then(function(t){try{return JSON.parse(t.toString())}catch(t){return Body.Promise.reject(new FetchError(`invalid json response body at ${e.url} reason: ${t.message}`,"invalid-json"))}})},text(){return consumeBody.call(this).then(function(e){return e.toString()})},buffer(){return consumeBody.call(this)},textConverted(){var e=this;return consumeBody.call(this).then(function(t){return convertBody(t,e.headers)})}};Object.defineProperties(Body.prototype,{body:{enumerable:true},bodyUsed:{enumerable:true},arrayBuffer:{enumerable:true},blob:{enumerable:true},json:{enumerable:true},text:{enumerable:true}});Body.mixIn=function(e){for(const t of Object.getOwnPropertyNames(Body.prototype)){if(!(t in e)){const n=Object.getOwnPropertyDescriptor(Body.prototype,t);Object.defineProperty(e,t,n)}}};function consumeBody(){var e=this;if(this[u].disturbed){return Body.Promise.reject(new TypeError(`body used already for: ${this.url}`))}this[u].disturbed=true;if(this[u].error){return Body.Promise.reject(this[u].error)}let t=this.body;if(t===null){return Body.Promise.resolve(Buffer.alloc(0))}if(isBlob(t)){t=t.stream()}if(Buffer.isBuffer(t)){return Body.Promise.resolve(t)}if(!(t instanceof i)){return Body.Promise.resolve(Buffer.alloc(0))}let n=[];let o=0;let r=false;return new Body.Promise(function(i,s){let c;if(e.timeout){c=setTimeout(function(){r=true;s(new FetchError(`Response timeout while trying to fetch ${e.url} (over ${e.timeout}ms)`,"body-timeout"))},e.timeout)}t.on("error",function(t){if(t.name==="AbortError"){r=true;s(t)}else{s(new FetchError(`Invalid response body while trying to fetch ${e.url}: ${t.message}`,"system",t))}});t.on("data",function(t){if(r||t===null){return}if(e.size&&o+t.length>e.size){r=true;s(new FetchError(`content size at ${e.url} over limit: ${e.size}`,"max-size"));return}o+=t.length;n.push(t)});t.on("end",function(){if(r){return}clearTimeout(c);try{i(Buffer.concat(n,o))}catch(t){s(new FetchError(`Could not create Buffer from response body for ${e.url}: ${t.message}`,"system",t))}})})}function convertBody(e,t){if(typeof p!=="function"){throw new Error("The package `encoding` must be installed to use the textConverted() function")}const n=t.get("content-type");let i="utf-8";let o,r;if(n){o=/charset=([^;]*)/i.exec(n)}r=e.slice(0,1024).toString();if(!o&&r){o=/<meta.+?charset=(['"])(.+?)\1/i.exec(r)}if(!o&&r){o=/<meta[\s]+?http-equiv=(['"])content-type\1[\s]+?content=(['"])(.+?)\2/i.exec(r);if(!o){o=/<meta[\s]+?content=(['"])(.+?)\1[\s]+?http-equiv=(['"])content-type\3/i.exec(r);if(o){o.pop()}}if(o){o=/charset=(.*)/i.exec(o.pop())}}if(!o&&r){o=/<\?xml.+?encoding=(['"])(.+?)\1/i.exec(r)}if(o){i=o.pop();if(i==="gb2312"||i==="gbk"){i="gb18030"}}return p(e,"UTF-8",i).toString()}function isURLSearchParams(e){if(typeof e!=="object"||typeof e.append!=="function"||typeof e.delete!=="function"||typeof e.get!=="function"||typeof e.getAll!=="function"||typeof e.has!=="function"||typeof e.set!=="function"){return false}return e.constructor.name==="URLSearchParams"||Object.prototype.toString.call(e)==="[object URLSearchParams]"||typeof e.sort==="function"}function isBlob(e){return typeof e==="object"&&typeof e.arrayBuffer==="function"&&typeof e.type==="string"&&typeof e.stream==="function"&&typeof e.constructor==="function"&&typeof e.constructor.name==="string"&&/^(Blob|File)$/.test(e.constructor.name)&&/^(Blob|File)$/.test(e[Symbol.toStringTag])}function clone(e){let t,n;let o=e.body;if(e.bodyUsed){throw new Error("cannot clone body after it is used")}if(o instanceof i&&typeof o.getBoundary!=="function"){t=new l;n=new l;o.pipe(t);o.pipe(n);e[u].body=t;o=n}return o}function extractContentType(e){if(e===null){return null}else if(typeof e==="string"){return"text/plain;charset=UTF-8"}else if(isURLSearchParams(e)){return"application/x-www-form-urlencoded;charset=UTF-8"}else if(isBlob(e)){return e.type||null}else if(Buffer.isBuffer(e)){return null}else if(Object.prototype.toString.call(e)==="[object ArrayBuffer]"){return null}else if(ArrayBuffer.isView(e)){return null}else if(typeof e.getBoundary==="function"){return`multipart/form-data;boundary=${e.getBoundary()}`}else if(e instanceof i){return null}else{return"text/plain;charset=UTF-8"}}function getTotalBytes(e){const t=e.body;if(t===null){return 0}else if(isBlob(t)){return t.size}else if(Buffer.isBuffer(t)){return t.length}else if(t&&typeof t.getLengthSync==="function"){if(t._lengthRetrievers&&t._lengthRetrievers.length==0||t.hasKnownLength&&t.hasKnownLength()){return t.getLengthSync()}return null}else{return null}}function writeToStream(e,t){const n=t.body;if(n===null){e.end()}else if(isBlob(n)){n.stream().pipe(e)}else if(Buffer.isBuffer(n)){e.write(n);e.end()}else{n.pipe(e)}}Body.Promise=global.Promise;const d=/[^\^_`a-zA-Z\-0-9!#$%&'*+.|~]/;const b=/[^\t\x20-\x7e\x80-\xff]/;function validateName(e){e=`${e}`;if(d.test(e)||e===""){throw new TypeError(`${e} is not a legal HTTP header name`)}}function validateValue(e){e=`${e}`;if(b.test(e)){throw new TypeError(`${e} is not a legal HTTP header value`)}}function find(e,t){t=t.toLowerCase();for(const n in e){if(n.toLowerCase()===t){return n}}return undefined}const y=Symbol("map");class Headers{constructor(){let e=arguments.length>0&&arguments[0]!==undefined?arguments[0]:undefined;this[y]=Object.create(null);if(e instanceof Headers){const t=e.raw();const n=Object.keys(t);for(const e of n){for(const n of t[e]){this.append(e,n)}}return}if(e==null)   ;else if(typeof e==="object"){const t=e[Symbol.iterator];if(t!=null){if(typeof t!=="function"){throw new TypeError("Header pairs must be iterable")}const n=[];for(const t of e){if(typeof t!=="object"||typeof t[Symbol.iterator]!=="function"){throw new TypeError("Each header pair must be iterable")}n.push(Array.from(t))}for(const e of n){if(e.length!==2){throw new TypeError("Each header pair must be a name/value tuple")}this.append(e[0],e[1])}}else{for(const t of Object.keys(e)){const n=e[t];this.append(t,n)}}}else{throw new TypeError("Provided initializer must be an object")}}get(e){e=`${e}`;validateName(e);const t=find(this[y],e);if(t===undefined){return null}return this[y][t].join(", ")}forEach(e){let t=arguments.length>1&&arguments[1]!==undefined?arguments[1]:undefined;let n=getHeaders(this);let i=0;while(i<n.length){var o=n[i];const r=o[0],s=o[1];e.call(t,s,r,this);n=getHeaders(this);i++}}set(e,t){e=`${e}`;t=`${t}`;validateName(e);validateValue(t);const n=find(this[y],e);this[y][n!==undefined?n:e]=[t]}append(e,t){e=`${e}`;t=`${t}`;validateName(e);validateValue(t);const n=find(this[y],e);if(n!==undefined){this[y][n].push(t)}else{this[y][e]=[t]}}has(e){e=`${e}`;validateName(e);return find(this[y],e)!==undefined}delete(e){e=`${e}`;validateName(e);const t=find(this[y],e);if(t!==undefined){delete this[y][t]}}raw(){return this[y]}keys(){return createHeadersIterator(this,"key")}values(){return createHeadersIterator(this,"value")}[Symbol.iterator](){return createHeadersIterator(this,"key+value")}}Headers.prototype.entries=Headers.prototype[Symbol.iterator];Object.defineProperty(Headers.prototype,Symbol.toStringTag,{value:"Headers",writable:false,enumerable:false,configurable:true});Object.defineProperties(Headers.prototype,{get:{enumerable:true},forEach:{enumerable:true},set:{enumerable:true},append:{enumerable:true},has:{enumerable:true},delete:{enumerable:true},keys:{enumerable:true},values:{enumerable:true},entries:{enumerable:true}});function getHeaders(e){let t=arguments.length>1&&arguments[1]!==undefined?arguments[1]:"key+value";const n=Object.keys(e[y]).sort();return n.map(t==="key"?function(e){return e.toLowerCase()}:t==="value"?function(t){return e[y][t].join(", ")}:function(t){return[t.toLowerCase(),e[y][t].join(", ")]})}const g=Symbol("internal");function createHeadersIterator(e,t){const n=Object.create(m);n[g]={target:e,kind:t,index:0};return n}const m=Object.setPrototypeOf({next(){if(!this||Object.getPrototypeOf(this)!==m){throw new TypeError("Value of `this` is not a HeadersIterator")}var e=this[g];const t=e.target,n=e.kind,i=e.index;const o=getHeaders(t,n);const r=o.length;if(i>=r){return{value:undefined,done:true}}this[g].index=i+1;return{value:o[i],done:false}}},Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]())));Object.defineProperty(m,Symbol.toStringTag,{value:"HeadersIterator",writable:false,enumerable:false,configurable:true});function exportNodeCompatibleHeaders(e){const t=Object.assign({__proto__:null},e[y]);const n=find(e[y],"Host");if(n!==undefined){t[n]=t[n][0]}return t}function createHeadersLenient(e){const t=new Headers;for(const n of Object.keys(e)){if(d.test(n)){continue}if(Array.isArray(e[n])){for(const i of e[n]){if(b.test(i)){continue}if(t[y][n]===undefined){t[y][n]=[i]}else{t[y][n].push(i)}}}else if(!b.test(e[n])){t[y][n]=[e[n]]}}return t}const v=Symbol("Response internals");const w=o.STATUS_CODES;class Response{constructor(){let e=arguments.length>0&&arguments[0]!==undefined?arguments[0]:null;let t=arguments.length>1&&arguments[1]!==undefined?arguments[1]:{};Body.call(this,e,t);const n=t.status||200;const i=new Headers(t.headers);if(e!=null&&!i.has("Content-Type")){const t=extractContentType(e);if(t){i.append("Content-Type",t)}}this[v]={url:t.url,status:n,statusText:t.statusText||w[n],headers:i,counter:t.counter}}get url(){return this[v].url||""}get status(){return this[v].status}get ok(){return this[v].status>=200&&this[v].status<300}get redirected(){return this[v].counter>0}get statusText(){return this[v].statusText}get headers(){return this[v].headers}clone(){return new Response(clone(this),{url:this.url,status:this.status,statusText:this.statusText,headers:this.headers,ok:this.ok,redirected:this.redirected})}}Body.mixIn(Response.prototype);Object.defineProperties(Response.prototype,{url:{enumerable:true},status:{enumerable:true},ok:{enumerable:true},redirected:{enumerable:true},statusText:{enumerable:true},headers:{enumerable:true},clone:{enumerable:true}});Object.defineProperty(Response.prototype,Symbol.toStringTag,{value:"Response",writable:false,enumerable:false,configurable:true});const E=Symbol("Request internals");const B=r.parse;const _=r.format;const S="destroy"in i.Readable.prototype;function isRequest(e){return typeof e==="object"&&typeof e[E]==="object"}function isAbortSignal(e){const t=e&&typeof e==="object"&&Object.getPrototypeOf(e);return!!(t&&t.constructor.name==="AbortSignal")}class Request{constructor(e){let t=arguments.length>1&&arguments[1]!==undefined?arguments[1]:{};let n;if(!isRequest(e)){if(e&&e.href){n=B(e.href)}else{n=B(`${e}`)}e={}}else{n=B(e.url)}let i=t.method||e.method||"GET";i=i.toUpperCase();if((t.body!=null||isRequest(e)&&e.body!==null)&&(i==="GET"||i==="HEAD")){throw new TypeError("Request with GET/HEAD method cannot have body")}let o=t.body!=null?t.body:isRequest(e)&&e.body!==null?clone(e):null;Body.call(this,o,{timeout:t.timeout||e.timeout||0,size:t.size||e.size||0});const r=new Headers(t.headers||e.headers||{});if(o!=null&&!r.has("Content-Type")){const e=extractContentType(o);if(e){r.append("Content-Type",e)}}let s=isRequest(e)?e.signal:null;if("signal"in t)s=t.signal;if(s!=null&&!isAbortSignal(s)){throw new TypeError("Expected signal to be an instanceof AbortSignal")}this[E]={method:i,redirect:t.redirect||e.redirect||"follow",headers:r,parsedURL:n,signal:s};this.follow=t.follow!==undefined?t.follow:e.follow!==undefined?e.follow:20;this.compress=t.compress!==undefined?t.compress:e.compress!==undefined?e.compress:true;this.counter=t.counter||e.counter||0;this.agent=t.agent||e.agent}get method(){return this[E].method}get url(){return _(this[E].parsedURL)}get headers(){return this[E].headers}get redirect(){return this[E].redirect}get signal(){return this[E].signal}clone(){return new Request(this)}}Body.mixIn(Request.prototype);Object.defineProperty(Request.prototype,Symbol.toStringTag,{value:"Request",writable:false,enumerable:false,configurable:true});Object.defineProperties(Request.prototype,{method:{enumerable:true},url:{enumerable:true},headers:{enumerable:true},redirect:{enumerable:true},clone:{enumerable:true},signal:{enumerable:true}});function getNodeRequestOptions(e){const t=e[E].parsedURL;const n=new Headers(e[E].headers);if(!n.has("Accept")){n.set("Accept","*/*")}if(!t.protocol||!t.hostname){throw new TypeError("Only absolute URLs are supported")}if(!/^https?:$/.test(t.protocol)){throw new TypeError("Only HTTP(S) protocols are supported")}if(e.signal&&e.body instanceof i.Readable&&!S){throw new Error("Cancellation of streamed requests with AbortSignal is not supported in node < 8")}let o=null;if(e.body==null&&/^(POST|PUT)$/i.test(e.method)){o="0"}if(e.body!=null){const t=getTotalBytes(e);if(typeof t==="number"){o=String(t)}}if(o){n.set("Content-Length",o)}if(!n.has("User-Agent")){n.set("User-Agent","node-fetch/1.0 (+https://github.com/bitinn/node-fetch)")}if(e.compress&&!n.has("Accept-Encoding")){n.set("Accept-Encoding","gzip,deflate")}let r=e.agent;if(typeof r==="function"){r=r(t)}if(!n.has("Connection")&&!r){n.set("Connection","close")}return Object.assign({},t,{method:e.method,headers:exportNodeCompatibleHeaders(n),agent:r})}function AbortError(e){Error.call(this,e);this.type="aborted";this.message=e;Error.captureStackTrace(this,this.constructor)}AbortError.prototype=Object.create(Error.prototype);AbortError.prototype.constructor=AbortError;AbortError.prototype.name="AbortError";const x=i.PassThrough;const U=r.resolve;function fetch(e,t){if(!fetch.Promise){throw new Error("native promise missing, set fetch.Promise to your favorite alternative")}Body.Promise=fetch.Promise;return new fetch.Promise(function(n,r){const a=new Request(e,t);const f=getNodeRequestOptions(a);const h=(f.protocol==="https:"?s:o).request;const p=a.signal;let u=null;const l=function abort(){let e=new AbortError("The user aborted a request.");r(e);if(a.body&&a.body instanceof i.Readable){a.body.destroy(e)}if(!u||!u.body)return;u.body.emit("error",e)};if(p&&p.aborted){l();return}const d=function abortAndFinalize(){l();finalize()};const b=h(f);let y;if(p){p.addEventListener("abort",d)}function finalize(){b.abort();if(p)p.removeEventListener("abort",d);clearTimeout(y)}if(a.timeout){b.once("socket",function(e){y=setTimeout(function(){r(new FetchError(`network timeout at: ${a.url}`,"request-timeout"));finalize()},a.timeout)})}b.on("error",function(e){r(new FetchError(`request to ${a.url} failed, reason: ${e.message}`,"system",e));finalize()});b.on("response",function(e){clearTimeout(y);const t=createHeadersLenient(e.headers);if(fetch.isRedirect(e.statusCode)){const i=t.get("Location");const o=i===null?null:U(a.url,i);switch(a.redirect){case"error":r(new FetchError(`uri requested responds with a redirect, redirect mode is set to error: ${a.url}`,"no-redirect"));finalize();return;case"manual":if(o!==null){try{t.set("Location",o)}catch(e){r(e)}}break;case"follow":if(o===null){break}if(a.counter>=a.follow){r(new FetchError(`maximum redirect reached at: ${a.url}`,"max-redirect"));finalize();return}const i={headers:new Headers(a.headers),follow:a.follow,counter:a.counter+1,agent:a.agent,compress:a.compress,method:a.method,body:a.body,signal:a.signal,timeout:a.timeout,size:a.size};if(e.statusCode!==303&&a.body&&getTotalBytes(a)===null){r(new FetchError("Cannot follow redirect with body being a readable stream","unsupported-redirect"));finalize();return}if(e.statusCode===303||(e.statusCode===301||e.statusCode===302)&&a.method==="POST"){i.method="GET";i.body=undefined;i.headers.delete("content-length")}n(fetch(new Request(o,i)));finalize();return}}e.once("end",function(){if(p)p.removeEventListener("abort",d)});let i=e.pipe(new x);const o={url:a.url,status:e.statusCode,statusText:e.statusMessage,headers:t,size:a.size,timeout:a.timeout,counter:a.counter};const s=t.get("Content-Encoding");if(!a.compress||a.method==="HEAD"||s===null||e.statusCode===204||e.statusCode===304){u=new Response(i,o);n(u);return}const f={flush:c.Z_SYNC_FLUSH,finishFlush:c.Z_SYNC_FLUSH};if(s=="gzip"||s=="x-gzip"){i=i.pipe(c.createGunzip(f));u=new Response(i,o);n(u);return}if(s=="deflate"||s=="x-deflate"){const t=e.pipe(new x);t.once("data",function(e){if((e[0]&15)===8){i=i.pipe(c.createInflate())}else{i=i.pipe(c.createInflateRaw())}u=new Response(i,o);n(u)});return}if(s=="br"&&typeof c.createBrotliDecompress==="function"){i=i.pipe(c.createBrotliDecompress());u=new Response(i,o);n(u);return}u=new Response(i,o);n(u)});writeToStream(b,a)})}fetch.isRedirect=function(e){return e===301||e===302||e===303||e===307||e===308};fetch.Promise=global.Promise;e.exports=t=fetch;Object.defineProperty(t,"__esModule",{value:true});t.default=t;t.Headers=Headers;t.Request=Request;t.Response=Response;t.FetchError=FetchError},189:function(e,t,n){"use strict";var i=n(293).Buffer,o=n(413).Transform;e.exports=function(e){e.encodeStream=function encodeStream(t,n){return new IconvLiteEncoderStream(e.getEncoder(t,n),n)};e.decodeStream=function decodeStream(t,n){return new IconvLiteDecoderStream(e.getDecoder(t,n),n)};e.supportsStreams=true;e.IconvLiteEncoderStream=IconvLiteEncoderStream;e.IconvLiteDecoderStream=IconvLiteDecoderStream;e._collect=IconvLiteDecoderStream.prototype.collect};function IconvLiteEncoderStream(e,t){this.conv=e;t=t||{};t.decodeStrings=false;o.call(this,t)}IconvLiteEncoderStream.prototype=Object.create(o.prototype,{constructor:{value:IconvLiteEncoderStream}});IconvLiteEncoderStream.prototype._transform=function(e,t,n){if(typeof e!="string")return n(new Error("Iconv encoding stream needs strings as its input."));try{var i=this.conv.write(e);if(i&&i.length)this.push(i);n()}catch(e){n(e)}};IconvLiteEncoderStream.prototype._flush=function(e){try{var t=this.conv.end();if(t&&t.length)this.push(t);e()}catch(t){e(t)}};IconvLiteEncoderStream.prototype.collect=function(e){var t=[];this.on("error",e);this.on("data",function(e){t.push(e)});this.on("end",function(){e(null,i.concat(t))});return this};function IconvLiteDecoderStream(e,t){this.conv=e;t=t||{};t.encoding=this.encoding="utf8";o.call(this,t)}IconvLiteDecoderStream.prototype=Object.create(o.prototype,{constructor:{value:IconvLiteDecoderStream}});IconvLiteDecoderStream.prototype._transform=function(e,t,n){if(!i.isBuffer(e))return n(new Error("Iconv decoding stream needs buffers as its input."));try{var o=this.conv.write(e);if(o&&o.length)this.push(o,this.encoding);n()}catch(e){n(e)}};IconvLiteDecoderStream.prototype._flush=function(e){try{var t=this.conv.end();if(t&&t.length)this.push(t,this.encoding);e()}catch(t){e(t)}};IconvLiteDecoderStream.prototype.collect=function(e){var t="";this.on("error",e);this.on("data",function(e){t+=e});this.on("end",function(){e(null,t)});return this}},211:function(e){e.exports=__webpack_require__("7WL4")},237:function(e){e.exports=[["0","\0",127],["8141","갂갃갅갆갋",4,"갘갞갟갡갢갣갥",6,"갮갲갳갴"],["8161","갵갶갷갺갻갽갾갿걁",9,"걌걎",5,"걕"],["8181","걖걗걙걚걛걝",18,"걲걳걵걶걹걻",4,"겂겇겈겍겎겏겑겒겓겕",6,"겞겢",5,"겫겭겮겱",6,"겺겾겿곀곂곃곅곆곇곉곊곋곍",7,"곖곘",7,"곢곣곥곦곩곫곭곮곲곴곷",4,"곾곿괁괂괃괅괇",4,"괎괐괒괓"],["8241","괔괕괖괗괙괚괛괝괞괟괡",7,"괪괫괮",5],["8261","괶괷괹괺괻괽",6,"굆굈굊",5,"굑굒굓굕굖굗"],["8281","굙",7,"굢굤",7,"굮굯굱굲굷굸굹굺굾궀궃",4,"궊궋궍궎궏궑",10,"궞",5,"궥",17,"궸",7,"귂귃귅귆귇귉",6,"귒귔",7,"귝귞귟귡귢귣귥",18],["8341","귺귻귽귾긂",5,"긊긌긎",5,"긕",7],["8361","긝",18,"긲긳긵긶긹긻긼"],["8381","긽긾긿깂깄깇깈깉깋깏깑깒깓깕깗",4,"깞깢깣깤깦깧깪깫깭깮깯깱",6,"깺깾",5,"꺆",5,"꺍",46,"꺿껁껂껃껅",6,"껎껒",5,"껚껛껝",8],["8441","껦껧껩껪껬껮",5,"껵껶껷껹껺껻껽",8],["8461","꼆꼉꼊꼋꼌꼎꼏꼑",18],["8481","꼤",7,"꼮꼯꼱꼳꼵",6,"꼾꽀꽄꽅꽆꽇꽊",5,"꽑",10,"꽞",5,"꽦",18,"꽺",5,"꾁꾂꾃꾅꾆꾇꾉",6,"꾒꾓꾔꾖",5,"꾝",26,"꾺꾻꾽꾾"],["8541","꾿꿁",5,"꿊꿌꿏",4,"꿕",6,"꿝",4],["8561","꿢",5,"꿪",5,"꿲꿳꿵꿶꿷꿹",6,"뀂뀃"],["8581","뀅",6,"뀍뀎뀏뀑뀒뀓뀕",6,"뀞",9,"뀩",26,"끆끇끉끋끍끏끐끑끒끖끘끚끛끜끞",29,"끾끿낁낂낃낅",6,"낎낐낒",5,"낛낝낞낣낤"],["8641","낥낦낧낪낰낲낶낷낹낺낻낽",6,"냆냊",5,"냒"],["8661","냓냕냖냗냙",6,"냡냢냣냤냦",10],["8681","냱",22,"넊넍넎넏넑넔넕넖넗넚넞",4,"넦넧넩넪넫넭",6,"넶넺",5,"녂녃녅녆녇녉",6,"녒녓녖녗녙녚녛녝녞녟녡",22,"녺녻녽녾녿놁놃",4,"놊놌놎놏놐놑놕놖놗놙놚놛놝"],["8741","놞",9,"놩",15],["8761","놹",18,"뇍뇎뇏뇑뇒뇓뇕"],["8781","뇖",5,"뇞뇠",7,"뇪뇫뇭뇮뇯뇱",7,"뇺뇼뇾",5,"눆눇눉눊눍",6,"눖눘눚",5,"눡",18,"눵",6,"눽",26,"뉙뉚뉛뉝뉞뉟뉡",6,"뉪",4],["8841","뉯",4,"뉶",5,"뉽",6,"늆늇늈늊",4],["8861","늏늒늓늕늖늗늛",4,"늢늤늧늨늩늫늭늮늯늱늲늳늵늶늷"],["8881","늸",15,"닊닋닍닎닏닑닓",4,"닚닜닞닟닠닡닣닧닩닪닰닱닲닶닼닽닾댂댃댅댆댇댉",6,"댒댖",5,"댝",54,"덗덙덚덝덠덡덢덣"],["8941","덦덨덪덬덭덯덲덳덵덶덷덹",6,"뎂뎆",5,"뎍"],["8961","뎎뎏뎑뎒뎓뎕",10,"뎢",5,"뎩뎪뎫뎭"],["8981","뎮",21,"돆돇돉돊돍돏돑돒돓돖돘돚돜돞돟돡돢돣돥돦돧돩",18,"돽",18,"됑",6,"됙됚됛됝됞됟됡",6,"됪됬",7,"됵",15],["8a41","둅",10,"둒둓둕둖둗둙",6,"둢둤둦"],["8a61","둧",4,"둭",18,"뒁뒂"],["8a81","뒃",4,"뒉",19,"뒞",5,"뒥뒦뒧뒩뒪뒫뒭",7,"뒶뒸뒺",5,"듁듂듃듅듆듇듉",6,"듑듒듓듔듖",5,"듞듟듡듢듥듧",4,"듮듰듲",5,"듹",26,"딖딗딙딚딝"],["8b41","딞",5,"딦딫",4,"딲딳딵딶딷딹",6,"땂땆"],["8b61","땇땈땉땊땎땏땑땒땓땕",6,"땞땢",8],["8b81","땫",52,"떢떣떥떦떧떩떬떭떮떯떲떶",4,"떾떿뗁뗂뗃뗅",6,"뗎뗒",5,"뗙",18,"뗭",18],["8c41","똀",15,"똒똓똕똖똗똙",4],["8c61","똞",6,"똦",5,"똭",6,"똵",5],["8c81","똻",12,"뙉",26,"뙥뙦뙧뙩",50,"뚞뚟뚡뚢뚣뚥",5,"뚭뚮뚯뚰뚲",16],["8d41","뛃",16,"뛕",8],["8d61","뛞",17,"뛱뛲뛳뛵뛶뛷뛹뛺"],["8d81","뛻",4,"뜂뜃뜄뜆",33,"뜪뜫뜭뜮뜱",6,"뜺뜼",7,"띅띆띇띉띊띋띍",6,"띖",9,"띡띢띣띥띦띧띩",6,"띲띴띶",5,"띾띿랁랂랃랅",6,"랎랓랔랕랚랛랝랞"],["8e41","랟랡",6,"랪랮",5,"랶랷랹",8],["8e61","럂",4,"럈럊",19],["8e81","럞",13,"럮럯럱럲럳럵",6,"럾렂",4,"렊렋렍렎렏렑",6,"렚렜렞",5,"렦렧렩렪렫렭",6,"렶렺",5,"롁롂롃롅",11,"롒롔",7,"롞롟롡롢롣롥",6,"롮롰롲",5,"롹롺롻롽",7],["8f41","뢅",7,"뢎",17],["8f61","뢠",7,"뢩",6,"뢱뢲뢳뢵뢶뢷뢹",4],["8f81","뢾뢿룂룄룆",5,"룍룎룏룑룒룓룕",7,"룞룠룢",5,"룪룫룭룮룯룱",6,"룺룼룾",5,"뤅",18,"뤙",6,"뤡",26,"뤾뤿륁륂륃륅",6,"륍륎륐륒",5],["9041","륚륛륝륞륟륡",6,"륪륬륮",5,"륶륷륹륺륻륽"],["9061","륾",5,"릆릈릋릌릏",15],["9081","릟",12,"릮릯릱릲릳릵",6,"릾맀맂",5,"맊맋맍맓",4,"맚맜맟맠맢맦맧맩맪맫맭",6,"맶맻",4,"먂",5,"먉",11,"먖",33,"먺먻먽먾먿멁멃멄멅멆"],["9141","멇멊멌멏멐멑멒멖멗멙멚멛멝",6,"멦멪",5],["9161","멲멳멵멶멷멹",9,"몆몈몉몊몋몍",5],["9181","몓",20,"몪몭몮몯몱몳",4,"몺몼몾",5,"뫅뫆뫇뫉",14,"뫚",33,"뫽뫾뫿묁묂묃묅",7,"묎묐묒",5,"묙묚묛묝묞묟묡",6],["9241","묨묪묬",7,"묷묹묺묿",4,"뭆뭈뭊뭋뭌뭎뭑뭒"],["9261","뭓뭕뭖뭗뭙",7,"뭢뭤",7,"뭭",4],["9281","뭲",21,"뮉뮊뮋뮍뮎뮏뮑",18,"뮥뮦뮧뮩뮪뮫뮭",6,"뮵뮶뮸",7,"믁믂믃믅믆믇믉",6,"믑믒믔",35,"믺믻믽믾밁"],["9341","밃",4,"밊밎밐밒밓밙밚밠밡밢밣밦밨밪밫밬밮밯밲밳밵"],["9361","밶밷밹",6,"뱂뱆뱇뱈뱊뱋뱎뱏뱑",8],["9381","뱚뱛뱜뱞",37,"벆벇벉벊벍벏",4,"벖벘벛",4,"벢벣벥벦벩",6,"벲벶",5,"벾벿볁볂볃볅",7,"볎볒볓볔볖볗볙볚볛볝",22,"볷볹볺볻볽"],["9441","볾",5,"봆봈봊",5,"봑봒봓봕",8],["9461","봞",5,"봥",6,"봭",12],["9481","봺",5,"뵁",6,"뵊뵋뵍뵎뵏뵑",6,"뵚",9,"뵥뵦뵧뵩",22,"붂붃붅붆붋",4,"붒붔붖붗붘붛붝",6,"붥",10,"붱",6,"붹",24],["9541","뷒뷓뷖뷗뷙뷚뷛뷝",11,"뷪",5,"뷱"],["9561","뷲뷳뷵뷶뷷뷹",6,"븁븂븄븆",5,"븎븏븑븒븓"],["9581","븕",6,"븞븠",35,"빆빇빉빊빋빍빏",4,"빖빘빜빝빞빟빢빣빥빦빧빩빫",4,"빲빶",4,"빾빿뺁뺂뺃뺅",6,"뺎뺒",5,"뺚",13,"뺩",14],["9641","뺸",23,"뻒뻓"],["9661","뻕뻖뻙",6,"뻡뻢뻦",5,"뻭",8],["9681","뻶",10,"뼂",5,"뼊",13,"뼚뼞",33,"뽂뽃뽅뽆뽇뽉",6,"뽒뽓뽔뽖",44],["9741","뾃",16,"뾕",8],["9761","뾞",17,"뾱",7],["9781","뾹",11,"뿆",5,"뿎뿏뿑뿒뿓뿕",6,"뿝뿞뿠뿢",89,"쀽쀾쀿"],["9841","쁀",16,"쁒",5,"쁙쁚쁛"],["9861","쁝쁞쁟쁡",6,"쁪",15],["9881","쁺",21,"삒삓삕삖삗삙",6,"삢삤삦",5,"삮삱삲삷",4,"삾샂샃샄샆샇샊샋샍샎샏샑",6,"샚샞",5,"샦샧샩샪샫샭",6,"샶샸샺",5,"섁섂섃섅섆섇섉",6,"섑섒섓섔섖",5,"섡섢섥섨섩섪섫섮"],["9941","섲섳섴섵섷섺섻섽섾섿셁",6,"셊셎",5,"셖셗"],["9961","셙셚셛셝",6,"셦셪",5,"셱셲셳셵셶셷셹셺셻"],["9981","셼",8,"솆",5,"솏솑솒솓솕솗",4,"솞솠솢솣솤솦솧솪솫솭솮솯솱",11,"솾",5,"쇅쇆쇇쇉쇊쇋쇍",6,"쇕쇖쇙",6,"쇡쇢쇣쇥쇦쇧쇩",6,"쇲쇴",7,"쇾쇿숁숂숃숅",6,"숎숐숒",5,"숚숛숝숞숡숢숣"],["9a41","숤숥숦숧숪숬숮숰숳숵",16],["9a61","쉆쉇쉉",6,"쉒쉓쉕쉖쉗쉙",6,"쉡쉢쉣쉤쉦"],["9a81","쉧",4,"쉮쉯쉱쉲쉳쉵",6,"쉾슀슂",5,"슊",5,"슑",6,"슙슚슜슞",5,"슦슧슩슪슫슮",5,"슶슸슺",33,"싞싟싡싢싥",5,"싮싰싲싳싴싵싷싺싽싾싿쌁",6,"쌊쌋쌎쌏"],["9b41","쌐쌑쌒쌖쌗쌙쌚쌛쌝",6,"쌦쌧쌪",8],["9b61","쌳",17,"썆",7],["9b81","썎",25,"썪썫썭썮썯썱썳",4,"썺썻썾",5,"쎅쎆쎇쎉쎊쎋쎍",50,"쏁",22,"쏚"],["9c41","쏛쏝쏞쏡쏣",4,"쏪쏫쏬쏮",5,"쏶쏷쏹",5],["9c61","쏿",8,"쐉",6,"쐑",9],["9c81","쐛",8,"쐥",6,"쐭쐮쐯쐱쐲쐳쐵",6,"쐾",9,"쑉",26,"쑦쑧쑩쑪쑫쑭",6,"쑶쑷쑸쑺",5,"쒁",18,"쒕",6,"쒝",12],["9d41","쒪",13,"쒹쒺쒻쒽",8],["9d61","쓆",25],["9d81","쓠",8,"쓪",5,"쓲쓳쓵쓶쓷쓹쓻쓼쓽쓾씂",9,"씍씎씏씑씒씓씕",6,"씝",10,"씪씫씭씮씯씱",6,"씺씼씾",5,"앆앇앋앏앐앑앒앖앚앛앜앟앢앣앥앦앧앩",6,"앲앶",5,"앾앿얁얂얃얅얆얈얉얊얋얎얐얒얓얔"],["9e41","얖얙얚얛얝얞얟얡",7,"얪",9,"얶"],["9e61","얷얺얿",4,"엋엍엏엒엓엕엖엗엙",6,"엢엤엦엧"],["9e81","엨엩엪엫엯엱엲엳엵엸엹엺엻옂옃옄옉옊옋옍옎옏옑",6,"옚옝",6,"옦옧옩옪옫옯옱옲옶옸옺옼옽옾옿왂왃왅왆왇왉",6,"왒왖",5,"왞왟왡",10,"왭왮왰왲",5,"왺왻왽왾왿욁",6,"욊욌욎",5,"욖욗욙욚욛욝",6,"욦"],["9f41","욨욪",5,"욲욳욵욶욷욻",4,"웂웄웆",5,"웎"],["9f61","웏웑웒웓웕",6,"웞웟웢",5,"웪웫웭웮웯웱웲"],["9f81","웳",4,"웺웻웼웾",5,"윆윇윉윊윋윍",6,"윖윘윚",5,"윢윣윥윦윧윩",6,"윲윴윶윸윹윺윻윾윿읁읂읃읅",4,"읋읎읐읙읚읛읝읞읟읡",6,"읩읪읬",7,"읶읷읹읺읻읿잀잁잂잆잋잌잍잏잒잓잕잙잛",4,"잢잧",4,"잮잯잱잲잳잵잶잷"],["a041","잸잹잺잻잾쟂",5,"쟊쟋쟍쟏쟑",6,"쟙쟚쟛쟜"],["a061","쟞",5,"쟥쟦쟧쟩쟪쟫쟭",13],["a081","쟻",4,"젂젃젅젆젇젉젋",4,"젒젔젗",4,"젞젟젡젢젣젥",6,"젮젰젲",5,"젹젺젻젽젾젿졁",6,"졊졋졎",5,"졕",26,"졲졳졵졶졷졹졻",4,"좂좄좈좉좊좎",5,"좕",7,"좞좠좢좣좤"],["a141","좥좦좧좩",18,"좾좿죀죁"],["a161","죂죃죅죆죇죉죊죋죍",6,"죖죘죚",5,"죢죣죥"],["a181","죦",14,"죶",5,"죾죿줁줂줃줇",4,"줎　、。·‥…¨〃­―∥＼∼‘’“”〔〕〈",9,"±×÷≠≤≥∞∴°′″℃Å￠￡￥♂♀∠⊥⌒∂∇≡≒§※☆★○●◎◇◆□■△▲▽▼→←↑↓↔〓≪≫√∽∝∵∫∬∈∋⊆⊇⊂⊃∪∩∧∨￢"],["a241","줐줒",5,"줙",18],["a261","줭",6,"줵",18],["a281","쥈",7,"쥒쥓쥕쥖쥗쥙",6,"쥢쥤",7,"쥭쥮쥯⇒⇔∀∃´～ˇ˘˝˚˙¸˛¡¿ː∮∑∏¤℉‰◁◀▷▶♤♠♡♥♧♣⊙◈▣◐◑▒▤▥▨▧▦▩♨☏☎☜☞¶†‡↕↗↙↖↘♭♩♪♬㉿㈜№㏇™㏂㏘℡€®"],["a341","쥱쥲쥳쥵",6,"쥽",10,"즊즋즍즎즏"],["a361","즑",6,"즚즜즞",16],["a381","즯",16,"짂짃짅짆짉짋",4,"짒짔짗짘짛！",58,"￦］",32,"￣"],["a441","짞짟짡짣짥짦짨짩짪짫짮짲",5,"짺짻짽짾짿쨁쨂쨃쨄"],["a461","쨅쨆쨇쨊쨎",5,"쨕쨖쨗쨙",12],["a481","쨦쨧쨨쨪",28,"ㄱ",93],["a541","쩇",4,"쩎쩏쩑쩒쩓쩕",6,"쩞쩢",5,"쩩쩪"],["a561","쩫",17,"쩾",5,"쪅쪆"],["a581","쪇",16,"쪙",14,"ⅰ",9],["a5b0","Ⅰ",9],["a5c1","Α",16,"Σ",6],["a5e1","α",16,"σ",6],["a641","쪨",19,"쪾쪿쫁쫂쫃쫅"],["a661","쫆",5,"쫎쫐쫒쫔쫕쫖쫗쫚",5,"쫡",6],["a681","쫨쫩쫪쫫쫭",6,"쫵",18,"쬉쬊─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂┒┑┚┙┖┕┎┍┞┟┡┢┦┧┩┪┭┮┱┲┵┶┹┺┽┾╀╁╃",7],["a741","쬋",4,"쬑쬒쬓쬕쬖쬗쬙",6,"쬢",7],["a761","쬪",22,"쭂쭃쭄"],["a781","쭅쭆쭇쭊쭋쭍쭎쭏쭑",6,"쭚쭛쭜쭞",5,"쭥",7,"㎕㎖㎗ℓ㎘㏄㎣㎤㎥㎦㎙",9,"㏊㎍㎎㎏㏏㎈㎉㏈㎧㎨㎰",9,"㎀",4,"㎺",5,"㎐",4,"Ω㏀㏁㎊㎋㎌㏖㏅㎭㎮㎯㏛㎩㎪㎫㎬㏝㏐㏓㏃㏉㏜㏆"],["a841","쭭",10,"쭺",14],["a861","쮉",18,"쮝",6],["a881","쮤",19,"쮹",11,"ÆÐªĦ"],["a8a6","Ĳ"],["a8a8","ĿŁØŒºÞŦŊ"],["a8b1","㉠",27,"ⓐ",25,"①",14,"½⅓⅔¼¾⅛⅜⅝⅞"],["a941","쯅",14,"쯕",10],["a961","쯠쯡쯢쯣쯥쯦쯨쯪",18],["a981","쯽",14,"찎찏찑찒찓찕",6,"찞찟찠찣찤æđðħıĳĸŀłøœßþŧŋŉ㈀",27,"⒜",25,"⑴",14,"¹²³⁴ⁿ₁₂₃₄"],["aa41","찥찦찪찫찭찯찱",6,"찺찿",4,"챆챇챉챊챋챍챎"],["aa61","챏",4,"챖챚",5,"챡챢챣챥챧챩",6,"챱챲"],["aa81","챳챴챶",29,"ぁ",82],["ab41","첔첕첖첗첚첛첝첞첟첡",6,"첪첮",5,"첶첷첹"],["ab61","첺첻첽",6,"쳆쳈쳊",5,"쳑쳒쳓쳕",5],["ab81","쳛",8,"쳥",6,"쳭쳮쳯쳱",12,"ァ",85],["ac41","쳾쳿촀촂",5,"촊촋촍촎촏촑",6,"촚촜촞촟촠"],["ac61","촡촢촣촥촦촧촩촪촫촭",11,"촺",4],["ac81","촿",28,"쵝쵞쵟А",5,"ЁЖ",25],["acd1","а",5,"ёж",25],["ad41","쵡쵢쵣쵥",6,"쵮쵰쵲",5,"쵹",7],["ad61","춁",6,"춉",10,"춖춗춙춚춛춝춞춟"],["ad81","춠춡춢춣춦춨춪",5,"춱",18,"췅"],["ae41","췆",5,"췍췎췏췑",16],["ae61","췢",5,"췩췪췫췭췮췯췱",6,"췺췼췾",4],["ae81","츃츅츆츇츉츊츋츍",6,"츕츖츗츘츚",5,"츢츣츥츦츧츩츪츫"],["af41","츬츭츮츯츲츴츶",19],["af61","칊",13,"칚칛칝칞칢",5,"칪칬"],["af81","칮",5,"칶칷칹칺칻칽",6,"캆캈캊",5,"캒캓캕캖캗캙"],["b041","캚",5,"캢캦",5,"캮",12],["b061","캻",5,"컂",19],["b081","컖",13,"컦컧컩컪컭",6,"컶컺",5,"가각간갇갈갉갊감",7,"같",4,"갠갤갬갭갯갰갱갸갹갼걀걋걍걔걘걜거걱건걷걸걺검겁것겄겅겆겉겊겋게겐겔겜겝겟겠겡겨격겪견겯결겸겹겻겼경곁계곈곌곕곗고곡곤곧골곪곬곯곰곱곳공곶과곽관괄괆"],["b141","켂켃켅켆켇켉",6,"켒켔켖",5,"켝켞켟켡켢켣"],["b161","켥",6,"켮켲",5,"켹",11],["b181","콅",14,"콖콗콙콚콛콝",6,"콦콨콪콫콬괌괍괏광괘괜괠괩괬괭괴괵괸괼굄굅굇굉교굔굘굡굣구국군굳굴굵굶굻굼굽굿궁궂궈궉권궐궜궝궤궷귀귁귄귈귐귑귓규균귤그극근귿글긁금급긋긍긔기긱긴긷길긺김깁깃깅깆깊까깍깎깐깔깖깜깝깟깠깡깥깨깩깬깰깸"],["b241","콭콮콯콲콳콵콶콷콹",6,"쾁쾂쾃쾄쾆",5,"쾍"],["b261","쾎",18,"쾢",5,"쾩"],["b281","쾪",5,"쾱",18,"쿅",6,"깹깻깼깽꺄꺅꺌꺼꺽꺾껀껄껌껍껏껐껑께껙껜껨껫껭껴껸껼꼇꼈꼍꼐꼬꼭꼰꼲꼴꼼꼽꼿꽁꽂꽃꽈꽉꽐꽜꽝꽤꽥꽹꾀꾄꾈꾐꾑꾕꾜꾸꾹꾼꿀꿇꿈꿉꿋꿍꿎꿔꿜꿨꿩꿰꿱꿴꿸뀀뀁뀄뀌뀐뀔뀜뀝뀨끄끅끈끊끌끎끓끔끕끗끙"],["b341","쿌",19,"쿢쿣쿥쿦쿧쿩"],["b361","쿪",5,"쿲쿴쿶",5,"쿽쿾쿿퀁퀂퀃퀅",5],["b381","퀋",5,"퀒",5,"퀙",19,"끝끼끽낀낄낌낍낏낑나낙낚난낟날낡낢남납낫",4,"낱낳내낵낸낼냄냅냇냈냉냐냑냔냘냠냥너넉넋넌널넒넓넘넙넛넜넝넣네넥넨넬넴넵넷넸넹녀녁년녈념녑녔녕녘녜녠노녹논놀놂놈놉놋농높놓놔놘놜놨뇌뇐뇔뇜뇝"],["b441","퀮",5,"퀶퀷퀹퀺퀻퀽",6,"큆큈큊",5],["b461","큑큒큓큕큖큗큙",6,"큡",10,"큮큯"],["b481","큱큲큳큵",6,"큾큿킀킂",18,"뇟뇨뇩뇬뇰뇹뇻뇽누눅눈눋눌눔눕눗눙눠눴눼뉘뉜뉠뉨뉩뉴뉵뉼늄늅늉느늑는늘늙늚늠늡늣능늦늪늬늰늴니닉닌닐닒님닙닛닝닢다닥닦단닫",4,"닳담답닷",4,"닿대댁댄댈댐댑댓댔댕댜더덕덖던덛덜덞덟덤덥"],["b541","킕",14,"킦킧킩킪킫킭",5],["b561","킳킶킸킺",5,"탂탃탅탆탇탊",5,"탒탖",4],["b581","탛탞탟탡탢탣탥",6,"탮탲",5,"탹",11,"덧덩덫덮데덱덴델뎀뎁뎃뎄뎅뎌뎐뎔뎠뎡뎨뎬도독돈돋돌돎돐돔돕돗동돛돝돠돤돨돼됐되된될됨됩됫됴두둑둔둘둠둡둣둥둬뒀뒈뒝뒤뒨뒬뒵뒷뒹듀듄듈듐듕드득든듣들듦듬듭듯등듸디딕딘딛딜딤딥딧딨딩딪따딱딴딸"],["b641","턅",7,"턎",17],["b661","턠",15,"턲턳턵턶턷턹턻턼턽턾"],["b681","턿텂텆",5,"텎텏텑텒텓텕",6,"텞텠텢",5,"텩텪텫텭땀땁땃땄땅땋때땍땐땔땜땝땟땠땡떠떡떤떨떪떫떰떱떳떴떵떻떼떽뗀뗄뗌뗍뗏뗐뗑뗘뗬또똑똔똘똥똬똴뙈뙤뙨뚜뚝뚠뚤뚫뚬뚱뛔뛰뛴뛸뜀뜁뜅뜨뜩뜬뜯뜰뜸뜹뜻띄띈띌띔띕띠띤띨띰띱띳띵라락란랄람랍랏랐랑랒랖랗"],["b741","텮",13,"텽",6,"톅톆톇톉톊"],["b761","톋",20,"톢톣톥톦톧"],["b781","톩",6,"톲톴톶톷톸톹톻톽톾톿퇁",14,"래랙랜랠램랩랫랬랭랴략랸럇량러럭런럴럼럽럿렀렁렇레렉렌렐렘렙렛렝려력련렬렴렵렷렸령례롄롑롓로록론롤롬롭롯롱롸롼뢍뢨뢰뢴뢸룀룁룃룅료룐룔룝룟룡루룩룬룰룸룹룻룽뤄뤘뤠뤼뤽륀륄륌륏륑류륙륜률륨륩"],["b841","퇐",7,"퇙",17],["b861","퇫",8,"퇵퇶퇷퇹",13],["b881","툈툊",5,"툑",24,"륫륭르륵른를름릅릇릉릊릍릎리릭린릴림립릿링마막만많",4,"맘맙맛망맞맡맣매맥맨맬맴맵맷맸맹맺먀먁먈먕머먹먼멀멂멈멉멋멍멎멓메멕멘멜멤멥멧멨멩며멱면멸몃몄명몇몌모목몫몬몰몲몸몹못몽뫄뫈뫘뫙뫼"],["b941","툪툫툮툯툱툲툳툵",6,"툾퉀퉂",5,"퉉퉊퉋퉌"],["b961","퉍",14,"퉝",6,"퉥퉦퉧퉨"],["b981","퉩",22,"튂튃튅튆튇튉튊튋튌묀묄묍묏묑묘묜묠묩묫무묵묶문묻물묽묾뭄뭅뭇뭉뭍뭏뭐뭔뭘뭡뭣뭬뮈뮌뮐뮤뮨뮬뮴뮷므믄믈믐믓미믹민믿밀밂밈밉밋밌밍및밑바",4,"받",4,"밤밥밧방밭배백밴밸뱀뱁뱃뱄뱅뱉뱌뱍뱐뱝버벅번벋벌벎범법벗"],["ba41","튍튎튏튒튓튔튖",5,"튝튞튟튡튢튣튥",6,"튭"],["ba61","튮튯튰튲",5,"튺튻튽튾틁틃",4,"틊틌",5],["ba81","틒틓틕틖틗틙틚틛틝",6,"틦",9,"틲틳틵틶틷틹틺벙벚베벡벤벧벨벰벱벳벴벵벼벽변별볍볏볐병볕볘볜보복볶본볼봄봅봇봉봐봔봤봬뵀뵈뵉뵌뵐뵘뵙뵤뵨부북분붇불붉붊붐붑붓붕붙붚붜붤붰붸뷔뷕뷘뷜뷩뷰뷴뷸븀븃븅브븍븐블븜븝븟비빅빈빌빎빔빕빗빙빚빛빠빡빤"],["bb41","틻",4,"팂팄팆",5,"팏팑팒팓팕팗",4,"팞팢팣"],["bb61","팤팦팧팪팫팭팮팯팱",6,"팺팾",5,"퍆퍇퍈퍉"],["bb81","퍊",31,"빨빪빰빱빳빴빵빻빼빽뺀뺄뺌뺍뺏뺐뺑뺘뺙뺨뻐뻑뻔뻗뻘뻠뻣뻤뻥뻬뼁뼈뼉뼘뼙뼛뼜뼝뽀뽁뽄뽈뽐뽑뽕뾔뾰뿅뿌뿍뿐뿔뿜뿟뿡쀼쁑쁘쁜쁠쁨쁩삐삑삔삘삠삡삣삥사삭삯산삳살삵삶삼삽삿샀상샅새색샌샐샘샙샛샜생샤"],["bc41","퍪",17,"퍾퍿펁펂펃펅펆펇"],["bc61","펈펉펊펋펎펒",5,"펚펛펝펞펟펡",6,"펪펬펮"],["bc81","펯",4,"펵펶펷펹펺펻펽",6,"폆폇폊",5,"폑",5,"샥샨샬샴샵샷샹섀섄섈섐섕서",4,"섣설섦섧섬섭섯섰성섶세섹센셀셈셉셋셌셍셔셕션셜셤셥셧셨셩셰셴셸솅소속솎손솔솖솜솝솟송솥솨솩솬솰솽쇄쇈쇌쇔쇗쇘쇠쇤쇨쇰쇱쇳쇼쇽숀숄숌숍숏숑수숙순숟술숨숩숫숭"],["bd41","폗폙",7,"폢폤",7,"폮폯폱폲폳폵폶폷"],["bd61","폸폹폺폻폾퐀퐂",5,"퐉",13],["bd81","퐗",5,"퐞",25,"숯숱숲숴쉈쉐쉑쉔쉘쉠쉥쉬쉭쉰쉴쉼쉽쉿슁슈슉슐슘슛슝스슥슨슬슭슴습슷승시식신싣실싫심십싯싱싶싸싹싻싼쌀쌈쌉쌌쌍쌓쌔쌕쌘쌜쌤쌥쌨쌩썅써썩썬썰썲썸썹썼썽쎄쎈쎌쏀쏘쏙쏜쏟쏠쏢쏨쏩쏭쏴쏵쏸쐈쐐쐤쐬쐰"],["be41","퐸",7,"푁푂푃푅",14],["be61","푔",7,"푝푞푟푡푢푣푥",7,"푮푰푱푲"],["be81","푳",4,"푺푻푽푾풁풃",4,"풊풌풎",5,"풕",8,"쐴쐼쐽쑈쑤쑥쑨쑬쑴쑵쑹쒀쒔쒜쒸쒼쓩쓰쓱쓴쓸쓺쓿씀씁씌씐씔씜씨씩씬씰씸씹씻씽아악안앉않알앍앎앓암압앗았앙앝앞애액앤앨앰앱앳앴앵야약얀얄얇얌얍얏양얕얗얘얜얠얩어억언얹얻얼얽얾엄",6,"엌엎"],["bf41","풞",10,"풪",14],["bf61","풹",18,"퓍퓎퓏퓑퓒퓓퓕"],["bf81","퓖",5,"퓝퓞퓠",7,"퓩퓪퓫퓭퓮퓯퓱",6,"퓹퓺퓼에엑엔엘엠엡엣엥여역엮연열엶엷염",5,"옅옆옇예옌옐옘옙옛옜오옥온올옭옮옰옳옴옵옷옹옻와왁완왈왐왑왓왔왕왜왝왠왬왯왱외왹왼욀욈욉욋욍요욕욘욜욤욥욧용우욱운울욹욺움웁웃웅워웍원월웜웝웠웡웨"],["c041","퓾",5,"픅픆픇픉픊픋픍",6,"픖픘",5],["c061","픞",25],["c081","픸픹픺픻픾픿핁핂핃핅",6,"핎핐핒",5,"핚핛핝핞핟핡핢핣웩웬웰웸웹웽위윅윈윌윔윕윗윙유육윤율윰윱윳융윷으윽은을읊음읍읏응",7,"읜읠읨읫이익인일읽읾잃임입잇있잉잊잎자작잔잖잗잘잚잠잡잣잤장잦재잭잰잴잼잽잿쟀쟁쟈쟉쟌쟎쟐쟘쟝쟤쟨쟬저적전절젊"],["c141","핤핦핧핪핬핮",5,"핶핷핹핺핻핽",6,"햆햊햋"],["c161","햌햍햎햏햑",19,"햦햧"],["c181","햨",31,"점접젓정젖제젝젠젤젬젭젯젱져젼졀졈졉졌졍졔조족존졸졺좀좁좃종좆좇좋좌좍좔좝좟좡좨좼좽죄죈죌죔죕죗죙죠죡죤죵주죽준줄줅줆줌줍줏중줘줬줴쥐쥑쥔쥘쥠쥡쥣쥬쥰쥴쥼즈즉즌즐즘즙즛증지직진짇질짊짐집짓"],["c241","헊헋헍헎헏헑헓",4,"헚헜헞",5,"헦헧헩헪헫헭헮"],["c261","헯",4,"헶헸헺",5,"혂혃혅혆혇혉",6,"혒"],["c281","혖",5,"혝혞혟혡혢혣혥",7,"혮",9,"혺혻징짖짙짚짜짝짠짢짤짧짬짭짯짰짱째짹짼쨀쨈쨉쨋쨌쨍쨔쨘쨩쩌쩍쩐쩔쩜쩝쩟쩠쩡쩨쩽쪄쪘쪼쪽쫀쫄쫌쫍쫏쫑쫓쫘쫙쫠쫬쫴쬈쬐쬔쬘쬠쬡쭁쭈쭉쭌쭐쭘쭙쭝쭤쭸쭹쮜쮸쯔쯤쯧쯩찌찍찐찔찜찝찡찢찧차착찬찮찰참찹찻"],["c341","혽혾혿홁홂홃홄홆홇홊홌홎홏홐홒홓홖홗홙홚홛홝",4],["c361","홢",4,"홨홪",5,"홲홳홵",11],["c381","횁횂횄횆",5,"횎횏횑횒횓횕",7,"횞횠횢",5,"횩횪찼창찾채책챈챌챔챕챗챘챙챠챤챦챨챰챵처척천철첨첩첫첬청체첵첸첼쳄쳅쳇쳉쳐쳔쳤쳬쳰촁초촉촌촐촘촙촛총촤촨촬촹최쵠쵤쵬쵭쵯쵱쵸춈추축춘출춤춥춧충춰췄췌췐취췬췰췸췹췻췽츄츈츌츔츙츠측츤츨츰츱츳층"],["c441","횫횭횮횯횱",7,"횺횼",7,"훆훇훉훊훋"],["c461","훍훎훏훐훒훓훕훖훘훚",5,"훡훢훣훥훦훧훩",4],["c481","훮훯훱훲훳훴훶",5,"훾훿휁휂휃휅",11,"휒휓휔치칙친칟칠칡침칩칫칭카칵칸칼캄캅캇캉캐캑캔캘캠캡캣캤캥캬캭컁커컥컨컫컬컴컵컷컸컹케켁켄켈켐켑켓켕켜켠켤켬켭켯켰켱켸코콕콘콜콤콥콧콩콰콱콴콸쾀쾅쾌쾡쾨쾰쿄쿠쿡쿤쿨쿰쿱쿳쿵쿼퀀퀄퀑퀘퀭퀴퀵퀸퀼"],["c541","휕휖휗휚휛휝휞휟휡",6,"휪휬휮",5,"휶휷휹"],["c561","휺휻휽",6,"흅흆흈흊",5,"흒흓흕흚",4],["c581","흟흢흤흦흧흨흪흫흭흮흯흱흲흳흵",6,"흾흿힀힂",5,"힊힋큄큅큇큉큐큔큘큠크큭큰클큼큽킁키킥킨킬킴킵킷킹타탁탄탈탉탐탑탓탔탕태택탠탤탬탭탯탰탱탸턍터턱턴털턺텀텁텃텄텅테텍텐텔템텝텟텡텨텬텼톄톈토톡톤톨톰톱톳통톺톼퇀퇘퇴퇸툇툉툐투툭툰툴툼툽툿퉁퉈퉜"],["c641","힍힎힏힑",6,"힚힜힞",5],["c6a1","퉤튀튁튄튈튐튑튕튜튠튤튬튱트특튼튿틀틂틈틉틋틔틘틜틤틥티틱틴틸팀팁팃팅파팍팎판팔팖팜팝팟팠팡팥패팩팬팰팸팹팻팼팽퍄퍅퍼퍽펀펄펌펍펏펐펑페펙펜펠펨펩펫펭펴편펼폄폅폈평폐폘폡폣포폭폰폴폼폽폿퐁"],["c7a1","퐈퐝푀푄표푠푤푭푯푸푹푼푿풀풂품풉풋풍풔풩퓌퓐퓔퓜퓟퓨퓬퓰퓸퓻퓽프픈플픔픕픗피픽핀필핌핍핏핑하학한할핥함합핫항해핵핸핼햄햅햇했행햐향허헉헌헐헒험헙헛헝헤헥헨헬헴헵헷헹혀혁현혈혐협혓혔형혜혠"],["c8a1","혤혭호혹혼홀홅홈홉홋홍홑화확환활홧황홰홱홴횃횅회획횐횔횝횟횡효횬횰횹횻후훅훈훌훑훔훗훙훠훤훨훰훵훼훽휀휄휑휘휙휜휠휨휩휫휭휴휵휸휼흄흇흉흐흑흔흖흗흘흙흠흡흣흥흩희흰흴흼흽힁히힉힌힐힘힙힛힝"],["caa1","伽佳假價加可呵哥嘉嫁家暇架枷柯歌珂痂稼苛茄街袈訶賈跏軻迦駕刻却各恪慤殼珏脚覺角閣侃刊墾奸姦干幹懇揀杆柬桿澗癎看磵稈竿簡肝艮艱諫間乫喝曷渴碣竭葛褐蝎鞨勘坎堪嵌感憾戡敢柑橄減甘疳監瞰紺邯鑑鑒龕"],["cba1","匣岬甲胛鉀閘剛堈姜岡崗康强彊慷江畺疆糠絳綱羌腔舡薑襁講鋼降鱇介价個凱塏愷愾慨改槪漑疥皆盖箇芥蓋豈鎧開喀客坑更粳羹醵倨去居巨拒据據擧渠炬祛距踞車遽鉅鋸乾件健巾建愆楗腱虔蹇鍵騫乞傑杰桀儉劍劒檢"],["cca1","瞼鈐黔劫怯迲偈憩揭擊格檄激膈覡隔堅牽犬甄絹繭肩見譴遣鵑抉決潔結缺訣兼慊箝謙鉗鎌京俓倞傾儆勁勍卿坰境庚徑慶憬擎敬景暻更梗涇炅烱璟璥瓊痙硬磬竟競絅經耕耿脛莖警輕逕鏡頃頸驚鯨係啓堺契季屆悸戒桂械"],["cda1","棨溪界癸磎稽系繫繼計誡谿階鷄古叩告呱固姑孤尻庫拷攷故敲暠枯槁沽痼皐睾稿羔考股膏苦苽菰藁蠱袴誥賈辜錮雇顧高鼓哭斛曲梏穀谷鵠困坤崑昆梱棍滾琨袞鯤汨滑骨供公共功孔工恐恭拱控攻珙空蚣貢鞏串寡戈果瓜"],["cea1","科菓誇課跨過鍋顆廓槨藿郭串冠官寬慣棺款灌琯瓘管罐菅觀貫關館刮恝括适侊光匡壙廣曠洸炚狂珖筐胱鑛卦掛罫乖傀塊壞怪愧拐槐魁宏紘肱轟交僑咬喬嬌嶠巧攪敎校橋狡皎矯絞翹膠蕎蛟較轎郊餃驕鮫丘久九仇俱具勾"],["cfa1","區口句咎嘔坵垢寇嶇廐懼拘救枸柩構歐毆毬求溝灸狗玖球瞿矩究絿耉臼舅舊苟衢謳購軀逑邱鉤銶駒驅鳩鷗龜國局菊鞠鞫麴君窘群裙軍郡堀屈掘窟宮弓穹窮芎躬倦券勸卷圈拳捲權淃眷厥獗蕨蹶闕机櫃潰詭軌饋句晷歸貴"],["d0a1","鬼龜叫圭奎揆槻珪硅窺竅糾葵規赳逵閨勻均畇筠菌鈞龜橘克剋劇戟棘極隙僅劤勤懃斤根槿瑾筋芹菫覲謹近饉契今妗擒昑檎琴禁禽芩衾衿襟金錦伋及急扱汲級給亘兢矜肯企伎其冀嗜器圻基埼夔奇妓寄岐崎己幾忌技旗旣"],["d1a1","朞期杞棋棄機欺氣汽沂淇玘琦琪璂璣畸畿碁磯祁祇祈祺箕紀綺羈耆耭肌記譏豈起錡錤飢饑騎騏驥麒緊佶吉拮桔金喫儺喇奈娜懦懶拏拿癩",5,"那樂",4,"諾酪駱亂卵暖欄煖爛蘭難鸞捏捺南嵐枏楠湳濫男藍襤拉"],["d2a1","納臘蠟衲囊娘廊",4,"乃來內奈柰耐冷女年撚秊念恬拈捻寧寗努勞奴弩怒擄櫓爐瑙盧",5,"駑魯",10,"濃籠聾膿農惱牢磊腦賂雷尿壘",7,"嫩訥杻紐勒",5,"能菱陵尼泥匿溺多茶"],["d3a1","丹亶但單團壇彖斷旦檀段湍短端簞緞蛋袒鄲鍛撻澾獺疸達啖坍憺擔曇淡湛潭澹痰聃膽蕁覃談譚錟沓畓答踏遝唐堂塘幢戇撞棠當糖螳黨代垈坮大對岱帶待戴擡玳臺袋貸隊黛宅德悳倒刀到圖堵塗導屠島嶋度徒悼挑掉搗桃"],["d4a1","棹櫂淘渡滔濤燾盜睹禱稻萄覩賭跳蹈逃途道都鍍陶韜毒瀆牘犢獨督禿篤纛讀墩惇敦旽暾沌焞燉豚頓乭突仝冬凍動同憧東桐棟洞潼疼瞳童胴董銅兜斗杜枓痘竇荳讀豆逗頭屯臀芚遁遯鈍得嶝橙燈登等藤謄鄧騰喇懶拏癩羅"],["d5a1","蘿螺裸邏樂洛烙珞絡落諾酪駱丹亂卵欄欒瀾爛蘭鸞剌辣嵐擥攬欖濫籃纜藍襤覽拉臘蠟廊朗浪狼琅瑯螂郞來崍徠萊冷掠略亮倆兩凉梁樑粮粱糧良諒輛量侶儷勵呂廬慮戾旅櫚濾礪藜蠣閭驢驪麗黎力曆歷瀝礫轢靂憐戀攣漣"],["d6a1","煉璉練聯蓮輦連鍊冽列劣洌烈裂廉斂殮濂簾獵令伶囹寧岺嶺怜玲笭羚翎聆逞鈴零靈領齡例澧禮醴隷勞怒撈擄櫓潞瀘爐盧老蘆虜路輅露魯鷺鹵碌祿綠菉錄鹿麓論壟弄朧瀧瓏籠聾儡瀨牢磊賂賚賴雷了僚寮廖料燎療瞭聊蓼"],["d7a1","遼鬧龍壘婁屢樓淚漏瘻累縷蔞褸鏤陋劉旒柳榴流溜瀏琉瑠留瘤硫謬類六戮陸侖倫崙淪綸輪律慄栗率隆勒肋凜凌楞稜綾菱陵俚利厘吏唎履悧李梨浬犁狸理璃異痢籬罹羸莉裏裡里釐離鯉吝潾燐璘藺躪隣鱗麟林淋琳臨霖砬"],["d8a1","立笠粒摩瑪痲碼磨馬魔麻寞幕漠膜莫邈万卍娩巒彎慢挽晩曼滿漫灣瞞萬蔓蠻輓饅鰻唜抹末沫茉襪靺亡妄忘忙望網罔芒茫莽輞邙埋妹媒寐昧枚梅每煤罵買賣邁魅脈貊陌驀麥孟氓猛盲盟萌冪覓免冕勉棉沔眄眠綿緬面麵滅"],["d9a1","蔑冥名命明暝椧溟皿瞑茗蓂螟酩銘鳴袂侮冒募姆帽慕摸摹暮某模母毛牟牡瑁眸矛耗芼茅謀謨貌木沐牧目睦穆鶩歿沒夢朦蒙卯墓妙廟描昴杳渺猫竗苗錨務巫憮懋戊拇撫无楙武毋無珷畝繆舞茂蕪誣貿霧鵡墨默們刎吻問文"],["daa1","汶紊紋聞蚊門雯勿沕物味媚尾嵋彌微未梶楣渼湄眉米美薇謎迷靡黴岷悶愍憫敏旻旼民泯玟珉緡閔密蜜謐剝博拍搏撲朴樸泊珀璞箔粕縛膊舶薄迫雹駁伴半反叛拌搬攀斑槃泮潘班畔瘢盤盼磐磻礬絆般蟠返頒飯勃拔撥渤潑"],["dba1","發跋醱鉢髮魃倣傍坊妨尨幇彷房放方旁昉枋榜滂磅紡肪膀舫芳蒡蚌訪謗邦防龐倍俳北培徘拜排杯湃焙盃背胚裴裵褙賠輩配陪伯佰帛柏栢白百魄幡樊煩燔番磻繁蕃藩飜伐筏罰閥凡帆梵氾汎泛犯範范法琺僻劈壁擘檗璧癖"],["dca1","碧蘗闢霹便卞弁變辨辯邊別瞥鱉鼈丙倂兵屛幷昞昺柄棅炳甁病秉竝輧餠騈保堡報寶普步洑湺潽珤甫菩補褓譜輔伏僕匐卜宓復服福腹茯蔔複覆輹輻馥鰒本乶俸奉封峯峰捧棒烽熢琫縫蓬蜂逢鋒鳳不付俯傅剖副否咐埠夫婦"],["dda1","孚孵富府復扶敷斧浮溥父符簿缶腐腑膚艀芙莩訃負賦賻赴趺部釜阜附駙鳧北分吩噴墳奔奮忿憤扮昐汾焚盆粉糞紛芬賁雰不佛弗彿拂崩朋棚硼繃鵬丕備匕匪卑妃婢庇悲憊扉批斐枇榧比毖毗毘沸泌琵痺砒碑秕秘粃緋翡肥"],["dea1","脾臂菲蜚裨誹譬費鄙非飛鼻嚬嬪彬斌檳殯浜濱瀕牝玭貧賓頻憑氷聘騁乍事些仕伺似使俟僿史司唆嗣四士奢娑寫寺射巳師徙思捨斜斯柶査梭死沙泗渣瀉獅砂社祀祠私篩紗絲肆舍莎蓑蛇裟詐詞謝賜赦辭邪飼駟麝削數朔索"],["dfa1","傘刪山散汕珊産疝算蒜酸霰乷撒殺煞薩三參杉森渗芟蔘衫揷澁鈒颯上傷像償商喪嘗孀尙峠常床庠廂想桑橡湘爽牀狀相祥箱翔裳觴詳象賞霜塞璽賽嗇塞穡索色牲生甥省笙墅壻嶼序庶徐恕抒捿敍暑曙書栖棲犀瑞筮絮緖署"],["e0a1","胥舒薯西誓逝鋤黍鼠夕奭席惜昔晳析汐淅潟石碩蓆釋錫仙僊先善嬋宣扇敾旋渲煽琁瑄璇璿癬禪線繕羨腺膳船蘚蟬詵跣選銑鐥饍鮮卨屑楔泄洩渫舌薛褻設說雪齧剡暹殲纖蟾贍閃陝攝涉燮葉城姓宬性惺成星晟猩珹盛省筬"],["e1a1","聖聲腥誠醒世勢歲洗稅笹細說貰召嘯塑宵小少巢所掃搔昭梳沼消溯瀟炤燒甦疏疎瘙笑篠簫素紹蔬蕭蘇訴逍遡邵銷韶騷俗屬束涑粟續謖贖速孫巽損蓀遜飡率宋悚松淞訟誦送頌刷殺灑碎鎖衰釗修受嗽囚垂壽嫂守岫峀帥愁"],["e2a1","戍手授搜收數樹殊水洙漱燧狩獸琇璲瘦睡秀穗竪粹綏綬繡羞脩茱蒐蓚藪袖誰讐輸遂邃酬銖銹隋隧隨雖需須首髓鬚叔塾夙孰宿淑潚熟琡璹肅菽巡徇循恂旬栒楯橓殉洵淳珣盾瞬筍純脣舜荀蓴蕣詢諄醇錞順馴戌術述鉥崇崧"],["e3a1","嵩瑟膝蝨濕拾習褶襲丞乘僧勝升承昇繩蠅陞侍匙嘶始媤尸屎屍市弑恃施是時枾柴猜矢示翅蒔蓍視試詩諡豕豺埴寔式息拭植殖湜熄篒蝕識軾食飾伸侁信呻娠宸愼新晨燼申神紳腎臣莘薪藎蜃訊身辛辰迅失室實悉審尋心沁"],["e4a1","沈深瀋甚芯諶什十拾雙氏亞俄兒啞娥峨我牙芽莪蛾衙訝阿雅餓鴉鵝堊岳嶽幄惡愕握樂渥鄂鍔顎鰐齷安岸按晏案眼雁鞍顔鮟斡謁軋閼唵岩巖庵暗癌菴闇壓押狎鴨仰央怏昻殃秧鴦厓哀埃崖愛曖涯碍艾隘靄厄扼掖液縊腋額"],["e5a1","櫻罌鶯鸚也倻冶夜惹揶椰爺耶若野弱掠略約若葯蒻藥躍亮佯兩凉壤孃恙揚攘敭暘梁楊樣洋瀁煬痒瘍禳穰糧羊良襄諒讓釀陽量養圄御於漁瘀禦語馭魚齬億憶抑檍臆偃堰彦焉言諺孼蘖俺儼嚴奄掩淹嶪業円予余勵呂女如廬"],["e6a1","旅歟汝濾璵礖礪與艅茹輿轝閭餘驪麗黎亦力域役易曆歷疫繹譯轢逆驛嚥堧姸娟宴年延憐戀捐挻撚椽沇沿涎涓淵演漣烟然煙煉燃燕璉硏硯秊筵緣練縯聯衍軟輦蓮連鉛鍊鳶列劣咽悅涅烈熱裂說閱厭廉念捻染殮炎焰琰艶苒"],["e7a1","簾閻髥鹽曄獵燁葉令囹塋寧嶺嶸影怜映暎楹榮永泳渶潁濚瀛瀯煐營獰玲瑛瑩瓔盈穎纓羚聆英詠迎鈴鍈零霙靈領乂倪例刈叡曳汭濊猊睿穢芮藝蘂禮裔詣譽豫醴銳隸霓預五伍俉傲午吾吳嗚塢墺奧娛寤悟惡懊敖旿晤梧汚澳"],["e8a1","烏熬獒筽蜈誤鰲鼇屋沃獄玉鈺溫瑥瘟穩縕蘊兀壅擁瓮甕癰翁邕雍饔渦瓦窩窪臥蛙蝸訛婉完宛梡椀浣玩琓琬碗緩翫脘腕莞豌阮頑曰往旺枉汪王倭娃歪矮外嵬巍猥畏了僚僥凹堯夭妖姚寥寮尿嶢拗搖撓擾料曜樂橈燎燿瑤療"],["e9a1","窈窯繇繞耀腰蓼蟯要謠遙遼邀饒慾欲浴縟褥辱俑傭冗勇埇墉容庸慂榕涌湧溶熔瑢用甬聳茸蓉踊鎔鏞龍于佑偶優又友右宇寓尤愚憂旴牛玗瑀盂祐禑禹紆羽芋藕虞迂遇郵釪隅雨雩勖彧旭昱栯煜稶郁頊云暈橒殞澐熉耘芸蕓"],["eaa1","運隕雲韻蔚鬱亐熊雄元原員圓園垣媛嫄寃怨愿援沅洹湲源爰猿瑗苑袁轅遠阮院願鴛月越鉞位偉僞危圍委威尉慰暐渭爲瑋緯胃萎葦蔿蝟衛褘謂違韋魏乳侑儒兪劉唯喩孺宥幼幽庾悠惟愈愉揄攸有杻柔柚柳楡楢油洧流游溜"],["eba1","濡猶猷琉瑜由留癒硫紐維臾萸裕誘諛諭踰蹂遊逾遺酉釉鍮類六堉戮毓肉育陸倫允奫尹崙淪潤玧胤贇輪鈗閏律慄栗率聿戎瀜絨融隆垠恩慇殷誾銀隱乙吟淫蔭陰音飮揖泣邑凝應膺鷹依倚儀宜意懿擬椅毅疑矣義艤薏蟻衣誼"],["eca1","議醫二以伊利吏夷姨履已弛彛怡易李梨泥爾珥理異痍痢移罹而耳肄苡荑裏裡貽貳邇里離飴餌匿溺瀷益翊翌翼謚人仁刃印吝咽因姻寅引忍湮燐璘絪茵藺蚓認隣靭靷鱗麟一佚佾壹日溢逸鎰馹任壬妊姙恁林淋稔臨荏賃入卄"],["eda1","立笠粒仍剩孕芿仔刺咨姉姿子字孜恣慈滋炙煮玆瓷疵磁紫者自茨蔗藉諮資雌作勺嚼斫昨灼炸爵綽芍酌雀鵲孱棧殘潺盞岑暫潛箴簪蠶雜丈仗匠場墻壯奬將帳庄張掌暲杖樟檣欌漿牆狀獐璋章粧腸臟臧莊葬蔣薔藏裝贓醬長"],["eea1","障再哉在宰才材栽梓渽滓災縡裁財載齋齎爭箏諍錚佇低儲咀姐底抵杵楮樗沮渚狙猪疽箸紵苧菹著藷詛貯躇這邸雎齟勣吊嫡寂摘敵滴狄炙的積笛籍績翟荻謫賊赤跡蹟迪迹適鏑佃佺傳全典前剪塡塼奠專展廛悛戰栓殿氈澱"],["efa1","煎琠田甸畑癲筌箋箭篆纏詮輾轉鈿銓錢鐫電顚顫餞切截折浙癤竊節絶占岾店漸点粘霑鮎點接摺蝶丁井亭停偵呈姃定幀庭廷征情挺政整旌晶晸柾楨檉正汀淀淨渟湞瀞炡玎珽町睛碇禎程穽精綎艇訂諪貞鄭酊釘鉦鋌錠霆靖"],["f0a1","靜頂鼎制劑啼堤帝弟悌提梯濟祭第臍薺製諸蹄醍除際霽題齊俎兆凋助嘲弔彫措操早晁曺曹朝條棗槽漕潮照燥爪璪眺祖祚租稠窕粗糟組繰肇藻蚤詔調趙躁造遭釣阻雕鳥族簇足鏃存尊卒拙猝倧宗從悰慫棕淙琮種終綜縱腫"],["f1a1","踪踵鍾鐘佐坐左座挫罪主住侏做姝胄呪周嗾奏宙州廚晝朱柱株注洲湊澍炷珠疇籌紂紬綢舟蛛註誅走躊輳週酎酒鑄駐竹粥俊儁准埈寯峻晙樽浚準濬焌畯竣蠢逡遵雋駿茁中仲衆重卽櫛楫汁葺增憎曾拯烝甑症繒蒸證贈之只"],["f2a1","咫地址志持指摯支旨智枝枳止池沚漬知砥祉祗紙肢脂至芝芷蜘誌識贄趾遲直稙稷織職唇嗔塵振搢晉晋桭榛殄津溱珍瑨璡畛疹盡眞瞋秦縉縝臻蔯袗診賑軫辰進鎭陣陳震侄叱姪嫉帙桎瓆疾秩窒膣蛭質跌迭斟朕什執潗緝輯"],["f3a1","鏶集徵懲澄且侘借叉嗟嵯差次此磋箚茶蹉車遮捉搾着窄錯鑿齪撰澯燦璨瓚竄簒纂粲纘讚贊鑽餐饌刹察擦札紮僭參塹慘慙懺斬站讒讖倉倡創唱娼廠彰愴敞昌昶暢槍滄漲猖瘡窓脹艙菖蒼債埰寀寨彩採砦綵菜蔡采釵冊柵策"],["f4a1","責凄妻悽處倜刺剔尺慽戚拓擲斥滌瘠脊蹠陟隻仟千喘天川擅泉淺玔穿舛薦賤踐遷釧闡阡韆凸哲喆徹撤澈綴輟轍鐵僉尖沾添甛瞻簽籤詹諂堞妾帖捷牒疊睫諜貼輒廳晴淸聽菁請靑鯖切剃替涕滯締諦逮遞體初剿哨憔抄招梢"],["f5a1","椒楚樵炒焦硝礁礎秒稍肖艸苕草蕉貂超酢醋醮促囑燭矗蜀觸寸忖村邨叢塚寵悤憁摠總聰蔥銃撮催崔最墜抽推椎楸樞湫皺秋芻萩諏趨追鄒酋醜錐錘鎚雛騶鰍丑畜祝竺筑築縮蓄蹙蹴軸逐春椿瑃出朮黜充忠沖蟲衝衷悴膵萃"],["f6a1","贅取吹嘴娶就炊翠聚脆臭趣醉驟鷲側仄厠惻測層侈値嗤峙幟恥梔治淄熾痔痴癡稚穉緇緻置致蚩輜雉馳齒則勅飭親七柒漆侵寢枕沈浸琛砧針鍼蟄秤稱快他咤唾墮妥惰打拖朶楕舵陀馱駝倬卓啄坼度托拓擢晫柝濁濯琢琸託"],["f7a1","鐸呑嘆坦彈憚歎灘炭綻誕奪脫探眈耽貪塔搭榻宕帑湯糖蕩兌台太怠態殆汰泰笞胎苔跆邰颱宅擇澤撑攄兎吐土討慟桶洞痛筒統通堆槌腿褪退頹偸套妬投透鬪慝特闖坡婆巴把播擺杷波派爬琶破罷芭跛頗判坂板版瓣販辦鈑"],["f8a1","阪八叭捌佩唄悖敗沛浿牌狽稗覇貝彭澎烹膨愎便偏扁片篇編翩遍鞭騙貶坪平枰萍評吠嬖幣廢弊斃肺蔽閉陛佈包匍匏咆哺圃布怖抛抱捕暴泡浦疱砲胞脯苞葡蒲袍褒逋鋪飽鮑幅暴曝瀑爆輻俵剽彪慓杓標漂瓢票表豹飇飄驃"],["f9a1","品稟楓諷豊風馮彼披疲皮被避陂匹弼必泌珌畢疋筆苾馝乏逼下何厦夏廈昰河瑕荷蝦賀遐霞鰕壑學虐謔鶴寒恨悍旱汗漢澣瀚罕翰閑閒限韓割轄函含咸啣喊檻涵緘艦銜陷鹹合哈盒蛤閤闔陜亢伉姮嫦巷恒抗杭桁沆港缸肛航"],["faa1","行降項亥偕咳垓奚孩害懈楷海瀣蟹解該諧邂駭骸劾核倖幸杏荇行享向嚮珦鄕響餉饗香噓墟虛許憲櫶獻軒歇險驗奕爀赫革俔峴弦懸晛泫炫玄玹現眩睍絃絢縣舷衒見賢鉉顯孑穴血頁嫌俠協夾峽挾浹狹脅脇莢鋏頰亨兄刑型"],["fba1","形泂滎瀅灐炯熒珩瑩荊螢衡逈邢鎣馨兮彗惠慧暳蕙蹊醯鞋乎互呼壕壺好岵弧戶扈昊晧毫浩淏湖滸澔濠濩灝狐琥瑚瓠皓祜糊縞胡芦葫蒿虎號蝴護豪鎬頀顥惑或酷婚昏混渾琿魂忽惚笏哄弘汞泓洪烘紅虹訌鴻化和嬅樺火畵"],["fca1","禍禾花華話譁貨靴廓擴攫確碻穫丸喚奐宦幻患換歡晥桓渙煥環紈還驩鰥活滑猾豁闊凰幌徨恍惶愰慌晃晄榥況湟滉潢煌璜皇篁簧荒蝗遑隍黃匯回廻徊恢悔懷晦會檜淮澮灰獪繪膾茴蛔誨賄劃獲宖橫鐄哮嚆孝效斅曉梟涍淆"],["fda1","爻肴酵驍侯候厚后吼喉嗅帿後朽煦珝逅勛勳塤壎焄熏燻薰訓暈薨喧暄煊萱卉喙毁彙徽揮暉煇諱輝麾休携烋畦虧恤譎鷸兇凶匈洶胸黑昕欣炘痕吃屹紇訖欠欽歆吸恰洽翕興僖凞喜噫囍姬嬉希憙憘戱晞曦熙熹熺犧禧稀羲詰"]]},256:function(module){module.exports=eval("require")("iconv")},293:function(e){e.exports=__webpack_require__("NkYg")},304:function(e){e.exports=__webpack_require__("tlh6")},317:function(e){"use strict";e.exports={10029:"maccenteuro",maccenteuro:{type:"_sbcs",chars:"ÄĀāÉĄÖÜáąČäčĆćéŹźĎíďĒēĖóėôöõúĚěü†°Ę£§•¶ß®©™ę¨≠ģĮįĪ≤≥īĶ∂∑łĻļĽľĹĺŅņŃ¬√ńŇ∆«»… ňŐÕőŌ–—“”‘’÷◊ōŔŕŘ‹›řŖŗŠ‚„šŚśÁŤťÍŽžŪÓÔūŮÚůŰűŲųÝýķŻŁżĢˇ"},808:"cp808",ibm808:"cp808",cp808:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№€■ "},mik:{type:"_sbcs",chars:"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя└┴┬├─┼╣║╚╔╩╦╠═╬┐░▒▓│┤№§╗╝┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "},ascii8bit:"ascii",usascii:"ascii",ansix34:"ascii",ansix341968:"ascii",ansix341986:"ascii",csascii:"ascii",cp367:"ascii",ibm367:"ascii",isoir6:"ascii",iso646us:"ascii",iso646irv:"ascii",us:"ascii",latin1:"iso88591",latin2:"iso88592",latin3:"iso88593",latin4:"iso88594",latin5:"iso88599",latin6:"iso885910",latin7:"iso885913",latin8:"iso885914",latin9:"iso885915",latin10:"iso885916",csisolatin1:"iso88591",csisolatin2:"iso88592",csisolatin3:"iso88593",csisolatin4:"iso88594",csisolatincyrillic:"iso88595",csisolatinarabic:"iso88596",csisolatingreek:"iso88597",csisolatinhebrew:"iso88598",csisolatin5:"iso88599",csisolatin6:"iso885910",l1:"iso88591",l2:"iso88592",l3:"iso88593",l4:"iso88594",l5:"iso88599",l6:"iso885910",l7:"iso885913",l8:"iso885914",l9:"iso885915",l10:"iso885916",isoir14:"iso646jp",isoir57:"iso646cn",isoir100:"iso88591",isoir101:"iso88592",isoir109:"iso88593",isoir110:"iso88594",isoir144:"iso88595",isoir127:"iso88596",isoir126:"iso88597",isoir138:"iso88598",isoir148:"iso88599",isoir157:"iso885910",isoir166:"tis620",isoir179:"iso885913",isoir199:"iso885914",isoir203:"iso885915",isoir226:"iso885916",cp819:"iso88591",ibm819:"iso88591",cyrillic:"iso88595",arabic:"iso88596",arabic8:"iso88596",ecma114:"iso88596",asmo708:"iso88596",greek:"iso88597",greek8:"iso88597",ecma118:"iso88597",elot928:"iso88597",hebrew:"iso88598",hebrew8:"iso88598",turkish:"iso88599",turkish8:"iso88599",thai:"iso885911",thai8:"iso885911",celtic:"iso885914",celtic8:"iso885914",isoceltic:"iso885914",tis6200:"tis620",tis62025291:"tis620",tis62025330:"tis620",10000:"macroman",10006:"macgreek",10007:"maccyrillic",10079:"maciceland",10081:"macturkish",cspc8codepage437:"cp437",cspc775baltic:"cp775",cspc850multilingual:"cp850",cspcp852:"cp852",cspc862latinhebrew:"cp862",cpgr:"cp869",msee:"cp1250",mscyrl:"cp1251",msansi:"cp1252",msgreek:"cp1253",msturk:"cp1254",mshebr:"cp1255",msarab:"cp1256",winbaltrim:"cp1257",cp20866:"koi8r",20866:"koi8r",ibm878:"koi8r",cskoi8r:"koi8r",cp21866:"koi8u",21866:"koi8u",ibm1168:"koi8u",strk10482002:"rk1048",tcvn5712:"tcvn",tcvn57121:"tcvn",gb198880:"iso646cn",cn:"iso646cn",csiso14jisc6220ro:"iso646jp",jisc62201969ro:"iso646jp",jp:"iso646jp",cshproman8:"hproman8",r8:"hproman8",roman8:"hproman8",xroman8:"hproman8",ibm1051:"hproman8",mac:"macintosh",csmacintosh:"macintosh"}},413:function(e){e.exports=__webpack_require__("msIP")},422:function(e,t,n){"use strict";var i=n(986).Buffer;e.exports={utf8:{type:"_internal",bomAware:true},cesu8:{type:"_internal",bomAware:true},unicode11utf8:"utf8",ucs2:{type:"_internal",bomAware:true},utf16le:"ucs2",binary:{type:"_internal"},base64:{type:"_internal"},hex:{type:"_internal"},_internal:InternalCodec};function InternalCodec(e,t){this.enc=e.encodingName;this.bomAware=e.bomAware;if(this.enc==="base64")this.encoder=InternalEncoderBase64;else if(this.enc==="cesu8"){this.enc="utf8";this.encoder=InternalEncoderCesu8;if(i.from("eda0bdedb2a9","hex").toString()!=="💩"){this.decoder=InternalDecoderCesu8;this.defaultCharUnicode=t.defaultCharUnicode}}}InternalCodec.prototype.encoder=InternalEncoder;InternalCodec.prototype.decoder=InternalDecoder;var o=n(304).StringDecoder;if(!o.prototype.end)o.prototype.end=function(){};function InternalDecoder(e,t){o.call(this,t.enc)}InternalDecoder.prototype=o.prototype;function InternalEncoder(e,t){this.enc=t.enc}InternalEncoder.prototype.write=function(e){return i.from(e,this.enc)};InternalEncoder.prototype.end=function(){};function InternalEncoderBase64(e,t){this.prevStr=""}InternalEncoderBase64.prototype.write=function(e){e=this.prevStr+e;var t=e.length-e.length%4;this.prevStr=e.slice(t);e=e.slice(0,t);return i.from(e,"base64")};InternalEncoderBase64.prototype.end=function(){return i.from(this.prevStr,"base64")};function InternalEncoderCesu8(e,t){}InternalEncoderCesu8.prototype.write=function(e){var t=i.alloc(e.length*3),n=0;for(var o=0;o<e.length;o++){var r=e.charCodeAt(o);if(r<128)t[n++]=r;else if(r<2048){t[n++]=192+(r>>>6);t[n++]=128+(r&63)}else{t[n++]=224+(r>>>12);t[n++]=128+(r>>>6&63);t[n++]=128+(r&63)}}return t.slice(0,n)};InternalEncoderCesu8.prototype.end=function(){};function InternalDecoderCesu8(e,t){this.acc=0;this.contBytes=0;this.accBytes=0;this.defaultCharUnicode=t.defaultCharUnicode}InternalDecoderCesu8.prototype.write=function(e){var t=this.acc,n=this.contBytes,i=this.accBytes,o="";for(var r=0;r<e.length;r++){var s=e[r];if((s&192)!==128){if(n>0){o+=this.defaultCharUnicode;n=0}if(s<128){o+=String.fromCharCode(s)}else if(s<224){t=s&31;n=1;i=1}else if(s<240){t=s&15;n=2;i=1}else{o+=this.defaultCharUnicode}}else{if(n>0){t=t<<6|s&63;n--;i++;if(n===0){if(i===2&&t<128&&t>0)o+=this.defaultCharUnicode;else if(i===3&&t<2048)o+=this.defaultCharUnicode;else o+=String.fromCharCode(t)}}else{o+=this.defaultCharUnicode}}}this.acc=t;this.contBytes=n;this.accBytes=i;return o};InternalDecoderCesu8.prototype.end=function(){var e=0;if(this.contBytes>0)e+=this.defaultCharUnicode;return e}},445:function(e){e.exports=[["a140","",62],["a180","",32],["a240","",62],["a280","",32],["a2ab","",5],["a2e3","€"],["a2ef",""],["a2fd",""],["a340","",62],["a380","",31,"　"],["a440","",62],["a480","",32],["a4f4","",10],["a540","",62],["a580","",32],["a5f7","",7],["a640","",62],["a680","",32],["a6b9","",7],["a6d9","",6],["a6ec",""],["a6f3",""],["a6f6","",8],["a740","",62],["a780","",32],["a7c2","",14],["a7f2","",12],["a896","",10],["a8bc",""],["a8bf","ǹ"],["a8c1",""],["a8ea","",20],["a958",""],["a95b",""],["a95d",""],["a989","〾⿰",11],["a997","",12],["a9f0","",14],["aaa1","",93],["aba1","",93],["aca1","",93],["ada1","",93],["aea1","",93],["afa1","",93],["d7fa","",4],["f8a1","",93],["f9a1","",93],["faa1","",93],["fba1","",93],["fca1","",93],["fda1","",93],["fe50","⺁⺄㑳㑇⺈⺋㖞㘚㘎⺌⺗㥮㤘㧏㧟㩳㧐㭎㱮㳠⺧⺪䁖䅟⺮䌷⺳⺶⺷䎱䎬⺻䏝䓖䙡䙌"],["fe80","䜣䜩䝼䞍⻊䥇䥺䥽䦂䦃䦅䦆䦟䦛䦷䦶䲣䲟䲠䲡䱷䲢䴓",6,"䶮",93]]},467:function(e,t,n){"use strict";var i=[n(422),n(945),n(811),n(475),n(317),n(145),n(484),n(615)];for(var o=0;o<i.length;o++){var r=i[o];for(var s in r)if(Object.prototype.hasOwnProperty.call(r,s))t[s]=r[s]}},475:function(e,t,n){"use strict";var i=n(986).Buffer;t._sbcs=SBCSCodec;function SBCSCodec(e,t){if(!e)throw new Error("SBCS codec is called without the data.");if(!e.chars||e.chars.length!==128&&e.chars.length!==256)throw new Error("Encoding '"+e.type+"' has incorrect 'chars' (must be of len 128 or 256)");if(e.chars.length===128){var n="";for(var o=0;o<128;o++)n+=String.fromCharCode(o);e.chars=n+e.chars}this.decodeBuf=i.from(e.chars,"ucs2");var r=i.alloc(65536,t.defaultCharSingleByte.charCodeAt(0));for(var o=0;o<e.chars.length;o++)r[e.chars.charCodeAt(o)]=o;this.encodeBuf=r}SBCSCodec.prototype.encoder=SBCSEncoder;SBCSCodec.prototype.decoder=SBCSDecoder;function SBCSEncoder(e,t){this.encodeBuf=t.encodeBuf}SBCSEncoder.prototype.write=function(e){var t=i.alloc(e.length);for(var n=0;n<e.length;n++)t[n]=this.encodeBuf[e.charCodeAt(n)];return t};SBCSEncoder.prototype.end=function(){};function SBCSDecoder(e,t){this.decodeBuf=t.decodeBuf}SBCSDecoder.prototype.write=function(e){var t=this.decodeBuf;var n=i.alloc(e.length*2);var o=0,r=0;for(var s=0;s<e.length;s++){o=e[s]*2;r=s*2;n[r]=t[o];n[r+1]=t[o+1]}return n.toString("ucs2")};SBCSDecoder.prototype.end=function(){}},484:function(e,t,n){"use strict";var i=n(986).Buffer;t._dbcs=DBCSCodec;var o=-1,r=-2,s=-10,c=-1e3,a=new Array(256),f=-1;for(var h=0;h<256;h++)a[h]=o;function DBCSCodec(e,t){this.encodingName=e.encodingName;if(!e)throw new Error("DBCS codec is called without the data.");if(!e.table)throw new Error("Encoding '"+this.encodingName+"' has no data.");var n=e.table();this.decodeTables=[];this.decodeTables[0]=a.slice(0);this.decodeTableSeq=[];for(var i=0;i<n.length;i++)this._addDecodeChunk(n[i]);this.defaultCharUnicode=t.defaultCharUnicode;this.encodeTable=[];this.encodeTableSeq=[];var s={};if(e.encodeSkipVals)for(var i=0;i<e.encodeSkipVals.length;i++){var f=e.encodeSkipVals[i];if(typeof f==="number")s[f]=true;else for(var h=f.from;h<=f.to;h++)s[h]=true}this._fillEncodeTable(0,0,s);if(e.encodeAdd){for(var p in e.encodeAdd)if(Object.prototype.hasOwnProperty.call(e.encodeAdd,p))this._setEncodeChar(p.charCodeAt(0),e.encodeAdd[p])}this.defCharSB=this.encodeTable[0][t.defaultCharSingleByte.charCodeAt(0)];if(this.defCharSB===o)this.defCharSB=this.encodeTable[0]["?"];if(this.defCharSB===o)this.defCharSB="?".charCodeAt(0);if(typeof e.gb18030==="function"){this.gb18030=e.gb18030();var u=this.decodeTables.length;var l=this.decodeTables[u]=a.slice(0);var d=this.decodeTables.length;var b=this.decodeTables[d]=a.slice(0);for(var i=129;i<=254;i++){var y=c-this.decodeTables[0][i];var g=this.decodeTables[y];for(var h=48;h<=57;h++)g[h]=c-u}for(var i=129;i<=254;i++)l[i]=c-d;for(var i=48;i<=57;i++)b[i]=r}}DBCSCodec.prototype.encoder=DBCSEncoder;DBCSCodec.prototype.decoder=DBCSDecoder;DBCSCodec.prototype._getDecodeTrieNode=function(e){var t=[];for(;e>0;e>>=8)t.push(e&255);if(t.length==0)t.push(0);var n=this.decodeTables[0];for(var i=t.length-1;i>0;i--){var r=n[t[i]];if(r==o){n[t[i]]=c-this.decodeTables.length;this.decodeTables.push(n=a.slice(0))}else if(r<=c){n=this.decodeTables[c-r]}else throw new Error("Overwrite byte in "+this.encodingName+", addr: "+e.toString(16))}return n};DBCSCodec.prototype._addDecodeChunk=function(e){var t=parseInt(e[0],16);var n=this._getDecodeTrieNode(t);t=t&255;for(var i=1;i<e.length;i++){var o=e[i];if(typeof o==="string"){for(var r=0;r<o.length;){var c=o.charCodeAt(r++);if(55296<=c&&c<56320){var a=o.charCodeAt(r++);if(56320<=a&&a<57344)n[t++]=65536+(c-55296)*1024+(a-56320);else throw new Error("Incorrect surrogate pair in "+this.encodingName+" at chunk "+e[0])}else if(4080<c&&c<=4095){var f=4095-c+2;var h=[];for(var p=0;p<f;p++)h.push(o.charCodeAt(r++));n[t++]=s-this.decodeTableSeq.length;this.decodeTableSeq.push(h)}else n[t++]=c}}else if(typeof o==="number"){var u=n[t-1]+1;for(var r=0;r<o;r++)n[t++]=u++}else throw new Error("Incorrect type '"+typeof o+"' given in "+this.encodingName+" at chunk "+e[0])}if(t>255)throw new Error("Incorrect chunk in "+this.encodingName+" at addr "+e[0]+": too long"+t)};DBCSCodec.prototype._getEncodeBucket=function(e){var t=e>>8;if(this.encodeTable[t]===undefined)this.encodeTable[t]=a.slice(0);return this.encodeTable[t]};DBCSCodec.prototype._setEncodeChar=function(e,t){var n=this._getEncodeBucket(e);var i=e&255;if(n[i]<=s)this.encodeTableSeq[s-n[i]][f]=t;else if(n[i]==o)n[i]=t};DBCSCodec.prototype._setEncodeSequence=function(e,t){var n=e[0];var i=this._getEncodeBucket(n);var r=n&255;var c;if(i[r]<=s){c=this.encodeTableSeq[s-i[r]]}else{c={};if(i[r]!==o)c[f]=i[r];i[r]=s-this.encodeTableSeq.length;this.encodeTableSeq.push(c)}for(var a=1;a<e.length-1;a++){var h=c[n];if(typeof h==="object")c=h;else{c=c[n]={};if(h!==undefined)c[f]=h}}n=e[e.length-1];c[n]=t};DBCSCodec.prototype._fillEncodeTable=function(e,t,n){var i=this.decodeTables[e];for(var o=0;o<256;o++){var r=i[o];var a=t+o;if(n[a])continue;if(r>=0)this._setEncodeChar(r,a);else if(r<=c)this._fillEncodeTable(c-r,a<<8,n);else if(r<=s)this._setEncodeSequence(this.decodeTableSeq[s-r],a)}};function DBCSEncoder(e,t){this.leadSurrogate=-1;this.seqObj=undefined;this.encodeTable=t.encodeTable;this.encodeTableSeq=t.encodeTableSeq;this.defaultCharSingleByte=t.defCharSB;this.gb18030=t.gb18030}DBCSEncoder.prototype.write=function(e){var t=i.alloc(e.length*(this.gb18030?4:3)),n=this.leadSurrogate,r=this.seqObj,c=-1,a=0,h=0;while(true){if(c===-1){if(a==e.length)break;var p=e.charCodeAt(a++)}else{var p=c;c=-1}if(55296<=p&&p<57344){if(p<56320){if(n===-1){n=p;continue}else{n=p;p=o}}else{if(n!==-1){p=65536+(n-55296)*1024+(p-56320);n=-1}else{p=o}}}else if(n!==-1){c=p;p=o;n=-1}var u=o;if(r!==undefined&&p!=o){var l=r[p];if(typeof l==="object"){r=l;continue}else if(typeof l=="number"){u=l}else if(l==undefined){l=r[f];if(l!==undefined){u=l;c=p}else{}}r=undefined}else if(p>=0){var d=this.encodeTable[p>>8];if(d!==undefined)u=d[p&255];if(u<=s){r=this.encodeTableSeq[s-u];continue}if(u==o&&this.gb18030){var b=findIdx(this.gb18030.uChars,p);if(b!=-1){var u=this.gb18030.gbChars[b]+(p-this.gb18030.uChars[b]);t[h++]=129+Math.floor(u/12600);u=u%12600;t[h++]=48+Math.floor(u/1260);u=u%1260;t[h++]=129+Math.floor(u/10);u=u%10;t[h++]=48+u;continue}}}if(u===o)u=this.defaultCharSingleByte;if(u<256){t[h++]=u}else if(u<65536){t[h++]=u>>8;t[h++]=u&255}else{t[h++]=u>>16;t[h++]=u>>8&255;t[h++]=u&255}}this.seqObj=r;this.leadSurrogate=n;return t.slice(0,h)};DBCSEncoder.prototype.end=function(){if(this.leadSurrogate===-1&&this.seqObj===undefined)return;var e=i.alloc(10),t=0;if(this.seqObj){var n=this.seqObj[f];if(n!==undefined){if(n<256){e[t++]=n}else{e[t++]=n>>8;e[t++]=n&255}}else{}this.seqObj=undefined}if(this.leadSurrogate!==-1){e[t++]=this.defaultCharSingleByte;this.leadSurrogate=-1}return e.slice(0,t)};DBCSEncoder.prototype.findIdx=findIdx;function DBCSDecoder(e,t){this.nodeIdx=0;this.prevBuf=i.alloc(0);this.decodeTables=t.decodeTables;this.decodeTableSeq=t.decodeTableSeq;this.defaultCharUnicode=t.defaultCharUnicode;this.gb18030=t.gb18030}DBCSDecoder.prototype.write=function(e){var t=i.alloc(e.length*2),n=this.nodeIdx,a=this.prevBuf,f=this.prevBuf.length,h=-this.prevBuf.length,p;if(f>0)a=i.concat([a,e.slice(0,10)]);for(var u=0,l=0;u<e.length;u++){var d=u>=0?e[u]:a[u+f];var p=this.decodeTables[n][d];if(p>=0){}else if(p===o){u=h;p=this.defaultCharUnicode.charCodeAt(0)}else if(p===r){var b=h>=0?e.slice(h,u+1):a.slice(h+f,u+1+f);var y=(b[0]-129)*12600+(b[1]-48)*1260+(b[2]-129)*10+(b[3]-48);var g=findIdx(this.gb18030.gbChars,y);p=this.gb18030.uChars[g]+y-this.gb18030.gbChars[g]}else if(p<=c){n=c-p;continue}else if(p<=s){var m=this.decodeTableSeq[s-p];for(var v=0;v<m.length-1;v++){p=m[v];t[l++]=p&255;t[l++]=p>>8}p=m[m.length-1]}else throw new Error("iconv-lite internal error: invalid decoding table value "+p+" at "+n+"/"+d);if(p>65535){p-=65536;var w=55296+Math.floor(p/1024);t[l++]=w&255;t[l++]=w>>8;p=56320+p%1024}t[l++]=p&255;t[l++]=p>>8;n=0;h=u+1}this.nodeIdx=n;this.prevBuf=h>=0?e.slice(h):a.slice(h+f);return t.slice(0,l).toString("ucs2")};DBCSDecoder.prototype.end=function(){var e="";while(this.prevBuf.length>0){e+=this.defaultCharUnicode;var t=this.prevBuf.slice(1);this.prevBuf=i.alloc(0);this.nodeIdx=0;if(t.length>0)e+=this.write(t)}this.nodeIdx=0;return e};function findIdx(e,t){if(e[0]>t)return-1;var n=0,i=e.length;while(n<i-1){var o=n+Math.floor((i-n+1)/2);if(e[o]<=t)n=o;else i=o}return n}},605:function(e){e.exports=__webpack_require__("KEll")},615:function(e,t,n){"use strict";e.exports={shiftjis:{type:"_dbcs",table:function(){return n(693)},encodeAdd:{"¥":92,"‾":126},encodeSkipVals:[{from:60736,to:63808}]},csshiftjis:"shiftjis",mskanji:"shiftjis",sjis:"shiftjis",windows31j:"shiftjis",ms31j:"shiftjis",xsjis:"shiftjis",windows932:"shiftjis",ms932:"shiftjis",932:"shiftjis",cp932:"shiftjis",eucjp:{type:"_dbcs",table:function(){return n(42)},encodeAdd:{"¥":92,"‾":126}},gb2312:"cp936",gb231280:"cp936",gb23121980:"cp936",csgb2312:"cp936",csiso58gb231280:"cp936",euccn:"cp936",windows936:"cp936",ms936:"cp936",936:"cp936",cp936:{type:"_dbcs",table:function(){return n(791)}},gbk:{type:"_dbcs",table:function(){return n(791).concat(n(445))}},xgbk:"gbk",isoir58:"gbk",gb18030:{type:"_dbcs",table:function(){return n(791).concat(n(445))},gb18030:function(){return n(910)},encodeSkipVals:[128],encodeAdd:{"€":41699}},chinese:"gb18030",windows949:"cp949",ms949:"cp949",949:"cp949",cp949:{type:"_dbcs",table:function(){return n(237)}},cseuckr:"cp949",csksc56011987:"cp949",euckr:"cp949",isoir149:"cp949",korean:"cp949",ksc56011987:"cp949",ksc56011989:"cp949",ksc5601:"cp949",windows950:"cp950",ms950:"cp950",950:"cp950",cp950:{type:"_dbcs",table:function(){return n(48)}},big5:"big5hkscs",big5hkscs:{type:"_dbcs",table:function(){return n(48).concat(n(637))},encodeSkipVals:[41676]},cnbig5:"big5hkscs",csbig5:"big5hkscs",xxbig5:"big5hkscs"}},637:function(e){e.exports=[["8740","䏰䰲䘃䖦䕸𧉧䵷䖳𧲱䳢𧳅㮕䜶䝄䱇䱀𤊿𣘗𧍒𦺋𧃒䱗𪍑䝏䗚䲅𧱬䴇䪤䚡𦬣爥𥩔𡩣𣸆𣽡晍囻"],["8767","綕夝𨮹㷴霴𧯯寛𡵞媤㘥𩺰嫑宷峼杮薓𩥅瑡璝㡵𡵓𣚞𦀡㻬"],["87a1","𥣞㫵竼龗𤅡𨤍𣇪𠪊𣉞䌊蒄龖鐯䤰蘓墖靊鈘秐稲晠権袝瑌篅枂稬剏遆㓦珄𥶹瓆鿇垳䤯呌䄱𣚎堘穲𧭥讏䚮𦺈䆁𥶙箮𢒼鿈𢓁𢓉𢓌鿉蔄𣖻䂴鿊䓡𪷿拁灮鿋"],["8840","㇀",4,"𠄌㇅𠃑𠃍㇆㇇𠃋𡿨㇈𠃊㇉㇊㇋㇌𠄎㇍㇎ĀÁǍÀĒÉĚÈŌÓǑÒ࿿Ê̄Ế࿿Ê̌ỀÊāáǎàɑēéěèīíǐìōóǒòūúǔùǖǘǚ"],["88a1","ǜü࿿ê̄ế࿿ê̌ềêɡ⏚⏛"],["8940","𪎩𡅅"],["8943","攊"],["8946","丽滝鵎釟"],["894c","𧜵撑会伨侨兖兴农凤务动医华发变团声处备夲头学实実岚庆总斉柾栄桥济炼电纤纬纺织经统缆缷艺苏药视设询车轧轮"],["89a1","琑糼緍楆竉刧"],["89ab","醌碸酞肼"],["89b0","贋胶𠧧"],["89b5","肟黇䳍鷉鸌䰾𩷶𧀎鸊𪄳㗁"],["89c1","溚舾甙"],["89c5","䤑马骏龙禇𨑬𡷊𠗐𢫦两亁亀亇亿仫伷㑌侽㹈倃傈㑽㒓㒥円夅凛凼刅争剹劐匧㗇厩㕑厰㕓参吣㕭㕲㚁咓咣咴咹哐哯唘唣唨㖘唿㖥㖿嗗㗅"],["8a40","𧶄唥"],["8a43","𠱂𠴕𥄫喐𢳆㧬𠍁蹆𤶸𩓥䁓𨂾睺𢰸㨴䟕𨅝𦧲𤷪擝𠵼𠾴𠳕𡃴撍蹾𠺖𠰋𠽤𢲩𨉖𤓓"],["8a64","𠵆𩩍𨃩䟴𤺧𢳂骲㩧𩗴㿭㔆𥋇𩟔𧣈𢵄鵮頕"],["8a76","䏙𦂥撴哣𢵌𢯊𡁷㧻𡁯"],["8aa1","𦛚𦜖𧦠擪𥁒𠱃蹨𢆡𨭌𠜱"],["8aac","䠋𠆩㿺塳𢶍"],["8ab2","𤗈𠓼𦂗𠽌𠶖啹䂻䎺"],["8abb","䪴𢩦𡂝膪飵𠶜捹㧾𢝵跀嚡摼㹃"],["8ac9","𪘁𠸉𢫏𢳉"],["8ace","𡃈𣧂㦒㨆𨊛㕸𥹉𢃇噒𠼱𢲲𩜠㒼氽𤸻"],["8adf","𧕴𢺋𢈈𪙛𨳍𠹺𠰴𦠜羓𡃏𢠃𢤹㗻𥇣𠺌𠾍𠺪㾓𠼰𠵇𡅏𠹌"],["8af6","𠺫𠮩𠵈𡃀𡄽㿹𢚖搲𠾭"],["8b40","𣏴𧘹𢯎𠵾𠵿𢱑𢱕㨘𠺘𡃇𠼮𪘲𦭐𨳒𨶙𨳊閪哌苄喹"],["8b55","𩻃鰦骶𧝞𢷮煀腭胬尜𦕲脴㞗卟𨂽醶𠻺𠸏𠹷𠻻㗝𤷫㘉𠳖嚯𢞵𡃉𠸐𠹸𡁸𡅈𨈇𡑕𠹹𤹐𢶤婔𡀝𡀞𡃵𡃶垜𠸑"],["8ba1","𧚔𨋍𠾵𠹻𥅾㜃𠾶𡆀𥋘𪊽𤧚𡠺𤅷𨉼墙剨㘚𥜽箲孨䠀䬬鼧䧧鰟鮍𥭴𣄽嗻㗲嚉丨夂𡯁屮靑𠂆乛亻㔾尣彑忄㣺扌攵歺氵氺灬爫丬犭𤣩罒礻糹罓𦉪㓁"],["8bde","𦍋耂肀𦘒𦥑卝衤见𧢲讠贝钅镸长门𨸏韦页风飞饣𩠐鱼鸟黄歯龜丷𠂇阝户钢"],["8c40","倻淾𩱳龦㷉袏𤅎灷峵䬠𥇍㕙𥴰愢𨨲辧釶熑朙玺𣊁𪄇㲋𡦀䬐磤琂冮𨜏䀉橣𪊺䈣蘏𠩯稪𩥇𨫪靕灍匤𢁾鏴盙𨧣龧矝亣俰傼丯众龨吴綋墒壐𡶶庒庙忂𢜒斋"],["8ca1","𣏹椙橃𣱣泿"],["8ca7","爀𤔅玌㻛𤨓嬕璹讃𥲤𥚕窓篬糃繬苸薗龩袐龪躹龫迏蕟駠鈡龬𨶹𡐿䁱䊢娚"],["8cc9","顨杫䉶圽"],["8cce","藖𤥻芿𧄍䲁𦵴嵻𦬕𦾾龭龮宖龯曧繛湗秊㶈䓃𣉖𢞖䎚䔶"],["8ce6","峕𣬚諹屸㴒𣕑嵸龲煗䕘𤃬𡸣䱷㥸㑊𠆤𦱁諌侴𠈹妿腬顖𩣺弻"],["8d40","𠮟"],["8d42","𢇁𨥭䄂䚻𩁹㼇龳𪆵䃸㟖䛷𦱆䅼𨚲𧏿䕭㣔𥒚䕡䔛䶉䱻䵶䗪㿈𤬏㙡䓞䒽䇭崾嵈嵖㷼㠏嶤嶹㠠㠸幂庽弥徃㤈㤔㤿㥍惗愽峥㦉憷憹懏㦸戬抐拥挘㧸嚱"],["8da1","㨃揢揻搇摚㩋擀崕嘡龟㪗斆㪽旿晓㫲暒㬢朖㭂枤栀㭘桊梄㭲㭱㭻椉楃牜楤榟榅㮼槖㯝橥橴橱檂㯬檙㯲檫檵櫔櫶殁毁毪汵沪㳋洂洆洦涁㳯涤涱渕渘温溆𨧀溻滢滚齿滨滩漤漴㵆𣽁澁澾㵪㵵熷岙㶊瀬㶑灐灔灯灿炉𠌥䏁㗱𠻘"],["8e40","𣻗垾𦻓焾𥟠㙎榢𨯩孴穉𥣡𩓙穥穽𥦬窻窰竂竃燑𦒍䇊竚竝竪䇯咲𥰁笋筕笩𥌎𥳾箢筯莜𥮴𦱿篐萡箒箸𥴠㶭𥱥蒒篺簆簵𥳁籄粃𤢂粦晽𤕸糉糇糦籴糳糵糎"],["8ea1","繧䔝𦹄絝𦻖璍綉綫焵綳緒𤁗𦀩緤㴓緵𡟹緥𨍭縝𦄡𦅚繮纒䌫鑬縧罀罁罇礶𦋐駡羗𦍑羣𡙡𠁨䕜𣝦䔃𨌺翺𦒉者耈耝耨耯𪂇𦳃耻耼聡𢜔䦉𦘦𣷣𦛨朥肧𨩈脇脚墰𢛶汿𦒘𤾸擧𡒊舘𡡞橓𤩥𤪕䑺舩𠬍𦩒𣵾俹𡓽蓢荢𦬊𤦧𣔰𡝳𣷸芪椛芳䇛"],["8f40","蕋苐茚𠸖𡞴㛁𣅽𣕚艻苢茘𣺋𦶣𦬅𦮗𣗎㶿茝嗬莅䔋𦶥莬菁菓㑾𦻔橗蕚㒖𦹂𢻯葘𥯤葱㷓䓤檧葊𣲵祘蒨𦮖𦹷𦹃蓞萏莑䒠蒓蓤𥲑䉀𥳀䕃蔴嫲𦺙䔧蕳䔖枿蘖"],["8fa1","𨘥𨘻藁𧂈蘂𡖂𧃍䕫䕪蘨㙈𡢢号𧎚虾蝱𪃸蟮𢰧螱蟚蠏噡虬桖䘏衅衆𧗠𣶹𧗤衞袜䙛袴袵揁装睷𧜏覇覊覦覩覧覼𨨥觧𧤤𧪽誜瞓釾誐𧩙竩𧬺𣾏䜓𧬸煼謌謟𥐰𥕥謿譌譍誩𤩺讐讛誯𡛟䘕衏貛𧵔𧶏貫㜥𧵓賖𧶘𧶽贒贃𡤐賛灜贑𤳉㻐起"],["9040","趩𨀂𡀔𤦊㭼𨆼𧄌竧躭躶軃鋔輙輭𨍥𨐒辥錃𪊟𠩐辳䤪𨧞𨔽𣶻廸𣉢迹𪀔𨚼𨔁𢌥㦀𦻗逷𨔼𧪾遡𨕬𨘋邨𨜓郄𨛦邮都酧㫰醩釄粬𨤳𡺉鈎沟鉁鉢𥖹銹𨫆𣲛𨬌𥗛"],["90a1","𠴱錬鍫𨫡𨯫炏嫃𨫢𨫥䥥鉄𨯬𨰹𨯿鍳鑛躼閅閦鐦閠濶䊹𢙺𨛘𡉼𣸮䧟氜陻隖䅬隣𦻕懚隶磵𨫠隽双䦡𦲸𠉴𦐐𩂯𩃥𤫑𡤕𣌊霱虂霶䨏䔽䖅𤫩灵孁霛靜𩇕靗孊𩇫靟鐥僐𣂷𣂼鞉鞟鞱鞾韀韒韠𥑬韮琜𩐳響韵𩐝𧥺䫑頴頳顋顦㬎𧅵㵑𠘰𤅜"],["9140","𥜆飊颷飈飇䫿𦴧𡛓喰飡飦飬鍸餹𤨩䭲𩡗𩤅駵騌騻騐驘𥜥㛄𩂱𩯕髠髢𩬅髴䰎鬔鬭𨘀倴鬴𦦨㣃𣁽魐魀𩴾婅𡡣鮎𤉋鰂鯿鰌𩹨鷔𩾷𪆒𪆫𪃡𪄣𪇟鵾鶃𪄴鸎梈"],["91a1","鷄𢅛𪆓𪈠𡤻𪈳鴹𪂹𪊴麐麕麞麢䴴麪麯𤍤黁㭠㧥㴝伲㞾𨰫鼂鼈䮖鐤𦶢鼗鼖鼹嚟嚊齅馸𩂋韲葿齢齩竜龎爖䮾𤥵𤦻煷𤧸𤍈𤩑玞𨯚𡣺禟𨥾𨸶鍩鏳𨩄鋬鎁鏋𨥬𤒹爗㻫睲穃烐𤑳𤏸煾𡟯炣𡢾𣖙㻇𡢅𥐯𡟸㜢𡛻𡠹㛡𡝴𡣑𥽋㜣𡛀坛𤨥𡏾𡊨"],["9240","𡏆𡒶蔃𣚦蔃葕𤦔𧅥𣸱𥕜𣻻𧁒䓴𣛮𩦝𦼦柹㜳㰕㷧塬𡤢栐䁗𣜿𤃡𤂋𤄏𦰡哋嚞𦚱嚒𠿟𠮨𠸍鏆𨬓鎜仸儫㠙𤐶亼𠑥𠍿佋侊𥙑婨𠆫𠏋㦙𠌊𠐔㐵伩𠋀𨺳𠉵諚𠈌亘"],["92a1","働儍侢伃𤨎𣺊佂倮偬傁俌俥偘僼兙兛兝兞湶𣖕𣸹𣺿浲𡢄𣺉冨凃𠗠䓝𠒣𠒒𠒑赺𨪜𠜎剙劤𠡳勡鍮䙺熌𤎌𠰠𤦬𡃤槑𠸝瑹㻞璙琔瑖玘䮎𤪼𤂍叐㖄爏𤃉喴𠍅响𠯆圝鉝雴鍦埝垍坿㘾壋媙𨩆𡛺𡝯𡜐娬妸銏婾嫏娒𥥆𡧳𡡡𤊕㛵洅瑃娡𥺃"],["9340","媁𨯗𠐓鏠璌𡌃焅䥲鐈𨧻鎽㞠尞岞幞幈𡦖𡥼𣫮廍孏𡤃𡤄㜁𡢠㛝𡛾㛓脪𨩇𡶺𣑲𨦨弌弎𡤧𡞫婫𡜻孄蘔𧗽衠恾𢡠𢘫忛㺸𢖯𢖾𩂈𦽳懀𠀾𠁆𢘛憙憘恵𢲛𢴇𤛔𩅍"],["93a1","摱𤙥𢭪㨩𢬢𣑐𩣪𢹸挷𪑛撶挱揑𤧣𢵧护𢲡搻敫楲㯴𣂎𣊭𤦉𣊫唍𣋠𡣙𩐿曎𣊉𣆳㫠䆐𥖄𨬢𥖏𡛼𥕛𥐥磮𣄃𡠪𣈴㑤𣈏𣆂𤋉暎𦴤晫䮓昰𧡰𡷫晣𣋒𣋡昞𥡲㣑𣠺𣞼㮙𣞢𣏾瓐㮖枏𤘪梶栞㯄檾㡣𣟕𤒇樳橒櫉欅𡤒攑梘橌㯗橺歗𣿀𣲚鎠鋲𨯪𨫋"],["9440","銉𨀞𨧜鑧涥漋𤧬浧𣽿㶏渄𤀼娽渊塇洤硂焻𤌚𤉶烱牐犇犔𤞏𤜥兹𤪤𠗫瑺𣻸𣙟𤩊𤤗𥿡㼆㺱𤫟𨰣𣼵悧㻳瓌琼鎇琷䒟𦷪䕑疃㽣𤳙𤴆㽘畕癳𪗆㬙瑨𨫌𤦫𤦎㫻"],["94a1","㷍𤩎㻿𤧅𤣳釺圲鍂𨫣𡡤僟𥈡𥇧睸𣈲眎眏睻𤚗𣞁㩞𤣰琸璛㺿𤪺𤫇䃈𤪖𦆮錇𥖁砞碍碈磒珐祙𧝁𥛣䄎禛蒖禥樭𣻺稺秴䅮𡛦䄲鈵秱𠵌𤦌𠊙𣶺𡝮㖗啫㕰㚪𠇔𠰍竢婙𢛵𥪯𥪜娍𠉛磰娪𥯆竾䇹籝籭䈑𥮳𥺼𥺦糍𤧹𡞰粎籼粮檲緜縇緓罎𦉡"],["9540","𦅜𧭈綗𥺂䉪𦭵𠤖柖𠁎𣗏埄𦐒𦏸𤥢翝笧𠠬𥫩𥵃笌𥸎駦虅驣樜𣐿㧢𤧷𦖭騟𦖠蒀𧄧𦳑䓪脷䐂胆脉腂𦞴飃𦩂艢艥𦩑葓𦶧蘐𧈛媆䅿𡡀嬫𡢡嫤𡣘蚠蜨𣶏蠭𧐢娂"],["95a1","衮佅袇袿裦襥襍𥚃襔𧞅𧞄𨯵𨯙𨮜𨧹㺭蒣䛵䛏㟲訽訜𩑈彍鈫𤊄旔焩烄𡡅鵭貟賩𧷜妚矃姰䍮㛔踪躧𤰉輰轊䋴汘澻𢌡䢛潹溋𡟚鯩㚵𤤯邻邗啱䤆醻鐄𨩋䁢𨫼鐧𨰝𨰻蓥訫閙閧閗閖𨴴瑅㻂𤣿𤩂𤏪㻧𣈥随𨻧𨹦𨹥㻌𤧭𤩸𣿮琒瑫㻼靁𩂰"],["9640","桇䨝𩂓𥟟靝鍨𨦉𨰦𨬯𦎾銺嬑譩䤼珹𤈛鞛靱餸𠼦巁𨯅𤪲頟𩓚鋶𩗗釥䓀𨭐𤩧𨭤飜𨩅㼀鈪䤥萔餻饍𧬆㷽馛䭯馪驜𨭥𥣈檏騡嫾騯𩣱䮐𩥈馼䮽䮗鍽塲𡌂堢𤦸"],["96a1","𡓨硄𢜟𣶸棅㵽鑘㤧慐𢞁𢥫愇鱏鱓鱻鰵鰐魿鯏𩸭鮟𪇵𪃾鴡䲮𤄄鸘䲰鴌𪆴𪃭𪃳𩤯鶥蒽𦸒𦿟𦮂藼䔳𦶤𦺄𦷰萠藮𦸀𣟗𦁤秢𣖜𣙀䤭𤧞㵢鏛銾鍈𠊿碹鉷鑍俤㑀遤𥕝砽硔碶硋𡝗𣇉𤥁㚚佲濚濙瀞瀞吔𤆵垻壳垊鴖埗焴㒯𤆬燫𦱀𤾗嬨𡞵𨩉"],["9740","愌嫎娋䊼𤒈㜬䭻𨧼鎻鎸𡣖𠼝葲𦳀𡐓𤋺𢰦𤏁妔𣶷𦝁綨𦅛𦂤𤦹𤦋𨧺鋥珢㻩璴𨭣𡢟㻡𤪳櫘珳珻㻖𤨾𤪔𡟙𤩦𠎧𡐤𤧥瑈𤤖炥𤥶銄珦鍟𠓾錱𨫎𨨖鎆𨯧𥗕䤵𨪂煫"],["97a1","𤥃𠳿嚤𠘚𠯫𠲸唂秄𡟺緾𡛂𤩐𡡒䔮鐁㜊𨫀𤦭妰𡢿𡢃𧒄媡㛢𣵛㚰鉟婹𨪁𡡢鍴㳍𠪴䪖㦊僴㵩㵌𡎜煵䋻𨈘渏𩃤䓫浗𧹏灧沯㳖𣿭𣸭渂漌㵯𠏵畑㚼㓈䚀㻚䡱姄鉮䤾轁𨰜𦯀堒埈㛖𡑒烾𤍢𤩱𢿣𡊰𢎽梹楧𡎘𣓥𧯴𣛟𨪃𣟖𣏺𤲟樚𣚭𦲷萾䓟䓎"],["9840","𦴦𦵑𦲂𦿞漗𧄉茽𡜺菭𦲀𧁓𡟛妉媂𡞳婡婱𡤅𤇼㜭姯𡜼㛇熎鎐暚𤊥婮娫𤊓樫𣻹𧜶𤑛𤋊焝𤉙𨧡侰𦴨峂𤓎𧹍𤎽樌𤉖𡌄炦焳𤏩㶥泟勇𤩏繥姫崯㷳彜𤩝𡟟綤萦"],["98a1","咅𣫺𣌀𠈔坾𠣕𠘙㿥𡾞𪊶瀃𩅛嵰玏糓𨩙𩐠俈翧狍猐𧫴猸猹𥛶獁獈㺩𧬘遬燵𤣲珡臶㻊県㻑沢国琙琞琟㻢㻰㻴㻺瓓㼎㽓畂畭畲疍㽼痈痜㿀癍㿗癴㿜発𤽜熈嘣覀塩䀝睃䀹条䁅㗛瞘䁪䁯属瞾矋売砘点砜䂨砹硇硑硦葈𥔵礳栃礲䄃"],["9940","䄉禑禙辻稆込䅧窑䆲窼艹䇄竏竛䇏両筢筬筻簒簛䉠䉺类粜䊌粸䊔糭输烀𠳏総緔緐緽羮羴犟䎗耠耥笹耮耱联㷌垴炠肷胩䏭脌猪脎脒畠脔䐁㬹腖腙腚"],["99a1","䐓堺腼膄䐥膓䐭膥埯臁臤艔䒏芦艶苊苘苿䒰荗险榊萅烵葤惣蒈䔄蒾蓡蓸蔐蔸蕒䔻蕯蕰藠䕷虲蚒蚲蛯际螋䘆䘗袮裿褤襇覑𧥧訩訸誔誴豑賔賲贜䞘塟跃䟭仮踺嗘坔蹱嗵躰䠷軎転軤軭軲辷迁迊迌逳駄䢭飠鈓䤞鈨鉘鉫銱銮銿"],["9a40","鋣鋫鋳鋴鋽鍃鎄鎭䥅䥑麿鐗匁鐝鐭鐾䥪鑔鑹锭関䦧间阳䧥枠䨤靀䨵鞲韂噔䫤惨颹䬙飱塄餎餙冴餜餷饂饝饢䭰駅䮝騼鬏窃魩鮁鯝鯱鯴䱭鰠㝯𡯂鵉鰺"],["9aa1","黾噐鶓鶽鷀鷼银辶鹻麬麱麽黆铜黢黱黸竈齄𠂔𠊷𠎠椚铃妬𠓗塀铁㞹𠗕𠘕𠙶𡚺块煳𠫂𠫍𠮿呪吆𠯋咞𠯻𠰻𠱓𠱥𠱼惧𠲍噺𠲵𠳝𠳭𠵯𠶲𠷈楕鰯螥𠸄𠸎𠻗𠾐𠼭𠹳尠𠾼帋𡁜𡁏𡁶朞𡁻𡂈𡂖㙇𡂿𡃓𡄯𡄻卤蒭𡋣𡍵𡌶讁𡕷𡘙𡟃𡟇乸炻𡠭𡥪"],["9b40","𡨭𡩅𡰪𡱰𡲬𡻈拃𡻕𡼕熘桕𢁅槩㛈𢉼𢏗𢏺𢜪𢡱𢥏苽𢥧𢦓𢫕覥𢫨辠𢬎鞸𢬿顇骽𢱌"],["9b62","𢲈𢲷𥯨𢴈𢴒𢶷𢶕𢹂𢽴𢿌𣀳𣁦𣌟𣏞徱晈暿𧩹𣕧𣗳爁𤦺矗𣘚𣜖纇𠍆墵朎"],["9ba1","椘𣪧𧙗𥿢𣸑𣺹𧗾𢂚䣐䪸𤄙𨪚𤋮𤌍𤀻𤌴𤎖𤩅𠗊凒𠘑妟𡺨㮾𣳿𤐄𤓖垈𤙴㦛𤜯𨗨𩧉㝢𢇃譞𨭎駖𤠒𤣻𤨕爉𤫀𠱸奥𤺥𤾆𠝹軚𥀬劏圿煱𥊙𥐙𣽊𤪧喼𥑆𥑮𦭒釔㑳𥔿𧘲𥕞䜘𥕢𥕦𥟇𤤿𥡝偦㓻𣏌惞𥤃䝼𨥈𥪮𥮉𥰆𡶐垡煑澶𦄂𧰒遖𦆲𤾚譢𦐂𦑊"],["9c40","嵛𦯷輶𦒄𡤜諪𤧶𦒈𣿯𦔒䯀𦖿𦚵𢜛鑥𥟡憕娧晉侻嚹𤔡𦛼乪𤤴陖涏𦲽㘘襷𦞙𦡮𦐑𦡞營𦣇筂𩃀𠨑𦤦鄄𦤹穅鷰𦧺騦𦨭㙟𦑩𠀡禃𦨴𦭛崬𣔙菏𦮝䛐𦲤画补𦶮墶"],["9ca1","㜜𢖍𧁋𧇍㱔𧊀𧊅銁𢅺𧊋錰𧋦𤧐氹钟𧑐𠻸蠧裵𢤦𨑳𡞱溸𤨪𡠠㦤㚹尐秣䔿暶𩲭𩢤襃𧟌𧡘囖䃟𡘊㦡𣜯𨃨𡏅熭荦𧧝𩆨婧䲷𧂯𨦫𧧽𧨊𧬋𧵦𤅺筃祾𨀉澵𪋟樃𨌘厢𦸇鎿栶靝𨅯𨀣𦦵𡏭𣈯𨁈嶅𨰰𨂃圕頣𨥉嶫𤦈斾槕叒𤪥𣾁㰑朶𨂐𨃴𨄮𡾡𨅏"],["9d40","𨆉𨆯𨈚𨌆𨌯𨎊㗊𨑨𨚪䣺揦𨥖砈鉕𨦸䏲𨧧䏟𨧨𨭆𨯔姸𨰉輋𨿅𩃬筑𩄐𩄼㷷𩅞𤫊运犏嚋𩓧𩗩𩖰𩖸𩜲𩣑𩥉𩥪𩧃𩨨𩬎𩵚𩶛纟𩻸𩼣䲤镇𪊓熢𪋿䶑递𪗋䶜𠲜达嗁"],["9da1","辺𢒰边𤪓䔉繿潖檱仪㓤𨬬𧢝㜺躀𡟵𨀤𨭬𨮙𧨾𦚯㷫𧙕𣲷𥘵𥥖亚𥺁𦉘嚿𠹭踎孭𣺈𤲞揞拐𡟶𡡻攰嘭𥱊吚𥌑㷆𩶘䱽嘢嘞罉𥻘奵𣵀蝰东𠿪𠵉𣚺脗鵞贘瘻鱅癎瞹鍅吲腈苷嘥脲萘肽嗪祢噃吖𠺝㗎嘅嗱曱𨋢㘭甴嗰喺咗啲𠱁𠲖廐𥅈𠹶𢱢"],["9e40","𠺢麫絚嗞𡁵抝靭咔賍燶酶揼掹揾啩𢭃鱲𢺳冚㓟𠶧冧呍唞唓癦踭𦢊疱肶蠄螆裇膶萜𡃁䓬猄𤜆宐茋𦢓噻𢛴𧴯𤆣𧵳𦻐𧊶酰𡇙鈈𣳼𪚩𠺬𠻹牦𡲢䝎𤿂𧿹𠿫䃺"],["9ea1","鱝攟𢶠䣳𤟠𩵼𠿬𠸊恢𧖣𠿭"],["9ead","𦁈𡆇熣纎鵐业丄㕷嬍沲卧㚬㧜卽㚥𤘘墚𤭮舭呋垪𥪕𠥹"],["9ec5","㩒𢑥獴𩺬䴉鯭𣳾𩼰䱛𤾩𩖞𩿞葜𣶶𧊲𦞳𣜠挮紥𣻷𣸬㨪逈勌㹴㙺䗩𠒎癀嫰𠺶硺𧼮墧䂿噼鮋嵴癔𪐴麅䳡痹㟻愙𣃚𤏲"],["9ef5","噝𡊩垧𤥣𩸆刴𧂮㖭汊鵼"],["9f40","籖鬹埞𡝬屓擓𩓐𦌵𧅤蚭𠴨𦴢𤫢𠵱"],["9f4f","凾𡼏嶎霃𡷑麁遌笟鬂峑箣扨挵髿篏鬪籾鬮籂粆鰕篼鬉鼗鰛𤤾齚啳寃俽麘俲剠㸆勑坧偖妷帒韈鶫轜呩鞴饀鞺匬愰"],["9fa1","椬叚鰊鴂䰻陁榀傦畆𡝭駚剳"],["9fae","酙隁酜"],["9fb2","酑𨺗捿𦴣櫊嘑醎畺抅𠏼獏籰𥰡𣳽"],["9fc1","𤤙盖鮝个𠳔莾衂"],["9fc9","届槀僭坺刟巵从氱𠇲伹咜哚劚趂㗾弌㗳"],["9fdb","歒酼龥鮗頮颴骺麨麄煺笔"],["9fe7","毺蠘罸"],["9feb","嘠𪙊蹷齓"],["9ff0","跔蹏鸜踁抂𨍽踨蹵竓𤩷稾磘泪詧瘇"],["a040","𨩚鼦泎蟖痃𪊲硓咢贌狢獱謭猂瓱賫𤪻蘯徺袠䒷"],["a055","𡠻𦸅"],["a058","詾𢔛"],["a05b","惽癧髗鵄鍮鮏蟵"],["a063","蠏賷猬霡鮰㗖犲䰇籑饊𦅙慙䰄麖慽"],["a073","坟慯抦戹拎㩜懢厪𣏵捤栂㗒"],["a0a1","嵗𨯂迚𨸹"],["a0a6","僙𡵆礆匲阸𠼻䁥"],["a0ae","矾"],["a0b0","糂𥼚糚稭聦聣絍甅瓲覔舚朌聢𧒆聛瓰脃眤覉𦟌畓𦻑螩蟎臈螌詉貭譃眫瓸蓚㘵榲趦"],["a0d4","覩瑨涹蟁𤀑瓧㷛煶悤憜㳑煢恷"],["a0e2","罱𨬭牐惩䭾删㰘𣳇𥻗𧙖𥔱𡥄𡋾𩤃𦷜𧂭峁𦆭𨨏𣙷𠃮𦡆𤼎䕢嬟𦍌齐麦𦉫"],["a3c0","␀",31,"␡"],["c6a1","①",9,"⑴",9,"ⅰ",9,"丶丿亅亠冂冖冫勹匸卩厶夊宀巛⼳广廴彐彡攴无疒癶辵隶¨ˆヽヾゝゞ〃仝々〆〇ー［］✽ぁ",23],["c740","す",58,"ァアィイ"],["c7a1","ゥ",81,"А",5,"ЁЖ",4],["c840","Л",26,"ёж",25,"⇧↸↹㇏𠃌乚𠂊刂䒑"],["c8a1","龰冈龱𧘇"],["c8cd","￢￤＇＂㈱№℡゛゜⺀⺄⺆⺇⺈⺊⺌⺍⺕⺜⺝⺥⺧⺪⺬⺮⺶⺼⺾⻆⻊⻌⻍⻏⻖⻗⻞⻣"],["c8f5","ʃɐɛɔɵœøŋʊɪ"],["f9fe","￭"],["fa40","𠕇鋛𠗟𣿅蕌䊵珯况㙉𤥂𨧤鍄𡧛苮𣳈砼杄拟𤤳𨦪𠊠𦮳𡌅侫𢓭倈𦴩𧪄𣘀𤪱𢔓倩𠍾徤𠎀𠍇滛𠐟偽儁㑺儎顬㝃萖𤦤𠒇兠𣎴兪𠯿𢃼𠋥𢔰𠖎𣈳𡦃宂蝽𠖳𣲙冲冸"],["faa1","鴴凉减凑㳜凓𤪦决凢卂凭菍椾𣜭彻刋刦刼劵剗劔効勅簕蕂勠蘍𦬓包𨫞啉滙𣾀𠥔𣿬匳卄𠯢泋𡜦栛珕恊㺪㣌𡛨燝䒢卭却𨚫卾卿𡖖𡘓矦厓𨪛厠厫厮玧𥝲㽙玜叁叅汉义埾叙㪫𠮏叠𣿫𢶣叶𠱷吓灹唫晗浛呭𦭓𠵴啝咏咤䞦𡜍𠻝㶴𠵍"],["fb40","𨦼𢚘啇䳭启琗喆喩嘅𡣗𤀺䕒𤐵暳𡂴嘷曍𣊊暤暭噍噏磱囱鞇叾圀囯园𨭦㘣𡉏坆𤆥汮炋坂㚱𦱾埦𡐖堃𡑔𤍣堦𤯵塜墪㕡壠壜𡈼壻寿坃𪅐𤉸鏓㖡够梦㛃湙"],["fba1","𡘾娤啓𡚒蔅姉𠵎𦲁𦴪𡟜姙𡟻𡞲𦶦浱𡠨𡛕姹𦹅媫婣㛦𤦩婷㜈媖瑥嫓𦾡𢕔㶅𡤑㜲𡚸広勐孶斈孼𧨎䀄䡝𠈄寕慠𡨴𥧌𠖥寳宝䴐尅𡭄尓珎尔𡲥𦬨屉䣝岅峩峯嶋𡷹𡸷崐崘嵆𡺤岺巗苼㠭𤤁𢁉𢅳芇㠶㯂帮檊幵幺𤒼𠳓厦亷廐厨𡝱帉廴𨒂"],["fc40","廹廻㢠廼栾鐛弍𠇁弢㫞䢮𡌺强𦢈𢏐彘𢑱彣鞽𦹮彲鍀𨨶徧嶶㵟𥉐𡽪𧃸𢙨釖𠊞𨨩怱暅𡡷㥣㷇㘹垐𢞴祱㹀悞悤悳𤦂𤦏𧩓璤僡媠慤萤慂慈𦻒憁凴𠙖憇宪𣾷"],["fca1","𢡟懓𨮝𩥝懐㤲𢦀𢣁怣慜攞掋𠄘担𡝰拕𢸍捬𤧟㨗搸揸𡎎𡟼撐澊𢸶頔𤂌𥜝擡擥鑻㩦携㩗敍漖𤨨𤨣斅敭敟𣁾斵𤥀䬷旑䃘𡠩无旣忟𣐀昘𣇷𣇸晄𣆤𣆥晋𠹵晧𥇦晳晴𡸽𣈱𨗴𣇈𥌓矅𢣷馤朂𤎜𤨡㬫槺𣟂杞杧杢𤇍𩃭柗䓩栢湐鈼栁𣏦𦶠桝"],["fd40","𣑯槡樋𨫟楳棃𣗍椁椀㴲㨁𣘼㮀枬楡𨩊䋼椶榘㮡𠏉荣傐槹𣙙𢄪橅𣜃檝㯳枱櫈𩆜㰍欝𠤣惞欵歴𢟍溵𣫛𠎵𡥘㝀吡𣭚毡𣻼毜氷𢒋𤣱𦭑汚舦汹𣶼䓅𣶽𤆤𤤌𤤀"],["fda1","𣳉㛥㳫𠴲鮃𣇹𢒑羏样𦴥𦶡𦷫涖浜湼漄𤥿𤂅𦹲蔳𦽴凇沜渝萮𨬡港𣸯瑓𣾂秌湏媑𣁋濸㜍澝𣸰滺𡒗𤀽䕕鏰潄潜㵎潴𩅰㴻澟𤅄濓𤂑𤅕𤀹𣿰𣾴𤄿凟𤅖𤅗𤅀𦇝灋灾炧炁烌烕烖烟䄄㷨熴熖𤉷焫煅媈煊煮岜𤍥煏鍢𤋁焬𤑚𤨧𤨢熺𨯨炽爎"],["fe40","鑂爕夑鑃爤鍁𥘅爮牀𤥴梽牕牗㹕𣁄栍漽犂猪猫𤠣𨠫䣭𨠄猨献珏玪𠰺𦨮珉瑉𤇢𡛧𤨤昣㛅𤦷𤦍𤧻珷琕椃𤨦琹𠗃㻗瑜𢢭瑠𨺲瑇珤瑶莹瑬㜰瑴鏱樬璂䥓𤪌"],["fea1","𤅟𤩹𨮏孆𨰃𡢞瓈𡦈甎瓩甞𨻙𡩋寗𨺬鎅畍畊畧畮𤾂㼄𤴓疎瑝疞疴瘂瘬癑癏癯癶𦏵皐臯㟸𦤑𦤎皡皥皷盌𦾟葢𥂝𥅽𡸜眞眦着撯𥈠睘𣊬瞯𨥤𨥨𡛁矴砉𡍶𤨒棊碯磇磓隥礮𥗠磗礴碱𧘌辸袄𨬫𦂃𢘜禆褀椂禀𥡗禝𧬹礼禩渪𧄦㺨秆𩄍秔"]]},655:function(e,t,n){"use strict";var i=n(293).Buffer;e.exports=function(e){var t=undefined;e.supportsNodeEncodingsExtension=!(i.from||new i(0)instanceof Uint8Array);e.extendNodeEncodings=function extendNodeEncodings(){if(t)return;t={};if(!e.supportsNodeEncodingsExtension){console.error("ACTION NEEDED: require('iconv-lite').extendNodeEncodings() is not supported in your version of Node");console.error("See more info at https://github.com/ashtuchkin/iconv-lite/wiki/Node-v4-compatibility");return}var o={hex:true,utf8:true,"utf-8":true,ascii:true,binary:true,base64:true,ucs2:true,"ucs-2":true,utf16le:true,"utf-16le":true};i.isNativeEncoding=function(e){return e&&o[e.toLowerCase()]};var r=n(293).SlowBuffer;t.SlowBufferToString=r.prototype.toString;r.prototype.toString=function(n,o,r){n=String(n||"utf8").toLowerCase();if(i.isNativeEncoding(n))return t.SlowBufferToString.call(this,n,o,r);if(typeof o=="undefined")o=0;if(typeof r=="undefined")r=this.length;return e.decode(this.slice(o,r),n)};t.SlowBufferWrite=r.prototype.write;r.prototype.write=function(n,o,r,s){if(isFinite(o)){if(!isFinite(r)){s=r;r=undefined}}else{var c=s;s=o;o=r;r=c}o=+o||0;var a=this.length-o;if(!r){r=a}else{r=+r;if(r>a){r=a}}s=String(s||"utf8").toLowerCase();if(i.isNativeEncoding(s))return t.SlowBufferWrite.call(this,n,o,r,s);if(n.length>0&&(r<0||o<0))throw new RangeError("attempt to write beyond buffer bounds");var f=e.encode(n,s);if(f.length<r)r=f.length;f.copy(this,o,0,r);return r};t.BufferIsEncoding=i.isEncoding;i.isEncoding=function(t){return i.isNativeEncoding(t)||e.encodingExists(t)};t.BufferByteLength=i.byteLength;i.byteLength=r.byteLength=function(n,o){o=String(o||"utf8").toLowerCase();if(i.isNativeEncoding(o))return t.BufferByteLength.call(this,n,o);return e.encode(n,o).length};t.BufferToString=i.prototype.toString;i.prototype.toString=function(n,o,r){n=String(n||"utf8").toLowerCase();if(i.isNativeEncoding(n))return t.BufferToString.call(this,n,o,r);if(typeof o=="undefined")o=0;if(typeof r=="undefined")r=this.length;return e.decode(this.slice(o,r),n)};t.BufferWrite=i.prototype.write;i.prototype.write=function(n,o,r,s){var c=o,a=r,f=s;if(isFinite(o)){if(!isFinite(r)){s=r;r=undefined}}else{var h=s;s=o;o=r;r=h}s=String(s||"utf8").toLowerCase();if(i.isNativeEncoding(s))return t.BufferWrite.call(this,n,c,a,f);o=+o||0;var p=this.length-o;if(!r){r=p}else{r=+r;if(r>p){r=p}}if(n.length>0&&(r<0||o<0))throw new RangeError("attempt to write beyond buffer bounds");var u=e.encode(n,s);if(u.length<r)r=u.length;u.copy(this,o,0,r);return r};if(e.supportsStreams){var s=n(413).Readable;t.ReadableSetEncoding=s.prototype.setEncoding;s.prototype.setEncoding=function setEncoding(t,n){this._readableState.decoder=e.getDecoder(t,n);this._readableState.encoding=t};s.prototype.collect=e._collect}};e.undoExtendNodeEncodings=function undoExtendNodeEncodings(){if(!e.supportsNodeEncodingsExtension)return;if(!t)throw new Error("require('iconv-lite').undoExtendNodeEncodings(): Nothing to undo; extendNodeEncodings() is not called.");delete i.isNativeEncoding;var o=n(293).SlowBuffer;o.prototype.toString=t.SlowBufferToString;o.prototype.write=t.SlowBufferWrite;i.isEncoding=t.BufferIsEncoding;i.byteLength=t.BufferByteLength;i.prototype.toString=t.BufferToString;i.prototype.write=t.BufferWrite;if(e.supportsStreams){var r=n(413).Readable;r.prototype.setEncoding=t.ReadableSetEncoding;delete r.prototype.collect}t=undefined}}},693:function(e){e.exports=[["0","\0",128],["a1","｡",62],["8140","　、。，．・：；？！゛゜´｀¨＾￣＿ヽヾゝゞ〃仝々〆〇ー―‐／＼～∥｜…‥‘’“”（）〔〕［］｛｝〈",9,"＋－±×"],["8180","÷＝≠＜＞≦≧∞∴♂♀°′″℃￥＄￠￡％＃＆＊＠§☆★○●◎◇◆□■△▲▽▼※〒→←↑↓〓"],["81b8","∈∋⊆⊇⊂⊃∪∩"],["81c8","∧∨￢⇒⇔∀∃"],["81da","∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬"],["81f0","Å‰♯♭♪†‡¶"],["81fc","◯"],["824f","０",9],["8260","Ａ",25],["8281","ａ",25],["829f","ぁ",82],["8340","ァ",62],["8380","ム",22],["839f","Α",16,"Σ",6],["83bf","α",16,"σ",6],["8440","А",5,"ЁЖ",25],["8470","а",5,"ёж",7],["8480","о",17],["849f","─│┌┐┘└├┬┤┴┼━┃┏┓┛┗┣┳┫┻╋┠┯┨┷┿┝┰┥┸╂"],["8740","①",19,"Ⅰ",9],["875f","㍉㌔㌢㍍㌘㌧㌃㌶㍑㍗㌍㌦㌣㌫㍊㌻㎜㎝㎞㎎㎏㏄㎡"],["877e","㍻"],["8780","〝〟№㏍℡㊤",4,"㈱㈲㈹㍾㍽㍼≒≡∫∮∑√⊥∠∟⊿∵∩∪"],["889f","亜唖娃阿哀愛挨姶逢葵茜穐悪握渥旭葦芦鯵梓圧斡扱宛姐虻飴絢綾鮎或粟袷安庵按暗案闇鞍杏以伊位依偉囲夷委威尉惟意慰易椅為畏異移維緯胃萎衣謂違遺医井亥域育郁磯一壱溢逸稲茨芋鰯允印咽員因姻引飲淫胤蔭"],["8940","院陰隠韻吋右宇烏羽迂雨卯鵜窺丑碓臼渦嘘唄欝蔚鰻姥厩浦瓜閏噂云運雲荏餌叡営嬰影映曳栄永泳洩瑛盈穎頴英衛詠鋭液疫益駅悦謁越閲榎厭円"],["8980","園堰奄宴延怨掩援沿演炎焔煙燕猿縁艶苑薗遠鉛鴛塩於汚甥凹央奥往応押旺横欧殴王翁襖鴬鴎黄岡沖荻億屋憶臆桶牡乙俺卸恩温穏音下化仮何伽価佳加可嘉夏嫁家寡科暇果架歌河火珂禍禾稼箇花苛茄荷華菓蝦課嘩貨迦過霞蚊俄峨我牙画臥芽蛾賀雅餓駕介会解回塊壊廻快怪悔恢懐戒拐改"],["8a40","魁晦械海灰界皆絵芥蟹開階貝凱劾外咳害崖慨概涯碍蓋街該鎧骸浬馨蛙垣柿蛎鈎劃嚇各廓拡撹格核殻獲確穫覚角赫較郭閣隔革学岳楽額顎掛笠樫"],["8a80","橿梶鰍潟割喝恰括活渇滑葛褐轄且鰹叶椛樺鞄株兜竃蒲釜鎌噛鴨栢茅萱粥刈苅瓦乾侃冠寒刊勘勧巻喚堪姦完官寛干幹患感慣憾換敢柑桓棺款歓汗漢澗潅環甘監看竿管簡緩缶翰肝艦莞観諌貫還鑑間閑関陥韓館舘丸含岸巌玩癌眼岩翫贋雁頑顔願企伎危喜器基奇嬉寄岐希幾忌揮机旗既期棋棄"],["8b40","機帰毅気汽畿祈季稀紀徽規記貴起軌輝飢騎鬼亀偽儀妓宜戯技擬欺犠疑祇義蟻誼議掬菊鞠吉吃喫桔橘詰砧杵黍却客脚虐逆丘久仇休及吸宮弓急救"],["8b80","朽求汲泣灸球究窮笈級糾給旧牛去居巨拒拠挙渠虚許距鋸漁禦魚亨享京供侠僑兇競共凶協匡卿叫喬境峡強彊怯恐恭挟教橋況狂狭矯胸脅興蕎郷鏡響饗驚仰凝尭暁業局曲極玉桐粁僅勤均巾錦斤欣欽琴禁禽筋緊芹菌衿襟謹近金吟銀九倶句区狗玖矩苦躯駆駈駒具愚虞喰空偶寓遇隅串櫛釧屑屈"],["8c40","掘窟沓靴轡窪熊隈粂栗繰桑鍬勲君薫訓群軍郡卦袈祁係傾刑兄啓圭珪型契形径恵慶慧憩掲携敬景桂渓畦稽系経継繋罫茎荊蛍計詣警軽頚鶏芸迎鯨"],["8c80","劇戟撃激隙桁傑欠決潔穴結血訣月件倹倦健兼券剣喧圏堅嫌建憲懸拳捲検権牽犬献研硯絹県肩見謙賢軒遣鍵険顕験鹸元原厳幻弦減源玄現絃舷言諺限乎個古呼固姑孤己庫弧戸故枯湖狐糊袴股胡菰虎誇跨鈷雇顧鼓五互伍午呉吾娯後御悟梧檎瑚碁語誤護醐乞鯉交佼侯候倖光公功効勾厚口向"],["8d40","后喉坑垢好孔孝宏工巧巷幸広庚康弘恒慌抗拘控攻昂晃更杭校梗構江洪浩港溝甲皇硬稿糠紅紘絞綱耕考肯肱腔膏航荒行衡講貢購郊酵鉱砿鋼閤降"],["8d80","項香高鴻剛劫号合壕拷濠豪轟麹克刻告国穀酷鵠黒獄漉腰甑忽惚骨狛込此頃今困坤墾婚恨懇昏昆根梱混痕紺艮魂些佐叉唆嵯左差査沙瑳砂詐鎖裟坐座挫債催再最哉塞妻宰彩才採栽歳済災采犀砕砦祭斎細菜裁載際剤在材罪財冴坂阪堺榊肴咲崎埼碕鷺作削咋搾昨朔柵窄策索錯桜鮭笹匙冊刷"],["8e40","察拶撮擦札殺薩雑皐鯖捌錆鮫皿晒三傘参山惨撒散桟燦珊産算纂蚕讃賛酸餐斬暫残仕仔伺使刺司史嗣四士始姉姿子屍市師志思指支孜斯施旨枝止"],["8e80","死氏獅祉私糸紙紫肢脂至視詞詩試誌諮資賜雌飼歯事似侍児字寺慈持時次滋治爾璽痔磁示而耳自蒔辞汐鹿式識鴫竺軸宍雫七叱執失嫉室悉湿漆疾質実蔀篠偲柴芝屡蕊縞舎写射捨赦斜煮社紗者謝車遮蛇邪借勺尺杓灼爵酌釈錫若寂弱惹主取守手朱殊狩珠種腫趣酒首儒受呪寿授樹綬需囚収周"],["8f40","宗就州修愁拾洲秀秋終繍習臭舟蒐衆襲讐蹴輯週酋酬集醜什住充十従戎柔汁渋獣縦重銃叔夙宿淑祝縮粛塾熟出術述俊峻春瞬竣舜駿准循旬楯殉淳"],["8f80","準潤盾純巡遵醇順処初所暑曙渚庶緒署書薯藷諸助叙女序徐恕鋤除傷償勝匠升召哨商唱嘗奨妾娼宵将小少尚庄床廠彰承抄招掌捷昇昌昭晶松梢樟樵沼消渉湘焼焦照症省硝礁祥称章笑粧紹肖菖蒋蕉衝裳訟証詔詳象賞醤鉦鍾鐘障鞘上丈丞乗冗剰城場壌嬢常情擾条杖浄状畳穣蒸譲醸錠嘱埴飾"],["9040","拭植殖燭織職色触食蝕辱尻伸信侵唇娠寝審心慎振新晋森榛浸深申疹真神秦紳臣芯薪親診身辛進針震人仁刃塵壬尋甚尽腎訊迅陣靭笥諏須酢図厨"],["9080","逗吹垂帥推水炊睡粋翠衰遂酔錐錘随瑞髄崇嵩数枢趨雛据杉椙菅頗雀裾澄摺寸世瀬畝是凄制勢姓征性成政整星晴棲栖正清牲生盛精聖声製西誠誓請逝醒青静斉税脆隻席惜戚斥昔析石積籍績脊責赤跡蹟碩切拙接摂折設窃節説雪絶舌蝉仙先千占宣専尖川戦扇撰栓栴泉浅洗染潜煎煽旋穿箭線"],["9140","繊羨腺舛船薦詮賎践選遷銭銑閃鮮前善漸然全禅繕膳糎噌塑岨措曾曽楚狙疏疎礎祖租粗素組蘇訴阻遡鼠僧創双叢倉喪壮奏爽宋層匝惣想捜掃挿掻"],["9180","操早曹巣槍槽漕燥争痩相窓糟総綜聡草荘葬蒼藻装走送遭鎗霜騒像増憎臓蔵贈造促側則即息捉束測足速俗属賊族続卒袖其揃存孫尊損村遜他多太汰詑唾堕妥惰打柁舵楕陀駄騨体堆対耐岱帯待怠態戴替泰滞胎腿苔袋貸退逮隊黛鯛代台大第醍題鷹滝瀧卓啄宅托択拓沢濯琢託鐸濁諾茸凧蛸只"],["9240","叩但達辰奪脱巽竪辿棚谷狸鱈樽誰丹単嘆坦担探旦歎淡湛炭短端箪綻耽胆蛋誕鍛団壇弾断暖檀段男談値知地弛恥智池痴稚置致蜘遅馳築畜竹筑蓄"],["9280","逐秩窒茶嫡着中仲宙忠抽昼柱注虫衷註酎鋳駐樗瀦猪苧著貯丁兆凋喋寵帖帳庁弔張彫徴懲挑暢朝潮牒町眺聴脹腸蝶調諜超跳銚長頂鳥勅捗直朕沈珍賃鎮陳津墜椎槌追鎚痛通塚栂掴槻佃漬柘辻蔦綴鍔椿潰坪壷嬬紬爪吊釣鶴亭低停偵剃貞呈堤定帝底庭廷弟悌抵挺提梯汀碇禎程締艇訂諦蹄逓"],["9340","邸鄭釘鼎泥摘擢敵滴的笛適鏑溺哲徹撤轍迭鉄典填天展店添纏甜貼転顛点伝殿澱田電兎吐堵塗妬屠徒斗杜渡登菟賭途都鍍砥砺努度土奴怒倒党冬"],["9380","凍刀唐塔塘套宕島嶋悼投搭東桃梼棟盗淘湯涛灯燈当痘祷等答筒糖統到董蕩藤討謄豆踏逃透鐙陶頭騰闘働動同堂導憧撞洞瞳童胴萄道銅峠鴇匿得徳涜特督禿篤毒独読栃橡凸突椴届鳶苫寅酉瀞噸屯惇敦沌豚遁頓呑曇鈍奈那内乍凪薙謎灘捺鍋楢馴縄畷南楠軟難汝二尼弐迩匂賑肉虹廿日乳入"],["9440","如尿韮任妊忍認濡禰祢寧葱猫熱年念捻撚燃粘乃廼之埜嚢悩濃納能脳膿農覗蚤巴把播覇杷波派琶破婆罵芭馬俳廃拝排敗杯盃牌背肺輩配倍培媒梅"],["9480","楳煤狽買売賠陪這蝿秤矧萩伯剥博拍柏泊白箔粕舶薄迫曝漠爆縛莫駁麦函箱硲箸肇筈櫨幡肌畑畠八鉢溌発醗髪伐罰抜筏閥鳩噺塙蛤隼伴判半反叛帆搬斑板氾汎版犯班畔繁般藩販範釆煩頒飯挽晩番盤磐蕃蛮匪卑否妃庇彼悲扉批披斐比泌疲皮碑秘緋罷肥被誹費避非飛樋簸備尾微枇毘琵眉美"],["9540","鼻柊稗匹疋髭彦膝菱肘弼必畢筆逼桧姫媛紐百謬俵彪標氷漂瓢票表評豹廟描病秒苗錨鋲蒜蛭鰭品彬斌浜瀕貧賓頻敏瓶不付埠夫婦富冨布府怖扶敷"],["9580","斧普浮父符腐膚芙譜負賦赴阜附侮撫武舞葡蕪部封楓風葺蕗伏副復幅服福腹複覆淵弗払沸仏物鮒分吻噴墳憤扮焚奮粉糞紛雰文聞丙併兵塀幣平弊柄並蔽閉陛米頁僻壁癖碧別瞥蔑箆偏変片篇編辺返遍便勉娩弁鞭保舗鋪圃捕歩甫補輔穂募墓慕戊暮母簿菩倣俸包呆報奉宝峰峯崩庖抱捧放方朋"],["9640","法泡烹砲縫胞芳萌蓬蜂褒訪豊邦鋒飽鳳鵬乏亡傍剖坊妨帽忘忙房暴望某棒冒紡肪膨謀貌貿鉾防吠頬北僕卜墨撲朴牧睦穆釦勃没殆堀幌奔本翻凡盆"],["9680","摩磨魔麻埋妹昧枚毎哩槙幕膜枕鮪柾鱒桝亦俣又抹末沫迄侭繭麿万慢満漫蔓味未魅巳箕岬密蜜湊蓑稔脈妙粍民眠務夢無牟矛霧鵡椋婿娘冥名命明盟迷銘鳴姪牝滅免棉綿緬面麺摸模茂妄孟毛猛盲網耗蒙儲木黙目杢勿餅尤戻籾貰問悶紋門匁也冶夜爺耶野弥矢厄役約薬訳躍靖柳薮鑓愉愈油癒"],["9740","諭輸唯佑優勇友宥幽悠憂揖有柚湧涌猶猷由祐裕誘遊邑郵雄融夕予余与誉輿預傭幼妖容庸揚揺擁曜楊様洋溶熔用窯羊耀葉蓉要謡踊遥陽養慾抑欲"],["9780","沃浴翌翼淀羅螺裸来莱頼雷洛絡落酪乱卵嵐欄濫藍蘭覧利吏履李梨理璃痢裏裡里離陸律率立葎掠略劉流溜琉留硫粒隆竜龍侶慮旅虜了亮僚両凌寮料梁涼猟療瞭稜糧良諒遼量陵領力緑倫厘林淋燐琳臨輪隣鱗麟瑠塁涙累類令伶例冷励嶺怜玲礼苓鈴隷零霊麗齢暦歴列劣烈裂廉恋憐漣煉簾練聯"],["9840","蓮連錬呂魯櫓炉賂路露労婁廊弄朗楼榔浪漏牢狼篭老聾蝋郎六麓禄肋録論倭和話歪賄脇惑枠鷲亙亘鰐詫藁蕨椀湾碗腕"],["989f","弌丐丕个丱丶丼丿乂乖乘亂亅豫亊舒弍于亞亟亠亢亰亳亶从仍仄仆仂仗仞仭仟价伉佚估佛佝佗佇佶侈侏侘佻佩佰侑佯來侖儘俔俟俎俘俛俑俚俐俤俥倚倨倔倪倥倅伜俶倡倩倬俾俯們倆偃假會偕偐偈做偖偬偸傀傚傅傴傲"],["9940","僉僊傳僂僖僞僥僭僣僮價僵儉儁儂儖儕儔儚儡儺儷儼儻儿兀兒兌兔兢竸兩兪兮冀冂囘册冉冏冑冓冕冖冤冦冢冩冪冫决冱冲冰况冽凅凉凛几處凩凭"],["9980","凰凵凾刄刋刔刎刧刪刮刳刹剏剄剋剌剞剔剪剴剩剳剿剽劍劔劒剱劈劑辨辧劬劭劼劵勁勍勗勞勣勦飭勠勳勵勸勹匆匈甸匍匐匏匕匚匣匯匱匳匸區卆卅丗卉卍凖卞卩卮夘卻卷厂厖厠厦厥厮厰厶參簒雙叟曼燮叮叨叭叺吁吽呀听吭吼吮吶吩吝呎咏呵咎呟呱呷呰咒呻咀呶咄咐咆哇咢咸咥咬哄哈咨"],["9a40","咫哂咤咾咼哘哥哦唏唔哽哮哭哺哢唹啀啣啌售啜啅啖啗唸唳啝喙喀咯喊喟啻啾喘喞單啼喃喩喇喨嗚嗅嗟嗄嗜嗤嗔嘔嗷嘖嗾嗽嘛嗹噎噐營嘴嘶嘲嘸"],["9a80","噫噤嘯噬噪嚆嚀嚊嚠嚔嚏嚥嚮嚶嚴囂嚼囁囃囀囈囎囑囓囗囮囹圀囿圄圉圈國圍圓團圖嗇圜圦圷圸坎圻址坏坩埀垈坡坿垉垓垠垳垤垪垰埃埆埔埒埓堊埖埣堋堙堝塲堡塢塋塰毀塒堽塹墅墹墟墫墺壞墻墸墮壅壓壑壗壙壘壥壜壤壟壯壺壹壻壼壽夂夊夐夛梦夥夬夭夲夸夾竒奕奐奎奚奘奢奠奧奬奩"],["9b40","奸妁妝佞侫妣妲姆姨姜妍姙姚娥娟娑娜娉娚婀婬婉娵娶婢婪媚媼媾嫋嫂媽嫣嫗嫦嫩嫖嫺嫻嬌嬋嬖嬲嫐嬪嬶嬾孃孅孀孑孕孚孛孥孩孰孳孵學斈孺宀"],["9b80","它宦宸寃寇寉寔寐寤實寢寞寥寫寰寶寳尅將專對尓尠尢尨尸尹屁屆屎屓屐屏孱屬屮乢屶屹岌岑岔妛岫岻岶岼岷峅岾峇峙峩峽峺峭嶌峪崋崕崗嵜崟崛崑崔崢崚崙崘嵌嵒嵎嵋嵬嵳嵶嶇嶄嶂嶢嶝嶬嶮嶽嶐嶷嶼巉巍巓巒巖巛巫已巵帋帚帙帑帛帶帷幄幃幀幎幗幔幟幢幤幇幵并幺麼广庠廁廂廈廐廏"],["9c40","廖廣廝廚廛廢廡廨廩廬廱廳廰廴廸廾弃弉彝彜弋弑弖弩弭弸彁彈彌彎弯彑彖彗彙彡彭彳彷徃徂彿徊很徑徇從徙徘徠徨徭徼忖忻忤忸忱忝悳忿怡恠"],["9c80","怙怐怩怎怱怛怕怫怦怏怺恚恁恪恷恟恊恆恍恣恃恤恂恬恫恙悁悍惧悃悚悄悛悖悗悒悧悋惡悸惠惓悴忰悽惆悵惘慍愕愆惶惷愀惴惺愃愡惻惱愍愎慇愾愨愧慊愿愼愬愴愽慂慄慳慷慘慙慚慫慴慯慥慱慟慝慓慵憙憖憇憬憔憚憊憑憫憮懌懊應懷懈懃懆憺懋罹懍懦懣懶懺懴懿懽懼懾戀戈戉戍戌戔戛"],["9d40","戞戡截戮戰戲戳扁扎扞扣扛扠扨扼抂抉找抒抓抖拔抃抔拗拑抻拏拿拆擔拈拜拌拊拂拇抛拉挌拮拱挧挂挈拯拵捐挾捍搜捏掖掎掀掫捶掣掏掉掟掵捫"],["9d80","捩掾揩揀揆揣揉插揶揄搖搴搆搓搦搶攝搗搨搏摧摯摶摎攪撕撓撥撩撈撼據擒擅擇撻擘擂擱擧舉擠擡抬擣擯攬擶擴擲擺攀擽攘攜攅攤攣攫攴攵攷收攸畋效敖敕敍敘敞敝敲數斂斃變斛斟斫斷旃旆旁旄旌旒旛旙无旡旱杲昊昃旻杳昵昶昴昜晏晄晉晁晞晝晤晧晨晟晢晰暃暈暎暉暄暘暝曁暹曉暾暼"],["9e40","曄暸曖曚曠昿曦曩曰曵曷朏朖朞朦朧霸朮朿朶杁朸朷杆杞杠杙杣杤枉杰枩杼杪枌枋枦枡枅枷柯枴柬枳柩枸柤柞柝柢柮枹柎柆柧檜栞框栩桀桍栲桎"],["9e80","梳栫桙档桷桿梟梏梭梔條梛梃檮梹桴梵梠梺椏梍桾椁棊椈棘椢椦棡椌棍棔棧棕椶椒椄棗棣椥棹棠棯椨椪椚椣椡棆楹楷楜楸楫楔楾楮椹楴椽楙椰楡楞楝榁楪榲榮槐榿槁槓榾槎寨槊槝榻槃榧樮榑榠榜榕榴槞槨樂樛槿權槹槲槧樅榱樞槭樔槫樊樒櫁樣樓橄樌橲樶橸橇橢橙橦橈樸樢檐檍檠檄檢檣"],["9f40","檗蘗檻櫃櫂檸檳檬櫞櫑櫟檪櫚櫪櫻欅蘖櫺欒欖鬱欟欸欷盜欹飮歇歃歉歐歙歔歛歟歡歸歹歿殀殄殃殍殘殕殞殤殪殫殯殲殱殳殷殼毆毋毓毟毬毫毳毯"],["9f80","麾氈氓气氛氤氣汞汕汢汪沂沍沚沁沛汾汨汳沒沐泄泱泓沽泗泅泝沮沱沾沺泛泯泙泪洟衍洶洫洽洸洙洵洳洒洌浣涓浤浚浹浙涎涕濤涅淹渕渊涵淇淦涸淆淬淞淌淨淒淅淺淙淤淕淪淮渭湮渮渙湲湟渾渣湫渫湶湍渟湃渺湎渤滿渝游溂溪溘滉溷滓溽溯滄溲滔滕溏溥滂溟潁漑灌滬滸滾漿滲漱滯漲滌"],["e040","漾漓滷澆潺潸澁澀潯潛濳潭澂潼潘澎澑濂潦澳澣澡澤澹濆澪濟濕濬濔濘濱濮濛瀉瀋濺瀑瀁瀏濾瀛瀚潴瀝瀘瀟瀰瀾瀲灑灣炙炒炯烱炬炸炳炮烟烋烝"],["e080","烙焉烽焜焙煥煕熈煦煢煌煖煬熏燻熄熕熨熬燗熹熾燒燉燔燎燠燬燧燵燼燹燿爍爐爛爨爭爬爰爲爻爼爿牀牆牋牘牴牾犂犁犇犒犖犢犧犹犲狃狆狄狎狒狢狠狡狹狷倏猗猊猜猖猝猴猯猩猥猾獎獏默獗獪獨獰獸獵獻獺珈玳珎玻珀珥珮珞璢琅瑯琥珸琲琺瑕琿瑟瑙瑁瑜瑩瑰瑣瑪瑶瑾璋璞璧瓊瓏瓔珱"],["e140","瓠瓣瓧瓩瓮瓲瓰瓱瓸瓷甄甃甅甌甎甍甕甓甞甦甬甼畄畍畊畉畛畆畚畩畤畧畫畭畸當疆疇畴疊疉疂疔疚疝疥疣痂疳痃疵疽疸疼疱痍痊痒痙痣痞痾痿"],["e180","痼瘁痰痺痲痳瘋瘍瘉瘟瘧瘠瘡瘢瘤瘴瘰瘻癇癈癆癜癘癡癢癨癩癪癧癬癰癲癶癸發皀皃皈皋皎皖皓皙皚皰皴皸皹皺盂盍盖盒盞盡盥盧盪蘯盻眈眇眄眩眤眞眥眦眛眷眸睇睚睨睫睛睥睿睾睹瞎瞋瞑瞠瞞瞰瞶瞹瞿瞼瞽瞻矇矍矗矚矜矣矮矼砌砒礦砠礪硅碎硴碆硼碚碌碣碵碪碯磑磆磋磔碾碼磅磊磬"],["e240","磧磚磽磴礇礒礑礙礬礫祀祠祗祟祚祕祓祺祿禊禝禧齋禪禮禳禹禺秉秕秧秬秡秣稈稍稘稙稠稟禀稱稻稾稷穃穗穉穡穢穩龝穰穹穽窈窗窕窘窖窩竈窰"],["e280","窶竅竄窿邃竇竊竍竏竕竓站竚竝竡竢竦竭竰笂笏笊笆笳笘笙笞笵笨笶筐筺笄筍笋筌筅筵筥筴筧筰筱筬筮箝箘箟箍箜箚箋箒箏筝箙篋篁篌篏箴篆篝篩簑簔篦篥籠簀簇簓篳篷簗簍篶簣簧簪簟簷簫簽籌籃籔籏籀籐籘籟籤籖籥籬籵粃粐粤粭粢粫粡粨粳粲粱粮粹粽糀糅糂糘糒糜糢鬻糯糲糴糶糺紆"],["e340","紂紜紕紊絅絋紮紲紿紵絆絳絖絎絲絨絮絏絣經綉絛綏絽綛綺綮綣綵緇綽綫總綢綯緜綸綟綰緘緝緤緞緻緲緡縅縊縣縡縒縱縟縉縋縢繆繦縻縵縹繃縷"],["e380","縲縺繧繝繖繞繙繚繹繪繩繼繻纃緕繽辮繿纈纉續纒纐纓纔纖纎纛纜缸缺罅罌罍罎罐网罕罔罘罟罠罨罩罧罸羂羆羃羈羇羌羔羞羝羚羣羯羲羹羮羶羸譱翅翆翊翕翔翡翦翩翳翹飜耆耄耋耒耘耙耜耡耨耿耻聊聆聒聘聚聟聢聨聳聲聰聶聹聽聿肄肆肅肛肓肚肭冐肬胛胥胙胝胄胚胖脉胯胱脛脩脣脯腋"],["e440","隋腆脾腓腑胼腱腮腥腦腴膃膈膊膀膂膠膕膤膣腟膓膩膰膵膾膸膽臀臂膺臉臍臑臙臘臈臚臟臠臧臺臻臾舁舂舅與舊舍舐舖舩舫舸舳艀艙艘艝艚艟艤"],["e480","艢艨艪艫舮艱艷艸艾芍芒芫芟芻芬苡苣苟苒苴苳苺莓范苻苹苞茆苜茉苙茵茴茖茲茱荀茹荐荅茯茫茗茘莅莚莪莟莢莖茣莎莇莊荼莵荳荵莠莉莨菴萓菫菎菽萃菘萋菁菷萇菠菲萍萢萠莽萸蔆菻葭萪萼蕚蒄葷葫蒭葮蒂葩葆萬葯葹萵蓊葢蒹蒿蒟蓙蓍蒻蓚蓐蓁蓆蓖蒡蔡蓿蓴蔗蔘蔬蔟蔕蔔蓼蕀蕣蕘蕈"],["e540","蕁蘂蕋蕕薀薤薈薑薊薨蕭薔薛藪薇薜蕷蕾薐藉薺藏薹藐藕藝藥藜藹蘊蘓蘋藾藺蘆蘢蘚蘰蘿虍乕虔號虧虱蚓蚣蚩蚪蚋蚌蚶蚯蛄蛆蚰蛉蠣蚫蛔蛞蛩蛬"],["e580","蛟蛛蛯蜒蜆蜈蜀蜃蛻蜑蜉蜍蛹蜊蜴蜿蜷蜻蜥蜩蜚蝠蝟蝸蝌蝎蝴蝗蝨蝮蝙蝓蝣蝪蠅螢螟螂螯蟋螽蟀蟐雖螫蟄螳蟇蟆螻蟯蟲蟠蠏蠍蟾蟶蟷蠎蟒蠑蠖蠕蠢蠡蠱蠶蠹蠧蠻衄衂衒衙衞衢衫袁衾袞衵衽袵衲袂袗袒袮袙袢袍袤袰袿袱裃裄裔裘裙裝裹褂裼裴裨裲褄褌褊褓襃褞褥褪褫襁襄褻褶褸襌褝襠襞"],["e640","襦襤襭襪襯襴襷襾覃覈覊覓覘覡覩覦覬覯覲覺覽覿觀觚觜觝觧觴觸訃訖訐訌訛訝訥訶詁詛詒詆詈詼詭詬詢誅誂誄誨誡誑誥誦誚誣諄諍諂諚諫諳諧"],["e680","諤諱謔諠諢諷諞諛謌謇謚諡謖謐謗謠謳鞫謦謫謾謨譁譌譏譎證譖譛譚譫譟譬譯譴譽讀讌讎讒讓讖讙讚谺豁谿豈豌豎豐豕豢豬豸豺貂貉貅貊貍貎貔豼貘戝貭貪貽貲貳貮貶賈賁賤賣賚賽賺賻贄贅贊贇贏贍贐齎贓賍贔贖赧赭赱赳趁趙跂趾趺跏跚跖跌跛跋跪跫跟跣跼踈踉跿踝踞踐踟蹂踵踰踴蹊"],["e740","蹇蹉蹌蹐蹈蹙蹤蹠踪蹣蹕蹶蹲蹼躁躇躅躄躋躊躓躑躔躙躪躡躬躰軆躱躾軅軈軋軛軣軼軻軫軾輊輅輕輒輙輓輜輟輛輌輦輳輻輹轅轂輾轌轉轆轎轗轜"],["e780","轢轣轤辜辟辣辭辯辷迚迥迢迪迯邇迴逅迹迺逑逕逡逍逞逖逋逧逶逵逹迸遏遐遑遒逎遉逾遖遘遞遨遯遶隨遲邂遽邁邀邊邉邏邨邯邱邵郢郤扈郛鄂鄒鄙鄲鄰酊酖酘酣酥酩酳酲醋醉醂醢醫醯醪醵醴醺釀釁釉釋釐釖釟釡釛釼釵釶鈞釿鈔鈬鈕鈑鉞鉗鉅鉉鉤鉈銕鈿鉋鉐銜銖銓銛鉚鋏銹銷鋩錏鋺鍄錮"],["e840","錙錢錚錣錺錵錻鍜鍠鍼鍮鍖鎰鎬鎭鎔鎹鏖鏗鏨鏥鏘鏃鏝鏐鏈鏤鐚鐔鐓鐃鐇鐐鐶鐫鐵鐡鐺鑁鑒鑄鑛鑠鑢鑞鑪鈩鑰鑵鑷鑽鑚鑼鑾钁鑿閂閇閊閔閖閘閙"],["e880","閠閨閧閭閼閻閹閾闊濶闃闍闌闕闔闖關闡闥闢阡阨阮阯陂陌陏陋陷陜陞陝陟陦陲陬隍隘隕隗險隧隱隲隰隴隶隸隹雎雋雉雍襍雜霍雕雹霄霆霈霓霎霑霏霖霙霤霪霰霹霽霾靄靆靈靂靉靜靠靤靦靨勒靫靱靹鞅靼鞁靺鞆鞋鞏鞐鞜鞨鞦鞣鞳鞴韃韆韈韋韜韭齏韲竟韶韵頏頌頸頤頡頷頽顆顏顋顫顯顰"],["e940","顱顴顳颪颯颱颶飄飃飆飩飫餃餉餒餔餘餡餝餞餤餠餬餮餽餾饂饉饅饐饋饑饒饌饕馗馘馥馭馮馼駟駛駝駘駑駭駮駱駲駻駸騁騏騅駢騙騫騷驅驂驀驃"],["e980","騾驕驍驛驗驟驢驥驤驩驫驪骭骰骼髀髏髑髓體髞髟髢髣髦髯髫髮髴髱髷髻鬆鬘鬚鬟鬢鬣鬥鬧鬨鬩鬪鬮鬯鬲魄魃魏魍魎魑魘魴鮓鮃鮑鮖鮗鮟鮠鮨鮴鯀鯊鮹鯆鯏鯑鯒鯣鯢鯤鯔鯡鰺鯲鯱鯰鰕鰔鰉鰓鰌鰆鰈鰒鰊鰄鰮鰛鰥鰤鰡鰰鱇鰲鱆鰾鱚鱠鱧鱶鱸鳧鳬鳰鴉鴈鳫鴃鴆鴪鴦鶯鴣鴟鵄鴕鴒鵁鴿鴾鵆鵈"],["ea40","鵝鵞鵤鵑鵐鵙鵲鶉鶇鶫鵯鵺鶚鶤鶩鶲鷄鷁鶻鶸鶺鷆鷏鷂鷙鷓鷸鷦鷭鷯鷽鸚鸛鸞鹵鹹鹽麁麈麋麌麒麕麑麝麥麩麸麪麭靡黌黎黏黐黔黜點黝黠黥黨黯"],["ea80","黴黶黷黹黻黼黽鼇鼈皷鼕鼡鼬鼾齊齒齔齣齟齠齡齦齧齬齪齷齲齶龕龜龠堯槇遙瑤凜熙"],["ed40","纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏"],["ed80","塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱"],["ee40","犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙"],["ee80","蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"],["eeef","ⅰ",9,"￢￤＇＂"],["f040","",62],["f080","",124],["f140","",62],["f180","",124],["f240","",62],["f280","",124],["f340","",62],["f380","",124],["f440","",62],["f480","",124],["f540","",62],["f580","",124],["f640","",62],["f680","",124],["f740","",62],["f780","",124],["f840","",62],["f880","",124],["f940",""],["fa40","ⅰ",9,"Ⅰ",9,"￢￤＇＂㈱№℡∵纊褜鍈銈蓜俉炻昱棈鋹曻彅丨仡仼伀伃伹佖侒侊侚侔俍偀倢俿倞偆偰偂傔僴僘兊"],["fa80","兤冝冾凬刕劜劦勀勛匀匇匤卲厓厲叝﨎咜咊咩哿喆坙坥垬埈埇﨏塚增墲夋奓奛奝奣妤妺孖寀甯寘寬尞岦岺峵崧嵓﨑嵂嵭嶸嶹巐弡弴彧德忞恝悅悊惞惕愠惲愑愷愰憘戓抦揵摠撝擎敎昀昕昻昉昮昞昤晥晗晙晴晳暙暠暲暿曺朎朗杦枻桒柀栁桄棏﨓楨﨔榘槢樰橫橆橳橾櫢櫤毖氿汜沆汯泚洄涇浯"],["fb40","涖涬淏淸淲淼渹湜渧渼溿澈澵濵瀅瀇瀨炅炫焏焄煜煆煇凞燁燾犱犾猤猪獷玽珉珖珣珒琇珵琦琪琩琮瑢璉璟甁畯皂皜皞皛皦益睆劯砡硎硤硺礰礼神"],["fb80","祥禔福禛竑竧靖竫箞精絈絜綷綠緖繒罇羡羽茁荢荿菇菶葈蒴蕓蕙蕫﨟薰蘒﨡蠇裵訒訷詹誧誾諟諸諶譓譿賰賴贒赶﨣軏﨤逸遧郞都鄕鄧釚釗釞釭釮釤釥鈆鈐鈊鈺鉀鈼鉎鉙鉑鈹鉧銧鉷鉸鋧鋗鋙鋐﨧鋕鋠鋓錥錡鋻﨨錞鋿錝錂鍰鍗鎤鏆鏞鏸鐱鑅鑈閒隆﨩隝隯霳霻靃靍靏靑靕顗顥飯飼餧館馞驎髙"],["fc40","髜魵魲鮏鮱鮻鰀鵰鵫鶴鸙黑"]]},715:function(e,t,n){"use strict";var i;var o;try{i="iconv";o=n(256).Iconv}catch(e){}e.exports=o},761:function(e){e.exports=__webpack_require__("FMKJ")},791:function(e){e.exports=[["0","\0",127,"€"],["8140","丂丄丅丆丏丒丗丟丠両丣並丩丮丯丱丳丵丷丼乀乁乂乄乆乊乑乕乗乚乛乢乣乤乥乧乨乪",5,"乲乴",9,"乿",6,"亇亊"],["8180","亐亖亗亙亜亝亞亣亪亯亰亱亴亶亷亸亹亼亽亾仈仌仏仐仒仚仛仜仠仢仦仧仩仭仮仯仱仴仸仹仺仼仾伀伂",6,"伋伌伒",4,"伜伝伡伣伨伩伬伭伮伱伳伵伷伹伻伾",4,"佄佅佇",5,"佒佔佖佡佢佦佨佪佫佭佮佱佲併佷佸佹佺佽侀侁侂侅來侇侊侌侎侐侒侓侕侖侘侙侚侜侞侟価侢"],["8240","侤侫侭侰",4,"侶",8,"俀俁係俆俇俈俉俋俌俍俒",4,"俙俛俠俢俤俥俧俫俬俰俲俴俵俶俷俹俻俼俽俿",11],["8280","個倎倐們倓倕倖倗倛倝倞倠倢倣値倧倫倯",10,"倻倽倿偀偁偂偄偅偆偉偊偋偍偐",4,"偖偗偘偙偛偝",7,"偦",5,"偭",8,"偸偹偺偼偽傁傂傃傄傆傇傉傊傋傌傎",20,"傤傦傪傫傭",4,"傳",6,"傼"],["8340","傽",17,"僐",5,"僗僘僙僛",10,"僨僩僪僫僯僰僱僲僴僶",4,"僼",9,"儈"],["8380","儉儊儌",5,"儓",13,"儢",28,"兂兇兊兌兎兏児兒兓兗兘兙兛兝",4,"兣兤兦內兩兪兯兲兺兾兿冃冄円冇冊冋冎冏冐冑冓冔冘冚冝冞冟冡冣冦",4,"冭冮冴冸冹冺冾冿凁凂凃凅凈凊凍凎凐凒",5],["8440","凘凙凚凜凞凟凢凣凥",5,"凬凮凱凲凴凷凾刄刅刉刋刌刏刐刓刔刕刜刞刟刡刢刣別刦刧刪刬刯刱刲刴刵刼刾剄",5,"剋剎剏剒剓剕剗剘"],["8480","剙剚剛剝剟剠剢剣剤剦剨剫剬剭剮剰剱剳",9,"剾劀劃",4,"劉",6,"劑劒劔",6,"劜劤劥劦劧劮劯劰労",9,"勀勁勂勄勅勆勈勊勌勍勎勏勑勓勔動勗務",5,"勠勡勢勣勥",10,"勱",7,"勻勼勽匁匂匃匄匇匉匊匋匌匎"],["8540","匑匒匓匔匘匛匜匞匟匢匤匥匧匨匩匫匬匭匯",9,"匼匽區卂卄卆卋卌卍卐協単卙卛卝卥卨卪卬卭卲卶卹卻卼卽卾厀厁厃厇厈厊厎厏"],["8580","厐",4,"厖厗厙厛厜厞厠厡厤厧厪厫厬厭厯",6,"厷厸厹厺厼厽厾叀參",4,"収叏叐叒叓叕叚叜叝叞叡叢叧叴叺叾叿吀吂吅吇吋吔吘吙吚吜吢吤吥吪吰吳吶吷吺吽吿呁呂呄呅呇呉呌呍呎呏呑呚呝",4,"呣呥呧呩",7,"呴呹呺呾呿咁咃咅咇咈咉咊咍咑咓咗咘咜咞咟咠咡"],["8640","咢咥咮咰咲咵咶咷咹咺咼咾哃哅哊哋哖哘哛哠",4,"哫哬哯哰哱哴",5,"哻哾唀唂唃唄唅唈唊",4,"唒唓唕",5,"唜唝唞唟唡唥唦"],["8680","唨唩唫唭唲唴唵唶唸唹唺唻唽啀啂啅啇啈啋",4,"啑啒啓啔啗",4,"啝啞啟啠啢啣啨啩啫啯",5,"啹啺啽啿喅喆喌喍喎喐喒喓喕喖喗喚喛喞喠",6,"喨",8,"喲喴営喸喺喼喿",4,"嗆嗇嗈嗊嗋嗎嗏嗐嗕嗗",4,"嗞嗠嗢嗧嗩嗭嗮嗰嗱嗴嗶嗸",4,"嗿嘂嘃嘄嘅"],["8740","嘆嘇嘊嘋嘍嘐",7,"嘙嘚嘜嘝嘠嘡嘢嘥嘦嘨嘩嘪嘫嘮嘯嘰嘳嘵嘷嘸嘺嘼嘽嘾噀",11,"噏",4,"噕噖噚噛噝",4],["8780","噣噥噦噧噭噮噯噰噲噳噴噵噷噸噹噺噽",7,"嚇",6,"嚐嚑嚒嚔",14,"嚤",10,"嚰",6,"嚸嚹嚺嚻嚽",12,"囋",8,"囕囖囘囙囜団囥",5,"囬囮囯囲図囶囷囸囻囼圀圁圂圅圇國",6],["8840","園",9,"圝圞圠圡圢圤圥圦圧圫圱圲圴",4,"圼圽圿坁坃坄坅坆坈坉坋坒",4,"坘坙坢坣坥坧坬坮坰坱坲坴坵坸坹坺坽坾坿垀"],["8880","垁垇垈垉垊垍",4,"垔",6,"垜垝垞垟垥垨垪垬垯垰垱垳垵垶垷垹",8,"埄",6,"埌埍埐埑埓埖埗埛埜埞埡埢埣埥",7,"埮埰埱埲埳埵埶執埻埼埾埿堁堃堄堅堈堉堊堌堎堏堐堒堓堔堖堗堘堚堛堜堝堟堢堣堥",4,"堫",4,"報堲堳場堶",7],["8940","堾",5,"塅",6,"塎塏塐塒塓塕塖塗塙",4,"塟",5,"塦",4,"塭",16,"塿墂墄墆墇墈墊墋墌"],["8980","墍",4,"墔",4,"墛墜墝墠",7,"墪",17,"墽墾墿壀壂壃壄壆",10,"壒壓壔壖",13,"壥",5,"壭壯壱売壴壵壷壸壺",7,"夃夅夆夈",4,"夎夐夑夒夓夗夘夛夝夞夠夡夢夣夦夨夬夰夲夳夵夶夻"],["8a40","夽夾夿奀奃奅奆奊奌奍奐奒奓奙奛",4,"奡奣奤奦",12,"奵奷奺奻奼奾奿妀妅妉妋妌妎妏妐妑妔妕妘妚妛妜妝妟妠妡妢妦"],["8a80","妧妬妭妰妱妳",5,"妺妼妽妿",6,"姇姈姉姌姍姎姏姕姖姙姛姞",4,"姤姦姧姩姪姫姭",11,"姺姼姽姾娀娂娊娋娍娎娏娐娒娔娕娖娗娙娚娛娝娞娡娢娤娦娧娨娪",6,"娳娵娷",4,"娽娾娿婁",4,"婇婈婋",9,"婖婗婘婙婛",5],["8b40","婡婣婤婥婦婨婩婫",8,"婸婹婻婼婽婾媀",17,"媓",6,"媜",13,"媫媬"],["8b80","媭",4,"媴媶媷媹",4,"媿嫀嫃",5,"嫊嫋嫍",4,"嫓嫕嫗嫙嫚嫛嫝嫞嫟嫢嫤嫥嫧嫨嫪嫬",4,"嫲",22,"嬊",11,"嬘",25,"嬳嬵嬶嬸",7,"孁",6],["8c40","孈",7,"孒孖孞孠孡孧孨孫孭孮孯孲孴孶孷學孹孻孼孾孿宂宆宊宍宎宐宑宒宔宖実宧宨宩宬宭宮宯宱宲宷宺宻宼寀寁寃寈寉寊寋寍寎寏"],["8c80","寑寔",8,"寠寢寣實寧審",4,"寯寱",6,"寽対尀専尃尅將專尋尌對導尐尒尓尗尙尛尞尟尠尡尣尦尨尩尪尫尭尮尯尰尲尳尵尶尷屃屄屆屇屌屍屒屓屔屖屗屘屚屛屜屝屟屢層屧",6,"屰屲",6,"屻屼屽屾岀岃",4,"岉岊岋岎岏岒岓岕岝",4,"岤",4],["8d40","岪岮岯岰岲岴岶岹岺岻岼岾峀峂峃峅",5,"峌",5,"峓",5,"峚",6,"峢峣峧峩峫峬峮峯峱",9,"峼",4],["8d80","崁崄崅崈",5,"崏",4,"崕崗崘崙崚崜崝崟",4,"崥崨崪崫崬崯",4,"崵",7,"崿",7,"嵈嵉嵍",10,"嵙嵚嵜嵞",10,"嵪嵭嵮嵰嵱嵲嵳嵵",12,"嶃",21,"嶚嶛嶜嶞嶟嶠"],["8e40","嶡",21,"嶸",12,"巆",6,"巎",12,"巜巟巠巣巤巪巬巭"],["8e80","巰巵巶巸",4,"巿帀帄帇帉帊帋帍帎帒帓帗帞",7,"帨",4,"帯帰帲",4,"帹帺帾帿幀幁幃幆",5,"幍",6,"幖",4,"幜幝幟幠幣",14,"幵幷幹幾庁庂広庅庈庉庌庍庎庒庘庛庝庡庢庣庤庨",4,"庮",4,"庴庺庻庼庽庿",6],["8f40","廆廇廈廋",5,"廔廕廗廘廙廚廜",11,"廩廫",8,"廵廸廹廻廼廽弅弆弇弉弌弍弎弐弒弔弖弙弚弜弝弞弡弢弣弤"],["8f80","弨弫弬弮弰弲",6,"弻弽弾弿彁",14,"彑彔彙彚彛彜彞彟彠彣彥彧彨彫彮彯彲彴彵彶彸彺彽彾彿徃徆徍徎徏徑従徔徖徚徛徝從徟徠徢",5,"復徫徬徯",5,"徶徸徹徺徻徾",4,"忇忈忊忋忎忓忔忕忚忛応忞忟忢忣忥忦忨忩忬忯忰忲忳忴忶忷忹忺忼怇"],["9040","怈怉怋怌怐怑怓怗怘怚怞怟怢怣怤怬怭怮怰",4,"怶",4,"怽怾恀恄",6,"恌恎恏恑恓恔恖恗恘恛恜恞恟恠恡恥恦恮恱恲恴恵恷恾悀"],["9080","悁悂悅悆悇悈悊悋悎悏悐悑悓悕悗悘悙悜悞悡悢悤悥悧悩悪悮悰悳悵悶悷悹悺悽",7,"惇惈惉惌",4,"惒惓惔惖惗惙惛惞惡",4,"惪惱惲惵惷惸惻",4,"愂愃愄愅愇愊愋愌愐",4,"愖愗愘愙愛愜愝愞愡愢愥愨愩愪愬",18,"慀",6],["9140","慇慉態慍慏慐慒慓慔慖",6,"慞慟慠慡慣慤慥慦慩",6,"慱慲慳慴慶慸",18,"憌憍憏",4,"憕"],["9180","憖",6,"憞",8,"憪憫憭",9,"憸",5,"憿懀懁懃",4,"應懌",4,"懓懕",16,"懧",13,"懶",8,"戀",5,"戇戉戓戔戙戜戝戞戠戣戦戧戨戩戫戭戯戰戱戲戵戶戸",4,"扂扄扅扆扊"],["9240","扏扐払扖扗扙扚扜",6,"扤扥扨扱扲扴扵扷扸扺扻扽抁抂抃抅抆抇抈抋",5,"抔抙抜抝択抣抦抧抩抪抭抮抯抰抲抳抴抶抷抸抺抾拀拁"],["9280","拃拋拏拑拕拝拞拠拡拤拪拫拰拲拵拸拹拺拻挀挃挄挅挆挊挋挌挍挏挐挒挓挔挕挗挘挙挜挦挧挩挬挭挮挰挱挳",5,"挻挼挾挿捀捁捄捇捈捊捑捒捓捔捖",7,"捠捤捥捦捨捪捫捬捯捰捲捳捴捵捸捹捼捽捾捿掁掃掄掅掆掋掍掑掓掔掕掗掙",6,"採掤掦掫掯掱掲掵掶掹掻掽掿揀"],["9340","揁揂揃揅揇揈揊揋揌揑揓揔揕揗",6,"揟揢揤",4,"揫揬揮揯揰揱揳揵揷揹揺揻揼揾搃搄搆",4,"損搎搑搒搕",5,"搝搟搢搣搤"],["9380","搥搧搨搩搫搮",5,"搵",4,"搻搼搾摀摂摃摉摋",6,"摓摕摖摗摙",4,"摟",7,"摨摪摫摬摮",9,"摻",6,"撃撆撈",8,"撓撔撗撘撚撛撜撝撟",4,"撥撦撧撨撪撫撯撱撲撳撴撶撹撻撽撾撿擁擃擄擆",6,"擏擑擓擔擕擖擙據"],["9440","擛擜擝擟擠擡擣擥擧",24,"攁",7,"攊",7,"攓",4,"攙",8],["9480","攢攣攤攦",4,"攬攭攰攱攲攳攷攺攼攽敀",4,"敆敇敊敋敍敎敐敒敓敔敗敘敚敜敟敠敡敤敥敧敨敩敪敭敮敯敱敳敵敶數",14,"斈斉斊斍斎斏斒斔斕斖斘斚斝斞斠斢斣斦斨斪斬斮斱",7,"斺斻斾斿旀旂旇旈旉旊旍旐旑旓旔旕旘",7,"旡旣旤旪旫"],["9540","旲旳旴旵旸旹旻",4,"昁昄昅昇昈昉昋昍昐昑昒昖昗昘昚昛昜昞昡昢昣昤昦昩昪昫昬昮昰昲昳昷",4,"昽昿晀時晄",6,"晍晎晐晑晘"],["9580","晙晛晜晝晞晠晢晣晥晧晩",4,"晱晲晳晵晸晹晻晼晽晿暀暁暃暅暆暈暉暊暋暍暎暏暐暒暓暔暕暘",4,"暞",8,"暩",4,"暯",4,"暵暶暷暸暺暻暼暽暿",25,"曚曞",7,"曧曨曪",5,"曱曵曶書曺曻曽朁朂會"],["9640","朄朅朆朇朌朎朏朑朒朓朖朘朙朚朜朞朠",5,"朧朩朮朰朲朳朶朷朸朹朻朼朾朿杁杄杅杇杊杋杍杒杔杕杗",4,"杝杢杣杤杦杧杫杬杮東杴杶"],["9680","杸杹杺杻杽枀枂枃枅枆枈枊枌枍枎枏枑枒枓枔枖枙枛枟枠枡枤枦枩枬枮枱枲枴枹",7,"柂柅",9,"柕柖柗柛柟柡柣柤柦柧柨柪柫柭柮柲柵",7,"柾栁栂栃栄栆栍栐栒栔栕栘",4,"栞栟栠栢",6,"栫",6,"栴栵栶栺栻栿桇桋桍桏桒桖",5],["9740","桜桝桞桟桪桬",7,"桵桸",8,"梂梄梇",7,"梐梑梒梔梕梖梘",9,"梣梤梥梩梪梫梬梮梱梲梴梶梷梸"],["9780","梹",6,"棁棃",5,"棊棌棎棏棐棑棓棔棖棗棙棛",4,"棡棢棤",9,"棯棲棳棴棶棷棸棻棽棾棿椀椂椃椄椆",4,"椌椏椑椓",11,"椡椢椣椥",7,"椮椯椱椲椳椵椶椷椸椺椻椼椾楀楁楃",16,"楕楖楘楙楛楜楟"],["9840","楡楢楤楥楧楨楩楪楬業楯楰楲",4,"楺楻楽楾楿榁榃榅榊榋榌榎",5,"榖榗榙榚榝",9,"榩榪榬榮榯榰榲榳榵榶榸榹榺榼榽"],["9880","榾榿槀槂",7,"構槍槏槑槒槓槕",5,"槜槝槞槡",11,"槮槯槰槱槳",9,"槾樀",9,"樋",11,"標",5,"樠樢",5,"権樫樬樭樮樰樲樳樴樶",6,"樿",4,"橅橆橈",7,"橑",6,"橚"],["9940","橜",4,"橢橣橤橦",10,"橲",6,"橺橻橽橾橿檁檂檃檅",8,"檏檒",4,"檘",7,"檡",5],["9980","檧檨檪檭",114,"欥欦欨",6],["9a40","欯欰欱欳欴欵欶欸欻欼欽欿歀歁歂歄歅歈歊歋歍",11,"歚",7,"歨歩歫",13,"歺歽歾歿殀殅殈"],["9a80","殌殎殏殐殑殔殕殗殘殙殜",4,"殢",7,"殫",7,"殶殸",6,"毀毃毄毆",4,"毌毎毐毑毘毚毜",4,"毢",7,"毬毭毮毰毱毲毴毶毷毸毺毻毼毾",6,"氈",4,"氎氒気氜氝氞氠氣氥氫氬氭氱氳氶氷氹氺氻氼氾氿汃汄汅汈汋",4,"汑汒汓汖汘"],["9b40","汙汚汢汣汥汦汧汫",4,"汱汳汵汷汸決汻汼汿沀沄沇沊沋沍沎沑沒沕沖沗沘沚沜沝沞沠沢沨沬沯沰沴沵沶沷沺泀況泂泃泆泇泈泋泍泎泏泑泒泘"],["9b80","泙泚泜泝泟泤泦泧泩泬泭泲泴泹泿洀洂洃洅洆洈洉洊洍洏洐洑洓洔洕洖洘洜洝洟",5,"洦洨洩洬洭洯洰洴洶洷洸洺洿浀浂浄浉浌浐浕浖浗浘浛浝浟浡浢浤浥浧浨浫浬浭浰浱浲浳浵浶浹浺浻浽",4,"涃涄涆涇涊涋涍涏涐涒涖",4,"涜涢涥涬涭涰涱涳涴涶涷涹",5,"淁淂淃淈淉淊"],["9c40","淍淎淏淐淒淓淔淕淗淚淛淜淟淢淣淥淧淨淩淪淭淯淰淲淴淵淶淸淺淽",7,"渆渇済渉渋渏渒渓渕渘渙減渜渞渟渢渦渧渨渪測渮渰渱渳渵"],["9c80","渶渷渹渻",7,"湅",7,"湏湐湑湒湕湗湙湚湜湝湞湠",10,"湬湭湯",14,"満溁溂溄溇溈溊",4,"溑",6,"溙溚溛溝溞溠溡溣溤溦溨溩溫溬溭溮溰溳溵溸溹溼溾溿滀滃滄滅滆滈滉滊滌滍滎滐滒滖滘滙滛滜滝滣滧滪",5],["9d40","滰滱滲滳滵滶滷滸滺",7,"漃漄漅漇漈漊",4,"漐漑漒漖",9,"漡漢漣漥漦漧漨漬漮漰漲漴漵漷",6,"漿潀潁潂"],["9d80","潃潄潅潈潉潊潌潎",9,"潙潚潛潝潟潠潡潣潤潥潧",5,"潯潰潱潳潵潶潷潹潻潽",6,"澅澆澇澊澋澏",12,"澝澞澟澠澢",4,"澨",10,"澴澵澷澸澺",5,"濁濃",5,"濊",6,"濓",10,"濟濢濣濤濥"],["9e40","濦",7,"濰",32,"瀒",7,"瀜",6,"瀤",6],["9e80","瀫",9,"瀶瀷瀸瀺",17,"灍灎灐",13,"灟",11,"灮灱灲灳灴灷灹灺灻災炁炂炃炄炆炇炈炋炌炍炏炐炑炓炗炘炚炛炞",12,"炰炲炴炵炶為炾炿烄烅烆烇烉烋",12,"烚"],["9f40","烜烝烞烠烡烢烣烥烪烮烰",6,"烸烺烻烼烾",10,"焋",4,"焑焒焔焗焛",10,"焧",7,"焲焳焴"],["9f80","焵焷",13,"煆煇煈煉煋煍煏",12,"煝煟",4,"煥煩",4,"煯煰煱煴煵煶煷煹煻煼煾",5,"熅",4,"熋熌熍熎熐熑熒熓熕熖熗熚",4,"熡",6,"熩熪熫熭",5,"熴熶熷熸熺",8,"燄",9,"燏",4],["a040","燖",9,"燡燢燣燤燦燨",5,"燯",9,"燺",11,"爇",19],["a080","爛爜爞",9,"爩爫爭爮爯爲爳爴爺爼爾牀",6,"牉牊牋牎牏牐牑牓牔牕牗牘牚牜牞牠牣牤牥牨牪牫牬牭牰牱牳牴牶牷牸牻牼牽犂犃犅",4,"犌犎犐犑犓",11,"犠",11,"犮犱犲犳犵犺",6,"狅狆狇狉狊狋狌狏狑狓狔狕狖狘狚狛"],["a1a1","　、。·ˉˇ¨〃々—～‖…‘’“”〔〕〈",7,"〖〗【】±×÷∶∧∨∑∏∪∩∈∷√⊥∥∠⌒⊙∫∮≡≌≈∽∝≠≮≯≤≥∞∵∴♂♀°′″℃＄¤￠￡‰§№☆★○●◎◇◆□■△▲※→←↑↓〓"],["a2a1","ⅰ",9],["a2b1","⒈",19,"⑴",19,"①",9],["a2e5","㈠",9],["a2f1","Ⅰ",11],["a3a1","！＂＃￥％",88,"￣"],["a4a1","ぁ",82],["a5a1","ァ",85],["a6a1","Α",16,"Σ",6],["a6c1","α",16,"σ",6],["a6e0","︵︶︹︺︿﹀︽︾﹁﹂﹃﹄"],["a6ee","︻︼︷︸︱"],["a6f4","︳︴"],["a7a1","А",5,"ЁЖ",25],["a7d1","а",5,"ёж",25],["a840","ˊˋ˙–―‥‵℅℉↖↗↘↙∕∟∣≒≦≧⊿═",35,"▁",6],["a880","█",7,"▓▔▕▼▽◢◣◤◥☉⊕〒〝〞"],["a8a1","āáǎàēéěèīíǐìōóǒòūúǔùǖǘǚǜüêɑ"],["a8bd","ńň"],["a8c0","ɡ"],["a8c5","ㄅ",36],["a940","〡",8,"㊣㎎㎏㎜㎝㎞㎡㏄㏎㏑㏒㏕︰￢￤"],["a959","℡㈱"],["a95c","‐"],["a960","ー゛゜ヽヾ〆ゝゞ﹉",9,"﹔﹕﹖﹗﹙",8],["a980","﹢",4,"﹨﹩﹪﹫"],["a996","〇"],["a9a4","─",75],["aa40","狜狝狟狢",5,"狪狫狵狶狹狽狾狿猀猂猄",5,"猋猌猍猏猐猑猒猔猘猙猚猟猠猣猤猦猧猨猭猯猰猲猳猵猶猺猻猼猽獀",8],["aa80","獉獊獋獌獎獏獑獓獔獕獖獘",7,"獡",10,"獮獰獱"],["ab40","獲",11,"獿",4,"玅玆玈玊玌玍玏玐玒玓玔玕玗玘玙玚玜玝玞玠玡玣",5,"玪玬玭玱玴玵玶玸玹玼玽玾玿珁珃",4],["ab80","珋珌珎珒",6,"珚珛珜珝珟珡珢珣珤珦珨珪珫珬珮珯珰珱珳",4],["ac40","珸",10,"琄琇琈琋琌琍琎琑",8,"琜",5,"琣琤琧琩琫琭琯琱琲琷",4,"琽琾琿瑀瑂",11],["ac80","瑎",6,"瑖瑘瑝瑠",12,"瑮瑯瑱",4,"瑸瑹瑺"],["ad40","瑻瑼瑽瑿璂璄璅璆璈璉璊璌璍璏璑",10,"璝璟",7,"璪",15,"璻",12],["ad80","瓈",9,"瓓",8,"瓝瓟瓡瓥瓧",6,"瓰瓱瓲"],["ae40","瓳瓵瓸",6,"甀甁甂甃甅",7,"甎甐甒甔甕甖甗甛甝甞甠",4,"甦甧甪甮甴甶甹甼甽甿畁畂畃畄畆畇畉畊畍畐畑畒畓畕畖畗畘"],["ae80","畝",7,"畧畨畩畫",6,"畳畵當畷畺",4,"疀疁疂疄疅疇"],["af40","疈疉疊疌疍疎疐疓疕疘疛疜疞疢疦",4,"疭疶疷疺疻疿痀痁痆痋痌痎痏痐痑痓痗痙痚痜痝痟痠痡痥痩痬痭痮痯痲痳痵痶痷痸痺痻痽痾瘂瘄瘆瘇"],["af80","瘈瘉瘋瘍瘎瘏瘑瘒瘓瘔瘖瘚瘜瘝瘞瘡瘣瘧瘨瘬瘮瘯瘱瘲瘶瘷瘹瘺瘻瘽癁療癄"],["b040","癅",6,"癎",5,"癕癗",4,"癝癟癠癡癢癤",6,"癬癭癮癰",7,"癹発發癿皀皁皃皅皉皊皌皍皏皐皒皔皕皗皘皚皛"],["b080","皜",7,"皥",8,"皯皰皳皵",9,"盀盁盃啊阿埃挨哎唉哀皑癌蔼矮艾碍爱隘鞍氨安俺按暗岸胺案肮昂盎凹敖熬翱袄傲奥懊澳芭捌扒叭吧笆八疤巴拔跋靶把耙坝霸罢爸白柏百摆佰败拜稗斑班搬扳般颁板版扮拌伴瓣半办绊邦帮梆榜膀绑棒磅蚌镑傍谤苞胞包褒剥"],["b140","盄盇盉盋盌盓盕盙盚盜盝盞盠",4,"盦",7,"盰盳盵盶盷盺盻盽盿眀眂眃眅眆眊県眎",10,"眛眜眝眞眡眣眤眥眧眪眫"],["b180","眬眮眰",4,"眹眻眽眾眿睂睄睅睆睈",7,"睒",7,"睜薄雹保堡饱宝抱报暴豹鲍爆杯碑悲卑北辈背贝钡倍狈备惫焙被奔苯本笨崩绷甭泵蹦迸逼鼻比鄙笔彼碧蓖蔽毕毙毖币庇痹闭敝弊必辟壁臂避陛鞭边编贬扁便变卞辨辩辫遍标彪膘表鳖憋别瘪彬斌濒滨宾摈兵冰柄丙秉饼炳"],["b240","睝睞睟睠睤睧睩睪睭",11,"睺睻睼瞁瞂瞃瞆",5,"瞏瞐瞓",11,"瞡瞣瞤瞦瞨瞫瞭瞮瞯瞱瞲瞴瞶",4],["b280","瞼瞾矀",12,"矎",8,"矘矙矚矝",4,"矤病并玻菠播拨钵波博勃搏铂箔伯帛舶脖膊渤泊驳捕卜哺补埠不布步簿部怖擦猜裁材才财睬踩采彩菜蔡餐参蚕残惭惨灿苍舱仓沧藏操糙槽曹草厕策侧册测层蹭插叉茬茶查碴搽察岔差诧拆柴豺搀掺蝉馋谗缠铲产阐颤昌猖"],["b340","矦矨矪矯矰矱矲矴矵矷矹矺矻矼砃",5,"砊砋砎砏砐砓砕砙砛砞砠砡砢砤砨砪砫砮砯砱砲砳砵砶砽砿硁硂硃硄硆硈硉硊硋硍硏硑硓硔硘硙硚"],["b380","硛硜硞",11,"硯",7,"硸硹硺硻硽",6,"场尝常长偿肠厂敞畅唱倡超抄钞朝嘲潮巢吵炒车扯撤掣彻澈郴臣辰尘晨忱沉陈趁衬撑称城橙成呈乘程惩澄诚承逞骋秤吃痴持匙池迟弛驰耻齿侈尺赤翅斥炽充冲虫崇宠抽酬畴踌稠愁筹仇绸瞅丑臭初出橱厨躇锄雏滁除楚"],["b440","碄碅碆碈碊碋碏碐碒碔碕碖碙碝碞碠碢碤碦碨",7,"碵碶碷碸確碻碼碽碿磀磂磃磄磆磇磈磌磍磎磏磑磒磓磖磗磘磚",9],["b480","磤磥磦磧磩磪磫磭",4,"磳磵磶磸磹磻",5,"礂礃礄礆",6,"础储矗搐触处揣川穿椽传船喘串疮窗幢床闯创吹炊捶锤垂春椿醇唇淳纯蠢戳绰疵茨磁雌辞慈瓷词此刺赐次聪葱囱匆从丛凑粗醋簇促蹿篡窜摧崔催脆瘁粹淬翠村存寸磋撮搓措挫错搭达答瘩打大呆歹傣戴带殆代贷袋待逮"],["b540","礍",5,"礔",9,"礟",4,"礥",14,"礵",4,"礽礿祂祃祄祅祇祊",8,"祔祕祘祙祡祣"],["b580","祤祦祩祪祫祬祮祰",6,"祹祻",4,"禂禃禆禇禈禉禋禌禍禎禐禑禒怠耽担丹单郸掸胆旦氮但惮淡诞弹蛋当挡党荡档刀捣蹈倒岛祷导到稻悼道盗德得的蹬灯登等瞪凳邓堤低滴迪敌笛狄涤翟嫡抵底地蒂第帝弟递缔颠掂滇碘点典靛垫电佃甸店惦奠淀殿碉叼雕凋刁掉吊钓调跌爹碟蝶迭谍叠"],["b640","禓",6,"禛",11,"禨",10,"禴",4,"禼禿秂秄秅秇秈秊秌秎秏秐秓秔秖秗秙",5,"秠秡秢秥秨秪"],["b680","秬秮秱",6,"秹秺秼秾秿稁稄稅稇稈稉稊稌稏",4,"稕稖稘稙稛稜丁盯叮钉顶鼎锭定订丢东冬董懂动栋侗恫冻洞兜抖斗陡豆逗痘都督毒犊独读堵睹赌杜镀肚度渡妒端短锻段断缎堆兑队对墩吨蹲敦顿囤钝盾遁掇哆多夺垛躲朵跺舵剁惰堕蛾峨鹅俄额讹娥恶厄扼遏鄂饿恩而儿耳尔饵洱二"],["b740","稝稟稡稢稤",14,"稴稵稶稸稺稾穀",5,"穇",9,"穒",4,"穘",16],["b780","穩",6,"穱穲穳穵穻穼穽穾窂窅窇窉窊窋窌窎窏窐窓窔窙窚窛窞窡窢贰发罚筏伐乏阀法珐藩帆番翻樊矾钒繁凡烦反返范贩犯饭泛坊芳方肪房防妨仿访纺放菲非啡飞肥匪诽吠肺废沸费芬酚吩氛分纷坟焚汾粉奋份忿愤粪丰封枫蜂峰锋风疯烽逢冯缝讽奉凤佛否夫敷肤孵扶拂辐幅氟符伏俘服"],["b840","窣窤窧窩窪窫窮",4,"窴",10,"竀",10,"竌",9,"竗竘竚竛竜竝竡竢竤竧",5,"竮竰竱竲竳"],["b880","竴",4,"竻竼竾笀笁笂笅笇笉笌笍笎笐笒笓笖笗笘笚笜笝笟笡笢笣笧笩笭浮涪福袱弗甫抚辅俯釜斧脯腑府腐赴副覆赋复傅付阜父腹负富讣附妇缚咐噶嘎该改概钙盖溉干甘杆柑竿肝赶感秆敢赣冈刚钢缸肛纲岗港杠篙皋高膏羔糕搞镐稿告哥歌搁戈鸽胳疙割革葛格蛤阁隔铬个各给根跟耕更庚羹"],["b940","笯笰笲笴笵笶笷笹笻笽笿",5,"筆筈筊筍筎筓筕筗筙筜筞筟筡筣",10,"筯筰筳筴筶筸筺筼筽筿箁箂箃箄箆",6,"箎箏"],["b980","箑箒箓箖箘箙箚箛箞箟箠箣箤箥箮箯箰箲箳箵箶箷箹",7,"篂篃範埂耿梗工攻功恭龚供躬公宫弓巩汞拱贡共钩勾沟苟狗垢构购够辜菇咕箍估沽孤姑鼓古蛊骨谷股故顾固雇刮瓜剐寡挂褂乖拐怪棺关官冠观管馆罐惯灌贯光广逛瑰规圭硅归龟闺轨鬼诡癸桂柜跪贵刽辊滚棍锅郭国果裹过哈"],["ba40","篅篈築篊篋篍篎篏篐篒篔",4,"篛篜篞篟篠篢篣篤篧篨篩篫篬篭篯篰篲",4,"篸篹篺篻篽篿",7,"簈簉簊簍簎簐",5,"簗簘簙"],["ba80","簚",4,"簠",5,"簨簩簫",12,"簹",5,"籂骸孩海氦亥害骇酣憨邯韩含涵寒函喊罕翰撼捍旱憾悍焊汗汉夯杭航壕嚎豪毫郝好耗号浩呵喝荷菏核禾和何合盒貉阂河涸赫褐鹤贺嘿黑痕很狠恨哼亨横衡恒轰哄烘虹鸿洪宏弘红喉侯猴吼厚候后呼乎忽瑚壶葫胡蝴狐糊湖"],["bb40","籃",9,"籎",36,"籵",5,"籾",9],["bb80","粈粊",6,"粓粔粖粙粚粛粠粡粣粦粧粨粩粫粬粭粯粰粴",4,"粺粻弧虎唬护互沪户花哗华猾滑画划化话槐徊怀淮坏欢环桓还缓换患唤痪豢焕涣宦幻荒慌黄磺蝗簧皇凰惶煌晃幌恍谎灰挥辉徽恢蛔回毁悔慧卉惠晦贿秽会烩汇讳诲绘荤昏婚魂浑混豁活伙火获或惑霍货祸击圾基机畸稽积箕"],["bc40","粿糀糂糃糄糆糉糋糎",6,"糘糚糛糝糞糡",6,"糩",5,"糰",7,"糹糺糼",13,"紋",5],["bc80","紑",14,"紡紣紤紥紦紨紩紪紬紭紮細",6,"肌饥迹激讥鸡姬绩缉吉极棘辑籍集及急疾汲即嫉级挤几脊己蓟技冀季伎祭剂悸济寄寂计记既忌际妓继纪嘉枷夹佳家加荚颊贾甲钾假稼价架驾嫁歼监坚尖笺间煎兼肩艰奸缄茧检柬碱硷拣捡简俭剪减荐槛鉴践贱见键箭件"],["bd40","紷",54,"絯",7],["bd80","絸",32,"健舰剑饯渐溅涧建僵姜将浆江疆蒋桨奖讲匠酱降蕉椒礁焦胶交郊浇骄娇嚼搅铰矫侥脚狡角饺缴绞剿教酵轿较叫窖揭接皆秸街阶截劫节桔杰捷睫竭洁结解姐戒藉芥界借介疥诫届巾筋斤金今津襟紧锦仅谨进靳晋禁近烬浸"],["be40","継",12,"綧",6,"綯",42],["be80","線",32,"尽劲荆兢茎睛晶鲸京惊精粳经井警景颈静境敬镜径痉靖竟竞净炯窘揪究纠玖韭久灸九酒厩救旧臼舅咎就疚鞠拘狙疽居驹菊局咀矩举沮聚拒据巨具距踞锯俱句惧炬剧捐鹃娟倦眷卷绢撅攫抉掘倔爵觉决诀绝均菌钧军君峻"],["bf40","緻",62],["bf80","縺縼",4,"繂",4,"繈",21,"俊竣浚郡骏喀咖卡咯开揩楷凯慨刊堪勘坎砍看康慷糠扛抗亢炕考拷烤靠坷苛柯棵磕颗科壳咳可渴克刻客课肯啃垦恳坑吭空恐孔控抠口扣寇枯哭窟苦酷库裤夸垮挎跨胯块筷侩快宽款匡筐狂框矿眶旷况亏盔岿窥葵奎魁傀"],["c040","繞",35,"纃",23,"纜纝纞"],["c080","纮纴纻纼绖绤绬绹缊缐缞缷缹缻",6,"罃罆",9,"罒罓馈愧溃坤昆捆困括扩廓阔垃拉喇蜡腊辣啦莱来赖蓝婪栏拦篮阑兰澜谰揽览懒缆烂滥琅榔狼廊郎朗浪捞劳牢老佬姥酪烙涝勒乐雷镭蕾磊累儡垒擂肋类泪棱楞冷厘梨犁黎篱狸离漓理李里鲤礼莉荔吏栗丽厉励砾历利傈例俐"],["c140","罖罙罛罜罝罞罠罣",4,"罫罬罭罯罰罳罵罶罷罸罺罻罼罽罿羀羂",7,"羋羍羏",4,"羕",4,"羛羜羠羢羣羥羦羨",6,"羱"],["c180","羳",4,"羺羻羾翀翂翃翄翆翇翈翉翋翍翏",4,"翖翗翙",5,"翢翣痢立粒沥隶力璃哩俩联莲连镰廉怜涟帘敛脸链恋炼练粮凉梁粱良两辆量晾亮谅撩聊僚疗燎寥辽潦了撂镣廖料列裂烈劣猎琳林磷霖临邻鳞淋凛赁吝拎玲菱零龄铃伶羚凌灵陵岭领另令溜琉榴硫馏留刘瘤流柳六龙聋咙笼窿"],["c240","翤翧翨翪翫翬翭翯翲翴",6,"翽翾翿耂耇耈耉耊耎耏耑耓耚耛耝耞耟耡耣耤耫",5,"耲耴耹耺耼耾聀聁聄聅聇聈聉聎聏聐聑聓聕聖聗"],["c280","聙聛",13,"聫",5,"聲",11,"隆垄拢陇楼娄搂篓漏陋芦卢颅庐炉掳卤虏鲁麓碌露路赂鹿潞禄录陆戮驴吕铝侣旅履屡缕虑氯律率滤绿峦挛孪滦卵乱掠略抡轮伦仑沦纶论萝螺罗逻锣箩骡裸落洛骆络妈麻玛码蚂马骂嘛吗埋买麦卖迈脉瞒馒蛮满蔓曼慢漫"],["c340","聾肁肂肅肈肊肍",5,"肔肕肗肙肞肣肦肧肨肬肰肳肵肶肸肹肻胅胇",4,"胏",6,"胘胟胠胢胣胦胮胵胷胹胻胾胿脀脁脃脄脅脇脈脋"],["c380","脌脕脗脙脛脜脝脟",12,"脭脮脰脳脴脵脷脹",4,"脿谩芒茫盲氓忙莽猫茅锚毛矛铆卯茂冒帽貌贸么玫枚梅酶霉煤没眉媒镁每美昧寐妹媚门闷们萌蒙檬盟锰猛梦孟眯醚靡糜迷谜弥米秘觅泌蜜密幂棉眠绵冕免勉娩缅面苗描瞄藐秒渺庙妙蔑灭民抿皿敏悯闽明螟鸣铭名命谬摸"],["c440","腀",5,"腇腉腍腎腏腒腖腗腘腛",4,"腡腢腣腤腦腨腪腫腬腯腲腳腵腶腷腸膁膃",4,"膉膋膌膍膎膐膒",5,"膙膚膞",4,"膤膥"],["c480","膧膩膫",7,"膴",5,"膼膽膾膿臄臅臇臈臉臋臍",6,"摹蘑模膜磨摩魔抹末莫墨默沫漠寞陌谋牟某拇牡亩姆母墓暮幕募慕木目睦牧穆拿哪呐钠那娜纳氖乃奶耐奈南男难囊挠脑恼闹淖呢馁内嫩能妮霓倪泥尼拟你匿腻逆溺蔫拈年碾撵捻念娘酿鸟尿捏聂孽啮镊镍涅您柠狞凝宁"],["c540","臔",14,"臤臥臦臨臩臫臮",4,"臵",5,"臽臿舃與",4,"舎舏舑舓舕",5,"舝舠舤舥舦舧舩舮舲舺舼舽舿"],["c580","艀艁艂艃艅艆艈艊艌艍艎艐",7,"艙艛艜艝艞艠",7,"艩拧泞牛扭钮纽脓浓农弄奴努怒女暖虐疟挪懦糯诺哦欧鸥殴藕呕偶沤啪趴爬帕怕琶拍排牌徘湃派攀潘盘磐盼畔判叛乓庞旁耪胖抛咆刨炮袍跑泡呸胚培裴赔陪配佩沛喷盆砰抨烹澎彭蓬棚硼篷膨朋鹏捧碰坯砒霹批披劈琵毗"],["c640","艪艫艬艭艱艵艶艷艸艻艼芀芁芃芅芆芇芉芌芐芓芔芕芖芚芛芞芠芢芣芧芲芵芶芺芻芼芿苀苂苃苅苆苉苐苖苙苚苝苢苧苨苩苪苬苭苮苰苲苳苵苶苸"],["c680","苺苼",4,"茊茋茍茐茒茓茖茘茙茝",9,"茩茪茮茰茲茷茻茽啤脾疲皮匹痞僻屁譬篇偏片骗飘漂瓢票撇瞥拼频贫品聘乒坪苹萍平凭瓶评屏坡泼颇婆破魄迫粕剖扑铺仆莆葡菩蒲埔朴圃普浦谱曝瀑期欺栖戚妻七凄漆柒沏其棋奇歧畦崎脐齐旗祈祁骑起岂乞企启契砌器气迄弃汽泣讫掐"],["c740","茾茿荁荂荄荅荈荊",4,"荓荕",4,"荝荢荰",6,"荹荺荾",6,"莇莈莊莋莌莍莏莐莑莔莕莖莗莙莚莝莟莡",6,"莬莭莮"],["c780","莯莵莻莾莿菂菃菄菆菈菉菋菍菎菐菑菒菓菕菗菙菚菛菞菢菣菤菦菧菨菫菬菭恰洽牵扦钎铅千迁签仟谦乾黔钱钳前潜遣浅谴堑嵌欠歉枪呛腔羌墙蔷强抢橇锹敲悄桥瞧乔侨巧鞘撬翘峭俏窍切茄且怯窃钦侵亲秦琴勤芹擒禽寝沁青轻氢倾卿清擎晴氰情顷请庆琼穷秋丘邱球求囚酋泅趋区蛆曲躯屈驱渠"],["c840","菮華菳",4,"菺菻菼菾菿萀萂萅萇萈萉萊萐萒",5,"萙萚萛萞",5,"萩",7,"萲",5,"萹萺萻萾",7,"葇葈葉"],["c880","葊",6,"葒",4,"葘葝葞葟葠葢葤",4,"葪葮葯葰葲葴葷葹葻葼取娶龋趣去圈颧权醛泉全痊拳犬券劝缺炔瘸却鹊榷确雀裙群然燃冉染瓤壤攘嚷让饶扰绕惹热壬仁人忍韧任认刃妊纫扔仍日戎茸蓉荣融熔溶容绒冗揉柔肉茹蠕儒孺如辱乳汝入褥软阮蕊瑞锐闰润若弱撒洒萨腮鳃塞赛三叁"],["c940","葽",4,"蒃蒄蒅蒆蒊蒍蒏",7,"蒘蒚蒛蒝蒞蒟蒠蒢",12,"蒰蒱蒳蒵蒶蒷蒻蒼蒾蓀蓂蓃蓅蓆蓇蓈蓋蓌蓎蓏蓒蓔蓕蓗"],["c980","蓘",4,"蓞蓡蓢蓤蓧",4,"蓭蓮蓯蓱",10,"蓽蓾蔀蔁蔂伞散桑嗓丧搔骚扫嫂瑟色涩森僧莎砂杀刹沙纱傻啥煞筛晒珊苫杉山删煽衫闪陕擅赡膳善汕扇缮墒伤商赏晌上尚裳梢捎稍烧芍勺韶少哨邵绍奢赊蛇舌舍赦摄射慑涉社设砷申呻伸身深娠绅神沈审婶甚肾慎渗声生甥牲升绳"],["ca40","蔃",8,"蔍蔎蔏蔐蔒蔔蔕蔖蔘蔙蔛蔜蔝蔞蔠蔢",8,"蔭",9,"蔾",4,"蕄蕅蕆蕇蕋",10],["ca80","蕗蕘蕚蕛蕜蕝蕟",4,"蕥蕦蕧蕩",8,"蕳蕵蕶蕷蕸蕼蕽蕿薀薁省盛剩胜圣师失狮施湿诗尸虱十石拾时什食蚀实识史矢使屎驶始式示士世柿事拭誓逝势是嗜噬适仕侍释饰氏市恃室视试收手首守寿授售受瘦兽蔬枢梳殊抒输叔舒淑疏书赎孰熟薯暑曙署蜀黍鼠属术述树束戍竖墅庶数漱"],["cb40","薂薃薆薈",6,"薐",10,"薝",6,"薥薦薧薩薫薬薭薱",5,"薸薺",6,"藂",6,"藊",4,"藑藒"],["cb80","藔藖",5,"藝",6,"藥藦藧藨藪",14,"恕刷耍摔衰甩帅栓拴霜双爽谁水睡税吮瞬顺舜说硕朔烁斯撕嘶思私司丝死肆寺嗣四伺似饲巳松耸怂颂送宋讼诵搜艘擞嗽苏酥俗素速粟僳塑溯宿诉肃酸蒜算虽隋随绥髓碎岁穗遂隧祟孙损笋蓑梭唆缩琐索锁所塌他它她塔"],["cc40","藹藺藼藽藾蘀",4,"蘆",10,"蘒蘓蘔蘕蘗",15,"蘨蘪",13,"蘹蘺蘻蘽蘾蘿虀"],["cc80","虁",11,"虒虓處",4,"虛虜虝號虠虡虣",7,"獭挞蹋踏胎苔抬台泰酞太态汰坍摊贪瘫滩坛檀痰潭谭谈坦毯袒碳探叹炭汤塘搪堂棠膛唐糖倘躺淌趟烫掏涛滔绦萄桃逃淘陶讨套特藤腾疼誊梯剔踢锑提题蹄啼体替嚏惕涕剃屉天添填田甜恬舔腆挑条迢眺跳贴铁帖厅听烃"],["cd40","虭虯虰虲",6,"蚃",6,"蚎",4,"蚔蚖",5,"蚞",4,"蚥蚦蚫蚭蚮蚲蚳蚷蚸蚹蚻",4,"蛁蛂蛃蛅蛈蛌蛍蛒蛓蛕蛖蛗蛚蛜"],["cd80","蛝蛠蛡蛢蛣蛥蛦蛧蛨蛪蛫蛬蛯蛵蛶蛷蛺蛻蛼蛽蛿蜁蜄蜅蜆蜋蜌蜎蜏蜐蜑蜔蜖汀廷停亭庭挺艇通桐酮瞳同铜彤童桶捅筒统痛偷投头透凸秃突图徒途涂屠土吐兔湍团推颓腿蜕褪退吞屯臀拖托脱鸵陀驮驼椭妥拓唾挖哇蛙洼娃瓦袜歪外豌弯湾玩顽丸烷完碗挽晚皖惋宛婉万腕汪王亡枉网往旺望忘妄威"],["ce40","蜙蜛蜝蜟蜠蜤蜦蜧蜨蜪蜫蜬蜭蜯蜰蜲蜳蜵蜶蜸蜹蜺蜼蜽蝀",6,"蝊蝋蝍蝏蝐蝑蝒蝔蝕蝖蝘蝚",5,"蝡蝢蝦",7,"蝯蝱蝲蝳蝵"],["ce80","蝷蝸蝹蝺蝿螀螁螄螆螇螉螊螌螎",4,"螔螕螖螘",6,"螠",4,"巍微危韦违桅围唯惟为潍维苇萎委伟伪尾纬未蔚味畏胃喂魏位渭谓尉慰卫瘟温蚊文闻纹吻稳紊问嗡翁瓮挝蜗涡窝我斡卧握沃巫呜钨乌污诬屋无芜梧吾吴毋武五捂午舞伍侮坞戊雾晤物勿务悟误昔熙析西硒矽晰嘻吸锡牺"],["cf40","螥螦螧螩螪螮螰螱螲螴螶螷螸螹螻螼螾螿蟁",4,"蟇蟈蟉蟌",4,"蟔",6,"蟜蟝蟞蟟蟡蟢蟣蟤蟦蟧蟨蟩蟫蟬蟭蟯",9],["cf80","蟺蟻蟼蟽蟿蠀蠁蠂蠄",5,"蠋",7,"蠔蠗蠘蠙蠚蠜",4,"蠣稀息希悉膝夕惜熄烯溪汐犀檄袭席习媳喜铣洗系隙戏细瞎虾匣霞辖暇峡侠狭下厦夏吓掀锨先仙鲜纤咸贤衔舷闲涎弦嫌显险现献县腺馅羡宪陷限线相厢镶香箱襄湘乡翔祥详想响享项巷橡像向象萧硝霄削哮嚣销消宵淆晓"],["d040","蠤",13,"蠳",5,"蠺蠻蠽蠾蠿衁衂衃衆",5,"衎",5,"衕衖衘衚",6,"衦衧衪衭衯衱衳衴衵衶衸衹衺"],["d080","衻衼袀袃袆袇袉袊袌袎袏袐袑袓袔袕袗",4,"袝",4,"袣袥",5,"小孝校肖啸笑效楔些歇蝎鞋协挟携邪斜胁谐写械卸蟹懈泄泻谢屑薪芯锌欣辛新忻心信衅星腥猩惺兴刑型形邢行醒幸杏性姓兄凶胸匈汹雄熊休修羞朽嗅锈秀袖绣墟戌需虚嘘须徐许蓄酗叙旭序畜恤絮婿绪续轩喧宣悬旋玄"],["d140","袬袮袯袰袲",4,"袸袹袺袻袽袾袿裀裃裄裇裈裊裋裌裍裏裐裑裓裖裗裚",4,"裠裡裦裧裩",6,"裲裵裶裷裺裻製裿褀褁褃",5],["d180","褉褋",4,"褑褔",4,"褜",4,"褢褣褤褦褧褨褩褬褭褮褯褱褲褳褵褷选癣眩绚靴薛学穴雪血勋熏循旬询寻驯巡殉汛训讯逊迅压押鸦鸭呀丫芽牙蚜崖衙涯雅哑亚讶焉咽阉烟淹盐严研蜒岩延言颜阎炎沿奄掩眼衍演艳堰燕厌砚雁唁彦焰宴谚验殃央鸯秧杨扬佯疡羊洋阳氧仰痒养样漾邀腰妖瑶"],["d240","褸",8,"襂襃襅",24,"襠",5,"襧",19,"襼"],["d280","襽襾覀覂覄覅覇",26,"摇尧遥窑谣姚咬舀药要耀椰噎耶爷野冶也页掖业叶曳腋夜液一壹医揖铱依伊衣颐夷遗移仪胰疑沂宜姨彝椅蚁倚已乙矣以艺抑易邑屹亿役臆逸肄疫亦裔意毅忆义益溢诣议谊译异翼翌绎茵荫因殷音阴姻吟银淫寅饮尹引隐"],["d340","覢",30,"觃觍觓觔觕觗觘觙觛觝觟觠觡觢觤觧觨觩觪觬觭觮觰觱觲觴",6],["d380","觻",4,"訁",5,"計",21,"印英樱婴鹰应缨莹萤营荧蝇迎赢盈影颖硬映哟拥佣臃痈庸雍踊蛹咏泳涌永恿勇用幽优悠忧尤由邮铀犹油游酉有友右佑釉诱又幼迂淤于盂榆虞愚舆余俞逾鱼愉渝渔隅予娱雨与屿禹宇语羽玉域芋郁吁遇喻峪御愈欲狱育誉"],["d440","訞",31,"訿",8,"詉",21],["d480","詟",25,"詺",6,"浴寓裕预豫驭鸳渊冤元垣袁原援辕园员圆猿源缘远苑愿怨院曰约越跃钥岳粤月悦阅耘云郧匀陨允运蕴酝晕韵孕匝砸杂栽哉灾宰载再在咱攒暂赞赃脏葬遭糟凿藻枣早澡蚤躁噪造皂灶燥责择则泽贼怎增憎曾赠扎喳渣札轧"],["d540","誁",7,"誋",7,"誔",46],["d580","諃",32,"铡闸眨栅榨咋乍炸诈摘斋宅窄债寨瞻毡詹粘沾盏斩辗崭展蘸栈占战站湛绽樟章彰漳张掌涨杖丈帐账仗胀瘴障招昭找沼赵照罩兆肇召遮折哲蛰辙者锗蔗这浙珍斟真甄砧臻贞针侦枕疹诊震振镇阵蒸挣睁征狰争怔整拯正政"],["d640","諤",34,"謈",27],["d680","謤謥謧",30,"帧症郑证芝枝支吱蜘知肢脂汁之织职直植殖执值侄址指止趾只旨纸志挚掷至致置帜峙制智秩稚质炙痔滞治窒中盅忠钟衷终种肿重仲众舟周州洲诌粥轴肘帚咒皱宙昼骤珠株蛛朱猪诸诛逐竹烛煮拄瞩嘱主著柱助蛀贮铸筑"],["d740","譆",31,"譧",4,"譭",25],["d780","讇",24,"讬讱讻诇诐诪谉谞住注祝驻抓爪拽专砖转撰赚篆桩庄装妆撞壮状椎锥追赘坠缀谆准捉拙卓桌琢茁酌啄着灼浊兹咨资姿滋淄孜紫仔籽滓子自渍字鬃棕踪宗综总纵邹走奏揍租足卒族祖诅阻组钻纂嘴醉最罪尊遵昨左佐柞做作坐座"],["d840","谸",8,"豂豃豄豅豈豊豋豍",7,"豖豗豘豙豛",5,"豣",6,"豬",6,"豴豵豶豷豻",6,"貃貄貆貇"],["d880","貈貋貍",6,"貕貖貗貙",20,"亍丌兀丐廿卅丕亘丞鬲孬噩丨禺丿匕乇夭爻卮氐囟胤馗毓睾鼗丶亟鼐乜乩亓芈孛啬嘏仄厍厝厣厥厮靥赝匚叵匦匮匾赜卦卣刂刈刎刭刳刿剀剌剞剡剜蒯剽劂劁劐劓冂罔亻仃仉仂仨仡仫仞伛仳伢佤仵伥伧伉伫佞佧攸佚佝"],["d940","貮",62],["d980","賭",32,"佟佗伲伽佶佴侑侉侃侏佾佻侪佼侬侔俦俨俪俅俚俣俜俑俟俸倩偌俳倬倏倮倭俾倜倌倥倨偾偃偕偈偎偬偻傥傧傩傺僖儆僭僬僦僮儇儋仝氽佘佥俎龠汆籴兮巽黉馘冁夔勹匍訇匐凫夙兕亠兖亳衮袤亵脔裒禀嬴蠃羸冫冱冽冼"],["da40","贎",14,"贠赑赒赗赟赥赨赩赪赬赮赯赱赲赸",8,"趂趃趆趇趈趉趌",4,"趒趓趕",9,"趠趡"],["da80","趢趤",12,"趲趶趷趹趻趽跀跁跂跅跇跈跉跊跍跐跒跓跔凇冖冢冥讠讦讧讪讴讵讷诂诃诋诏诎诒诓诔诖诘诙诜诟诠诤诨诩诮诰诳诶诹诼诿谀谂谄谇谌谏谑谒谔谕谖谙谛谘谝谟谠谡谥谧谪谫谮谯谲谳谵谶卩卺阝阢阡阱阪阽阼陂陉陔陟陧陬陲陴隈隍隗隰邗邛邝邙邬邡邴邳邶邺"],["db40","跕跘跙跜跠跡跢跥跦跧跩跭跮跰跱跲跴跶跼跾",6,"踆踇踈踋踍踎踐踑踒踓踕",7,"踠踡踤",4,"踫踭踰踲踳踴踶踷踸踻踼踾"],["db80","踿蹃蹅蹆蹌",4,"蹓",5,"蹚",11,"蹧蹨蹪蹫蹮蹱邸邰郏郅邾郐郄郇郓郦郢郜郗郛郫郯郾鄄鄢鄞鄣鄱鄯鄹酃酆刍奂劢劬劭劾哿勐勖勰叟燮矍廴凵凼鬯厶弁畚巯坌垩垡塾墼壅壑圩圬圪圳圹圮圯坜圻坂坩垅坫垆坼坻坨坭坶坳垭垤垌垲埏垧垴垓垠埕埘埚埙埒垸埴埯埸埤埝"],["dc40","蹳蹵蹷",4,"蹽蹾躀躂躃躄躆躈",6,"躑躒躓躕",6,"躝躟",11,"躭躮躰躱躳",6,"躻",7],["dc80","軃",10,"軏",21,"堋堍埽埭堀堞堙塄堠塥塬墁墉墚墀馨鼙懿艹艽艿芏芊芨芄芎芑芗芙芫芸芾芰苈苊苣芘芷芮苋苌苁芩芴芡芪芟苄苎芤苡茉苷苤茏茇苜苴苒苘茌苻苓茑茚茆茔茕苠苕茜荑荛荜茈莒茼茴茱莛荞茯荏荇荃荟荀茗荠茭茺茳荦荥"],["dd40","軥",62],["dd80","輤",32,"荨茛荩荬荪荭荮莰荸莳莴莠莪莓莜莅荼莶莩荽莸荻莘莞莨莺莼菁萁菥菘堇萘萋菝菽菖萜萸萑萆菔菟萏萃菸菹菪菅菀萦菰菡葜葑葚葙葳蒇蒈葺蒉葸萼葆葩葶蒌蒎萱葭蓁蓍蓐蓦蒽蓓蓊蒿蒺蓠蒡蒹蒴蒗蓥蓣蔌甍蔸蓰蔹蔟蔺"],["de40","轅",32,"轪辀辌辒辝辠辡辢辤辥辦辧辪辬辭辮辯農辳辴辵辷辸辺辻込辿迀迃迆"],["de80","迉",4,"迏迒迖迗迚迠迡迣迧迬迯迱迲迴迵迶迺迻迼迾迿逇逈逌逎逓逕逘蕖蔻蓿蓼蕙蕈蕨蕤蕞蕺瞢蕃蕲蕻薤薨薇薏蕹薮薜薅薹薷薰藓藁藜藿蘧蘅蘩蘖蘼廾弈夼奁耷奕奚奘匏尢尥尬尴扌扪抟抻拊拚拗拮挢拶挹捋捃掭揶捱捺掎掴捭掬掊捩掮掼揲揸揠揿揄揞揎摒揆掾摅摁搋搛搠搌搦搡摞撄摭撖"],["df40","這逜連逤逥逧",5,"逰",4,"逷逹逺逽逿遀遃遅遆遈",4,"過達違遖遙遚遜",5,"遤遦遧適遪遫遬遯",4,"遶",6,"遾邁"],["df80","還邅邆邇邉邊邌",4,"邒邔邖邘邚邜邞邟邠邤邥邧邨邩邫邭邲邷邼邽邿郀摺撷撸撙撺擀擐擗擤擢攉攥攮弋忒甙弑卟叱叽叩叨叻吒吖吆呋呒呓呔呖呃吡呗呙吣吲咂咔呷呱呤咚咛咄呶呦咝哐咭哂咴哒咧咦哓哔呲咣哕咻咿哌哙哚哜咩咪咤哝哏哞唛哧唠哽唔哳唢唣唏唑唧唪啧喏喵啉啭啁啕唿啐唼"],["e040","郂郃郆郈郉郋郌郍郒郔郕郖郘郙郚郞郟郠郣郤郥郩郪郬郮郰郱郲郳郵郶郷郹郺郻郼郿鄀鄁鄃鄅",19,"鄚鄛鄜"],["e080","鄝鄟鄠鄡鄤",10,"鄰鄲",6,"鄺",8,"酄唷啖啵啶啷唳唰啜喋嗒喃喱喹喈喁喟啾嗖喑啻嗟喽喾喔喙嗪嗷嗉嘟嗑嗫嗬嗔嗦嗝嗄嗯嗥嗲嗳嗌嗍嗨嗵嗤辔嘞嘈嘌嘁嘤嘣嗾嘀嘧嘭噘嘹噗嘬噍噢噙噜噌噔嚆噤噱噫噻噼嚅嚓嚯囔囗囝囡囵囫囹囿圄圊圉圜帏帙帔帑帱帻帼"],["e140","酅酇酈酑酓酔酕酖酘酙酛酜酟酠酦酧酨酫酭酳酺酻酼醀",4,"醆醈醊醎醏醓",6,"醜",5,"醤",5,"醫醬醰醱醲醳醶醷醸醹醻"],["e180","醼",10,"釈釋釐釒",9,"針",8,"帷幄幔幛幞幡岌屺岍岐岖岈岘岙岑岚岜岵岢岽岬岫岱岣峁岷峄峒峤峋峥崂崃崧崦崮崤崞崆崛嵘崾崴崽嵬嵛嵯嵝嵫嵋嵊嵩嵴嶂嶙嶝豳嶷巅彳彷徂徇徉後徕徙徜徨徭徵徼衢彡犭犰犴犷犸狃狁狎狍狒狨狯狩狲狴狷猁狳猃狺"],["e240","釦",62],["e280","鈥",32,"狻猗猓猡猊猞猝猕猢猹猥猬猸猱獐獍獗獠獬獯獾舛夥飧夤夂饣饧",5,"饴饷饽馀馄馇馊馍馐馑馓馔馕庀庑庋庖庥庠庹庵庾庳赓廒廑廛廨廪膺忄忉忖忏怃忮怄忡忤忾怅怆忪忭忸怙怵怦怛怏怍怩怫怊怿怡恸恹恻恺恂"],["e340","鉆",45,"鉵",16],["e380","銆",7,"銏",24,"恪恽悖悚悭悝悃悒悌悛惬悻悱惝惘惆惚悴愠愦愕愣惴愀愎愫慊慵憬憔憧憷懔懵忝隳闩闫闱闳闵闶闼闾阃阄阆阈阊阋阌阍阏阒阕阖阗阙阚丬爿戕氵汔汜汊沣沅沐沔沌汨汩汴汶沆沩泐泔沭泷泸泱泗沲泠泖泺泫泮沱泓泯泾"],["e440","銨",5,"銯",24,"鋉",31],["e480","鋩",32,"洹洧洌浃浈洇洄洙洎洫浍洮洵洚浏浒浔洳涑浯涞涠浞涓涔浜浠浼浣渚淇淅淞渎涿淠渑淦淝淙渖涫渌涮渫湮湎湫溲湟溆湓湔渲渥湄滟溱溘滠漭滢溥溧溽溻溷滗溴滏溏滂溟潢潆潇漤漕滹漯漶潋潴漪漉漩澉澍澌潸潲潼潺濑"],["e540","錊",51,"錿",10],["e580","鍊",31,"鍫濉澧澹澶濂濡濮濞濠濯瀚瀣瀛瀹瀵灏灞宀宄宕宓宥宸甯骞搴寤寮褰寰蹇謇辶迓迕迥迮迤迩迦迳迨逅逄逋逦逑逍逖逡逵逶逭逯遄遑遒遐遨遘遢遛暹遴遽邂邈邃邋彐彗彖彘尻咫屐屙孱屣屦羼弪弩弭艴弼鬻屮妁妃妍妩妪妣"],["e640","鍬",34,"鎐",27],["e680","鎬",29,"鏋鏌鏍妗姊妫妞妤姒妲妯姗妾娅娆姝娈姣姘姹娌娉娲娴娑娣娓婀婧婊婕娼婢婵胬媪媛婷婺媾嫫媲嫒嫔媸嫠嫣嫱嫖嫦嫘嫜嬉嬗嬖嬲嬷孀尕尜孚孥孳孑孓孢驵驷驸驺驿驽骀骁骅骈骊骐骒骓骖骘骛骜骝骟骠骢骣骥骧纟纡纣纥纨纩"],["e740","鏎",7,"鏗",54],["e780","鐎",32,"纭纰纾绀绁绂绉绋绌绐绔绗绛绠绡绨绫绮绯绱绲缍绶绺绻绾缁缂缃缇缈缋缌缏缑缒缗缙缜缛缟缡",6,"缪缫缬缭缯",4,"缵幺畿巛甾邕玎玑玮玢玟珏珂珑玷玳珀珉珈珥珙顼琊珩珧珞玺珲琏琪瑛琦琥琨琰琮琬"],["e840","鐯",14,"鐿",43,"鑬鑭鑮鑯"],["e880","鑰",20,"钑钖钘铇铏铓铔铚铦铻锜锠琛琚瑁瑜瑗瑕瑙瑷瑭瑾璜璎璀璁璇璋璞璨璩璐璧瓒璺韪韫韬杌杓杞杈杩枥枇杪杳枘枧杵枨枞枭枋杷杼柰栉柘栊柩枰栌柙枵柚枳柝栀柃枸柢栎柁柽栲栳桠桡桎桢桄桤梃栝桕桦桁桧桀栾桊桉栩梵梏桴桷梓桫棂楮棼椟椠棹"],["e940","锧锳锽镃镈镋镕镚镠镮镴镵長",7,"門",42],["e980","閫",32,"椤棰椋椁楗棣椐楱椹楠楂楝榄楫榀榘楸椴槌榇榈槎榉楦楣楹榛榧榻榫榭槔榱槁槊槟榕槠榍槿樯槭樗樘橥槲橄樾檠橐橛樵檎橹樽樨橘橼檑檐檩檗檫猷獒殁殂殇殄殒殓殍殚殛殡殪轫轭轱轲轳轵轶轸轷轹轺轼轾辁辂辄辇辋"],["ea40","闌",27,"闬闿阇阓阘阛阞阠阣",6,"阫阬阭阯阰阷阸阹阺阾陁陃陊陎陏陑陒陓陖陗"],["ea80","陘陙陚陜陝陞陠陣陥陦陫陭",4,"陳陸",12,"隇隉隊辍辎辏辘辚軎戋戗戛戟戢戡戥戤戬臧瓯瓴瓿甏甑甓攴旮旯旰昊昙杲昃昕昀炅曷昝昴昱昶昵耆晟晔晁晏晖晡晗晷暄暌暧暝暾曛曜曦曩贲贳贶贻贽赀赅赆赈赉赇赍赕赙觇觊觋觌觎觏觐觑牮犟牝牦牯牾牿犄犋犍犏犒挈挲掰"],["eb40","隌階隑隒隓隕隖隚際隝",9,"隨",7,"隱隲隴隵隷隸隺隻隿雂雃雈雊雋雐雑雓雔雖",9,"雡",6,"雫"],["eb80","雬雭雮雰雱雲雴雵雸雺電雼雽雿霂霃霅霊霋霌霐霑霒霔霕霗",4,"霝霟霠搿擘耄毪毳毽毵毹氅氇氆氍氕氘氙氚氡氩氤氪氲攵敕敫牍牒牖爰虢刖肟肜肓肼朊肽肱肫肭肴肷胧胨胩胪胛胂胄胙胍胗朐胝胫胱胴胭脍脎胲胼朕脒豚脶脞脬脘脲腈腌腓腴腙腚腱腠腩腼腽腭腧塍媵膈膂膑滕膣膪臌朦臊膻"],["ec40","霡",8,"霫霬霮霯霱霳",4,"霺霻霼霽霿",18,"靔靕靗靘靚靜靝靟靣靤靦靧靨靪",7],["ec80","靲靵靷",4,"靽",7,"鞆",4,"鞌鞎鞏鞐鞓鞕鞖鞗鞙",4,"臁膦欤欷欹歃歆歙飑飒飓飕飙飚殳彀毂觳斐齑斓於旆旄旃旌旎旒旖炀炜炖炝炻烀炷炫炱烨烊焐焓焖焯焱煳煜煨煅煲煊煸煺熘熳熵熨熠燠燔燧燹爝爨灬焘煦熹戾戽扃扈扉礻祀祆祉祛祜祓祚祢祗祠祯祧祺禅禊禚禧禳忑忐"],["ed40","鞞鞟鞡鞢鞤",6,"鞬鞮鞰鞱鞳鞵",46],["ed80","韤韥韨韮",4,"韴韷",23,"怼恝恚恧恁恙恣悫愆愍慝憩憝懋懑戆肀聿沓泶淼矶矸砀砉砗砘砑斫砭砜砝砹砺砻砟砼砥砬砣砩硎硭硖硗砦硐硇硌硪碛碓碚碇碜碡碣碲碹碥磔磙磉磬磲礅磴礓礤礞礴龛黹黻黼盱眄眍盹眇眈眚眢眙眭眦眵眸睐睑睇睃睚睨"],["ee40","頏",62],["ee80","顎",32,"睢睥睿瞍睽瞀瞌瞑瞟瞠瞰瞵瞽町畀畎畋畈畛畲畹疃罘罡罟詈罨罴罱罹羁罾盍盥蠲钅钆钇钋钊钌钍钏钐钔钗钕钚钛钜钣钤钫钪钭钬钯钰钲钴钶",4,"钼钽钿铄铈",6,"铐铑铒铕铖铗铙铘铛铞铟铠铢铤铥铧铨铪"],["ef40","顯",5,"颋颎颒颕颙颣風",37,"飏飐飔飖飗飛飜飝飠",4],["ef80","飥飦飩",30,"铩铫铮铯铳铴铵铷铹铼铽铿锃锂锆锇锉锊锍锎锏锒",4,"锘锛锝锞锟锢锪锫锩锬锱锲锴锶锷锸锼锾锿镂锵镄镅镆镉镌镎镏镒镓镔镖镗镘镙镛镞镟镝镡镢镤",8,"镯镱镲镳锺矧矬雉秕秭秣秫稆嵇稃稂稞稔"],["f040","餈",4,"餎餏餑",28,"餯",26],["f080","饊",9,"饖",12,"饤饦饳饸饹饻饾馂馃馉稹稷穑黏馥穰皈皎皓皙皤瓞瓠甬鸠鸢鸨",4,"鸲鸱鸶鸸鸷鸹鸺鸾鹁鹂鹄鹆鹇鹈鹉鹋鹌鹎鹑鹕鹗鹚鹛鹜鹞鹣鹦",6,"鹱鹭鹳疒疔疖疠疝疬疣疳疴疸痄疱疰痃痂痖痍痣痨痦痤痫痧瘃痱痼痿瘐瘀瘅瘌瘗瘊瘥瘘瘕瘙"],["f140","馌馎馚",10,"馦馧馩",47],["f180","駙",32,"瘛瘼瘢瘠癀瘭瘰瘿瘵癃瘾瘳癍癞癔癜癖癫癯翊竦穸穹窀窆窈窕窦窠窬窨窭窳衤衩衲衽衿袂袢裆袷袼裉裢裎裣裥裱褚裼裨裾裰褡褙褓褛褊褴褫褶襁襦襻疋胥皲皴矜耒耔耖耜耠耢耥耦耧耩耨耱耋耵聃聆聍聒聩聱覃顸颀颃"],["f240","駺",62],["f280","騹",32,"颉颌颍颏颔颚颛颞颟颡颢颥颦虍虔虬虮虿虺虼虻蚨蚍蚋蚬蚝蚧蚣蚪蚓蚩蚶蛄蚵蛎蚰蚺蚱蚯蛉蛏蚴蛩蛱蛲蛭蛳蛐蜓蛞蛴蛟蛘蛑蜃蜇蛸蜈蜊蜍蜉蜣蜻蜞蜥蜮蜚蜾蝈蜴蜱蜩蜷蜿螂蜢蝽蝾蝻蝠蝰蝌蝮螋蝓蝣蝼蝤蝙蝥螓螯螨蟒"],["f340","驚",17,"驲骃骉骍骎骔骕骙骦骩",6,"骲骳骴骵骹骻骽骾骿髃髄髆",4,"髍髎髏髐髒體髕髖髗髙髚髛髜"],["f380","髝髞髠髢髣髤髥髧髨髩髪髬髮髰",8,"髺髼",6,"鬄鬅鬆蟆螈螅螭螗螃螫蟥螬螵螳蟋蟓螽蟑蟀蟊蟛蟪蟠蟮蠖蠓蟾蠊蠛蠡蠹蠼缶罂罄罅舐竺竽笈笃笄笕笊笫笏筇笸笪笙笮笱笠笥笤笳笾笞筘筚筅筵筌筝筠筮筻筢筲筱箐箦箧箸箬箝箨箅箪箜箢箫箴篑篁篌篝篚篥篦篪簌篾篼簏簖簋"],["f440","鬇鬉",5,"鬐鬑鬒鬔",10,"鬠鬡鬢鬤",10,"鬰鬱鬳",7,"鬽鬾鬿魀魆魊魋魌魎魐魒魓魕",5],["f480","魛",32,"簟簪簦簸籁籀臾舁舂舄臬衄舡舢舣舭舯舨舫舸舻舳舴舾艄艉艋艏艚艟艨衾袅袈裘裟襞羝羟羧羯羰羲籼敉粑粝粜粞粢粲粼粽糁糇糌糍糈糅糗糨艮暨羿翎翕翥翡翦翩翮翳糸絷綦綮繇纛麸麴赳趄趔趑趱赧赭豇豉酊酐酎酏酤"],["f540","魼",62],["f580","鮻",32,"酢酡酰酩酯酽酾酲酴酹醌醅醐醍醑醢醣醪醭醮醯醵醴醺豕鹾趸跫踅蹙蹩趵趿趼趺跄跖跗跚跞跎跏跛跆跬跷跸跣跹跻跤踉跽踔踝踟踬踮踣踯踺蹀踹踵踽踱蹉蹁蹂蹑蹒蹊蹰蹶蹼蹯蹴躅躏躔躐躜躞豸貂貊貅貘貔斛觖觞觚觜"],["f640","鯜",62],["f680","鰛",32,"觥觫觯訾謦靓雩雳雯霆霁霈霏霎霪霭霰霾龀龃龅",5,"龌黾鼋鼍隹隼隽雎雒瞿雠銎銮鋈錾鍪鏊鎏鐾鑫鱿鲂鲅鲆鲇鲈稣鲋鲎鲐鲑鲒鲔鲕鲚鲛鲞",5,"鲥",4,"鲫鲭鲮鲰",7,"鲺鲻鲼鲽鳄鳅鳆鳇鳊鳋"],["f740","鰼",62],["f780","鱻鱽鱾鲀鲃鲄鲉鲊鲌鲏鲓鲖鲗鲘鲙鲝鲪鲬鲯鲹鲾",4,"鳈鳉鳑鳒鳚鳛鳠鳡鳌",4,"鳓鳔鳕鳗鳘鳙鳜鳝鳟鳢靼鞅鞑鞒鞔鞯鞫鞣鞲鞴骱骰骷鹘骶骺骼髁髀髅髂髋髌髑魅魃魇魉魈魍魑飨餍餮饕饔髟髡髦髯髫髻髭髹鬈鬏鬓鬟鬣麽麾縻麂麇麈麋麒鏖麝麟黛黜黝黠黟黢黩黧黥黪黯鼢鼬鼯鼹鼷鼽鼾齄"],["f840","鳣",62],["f880","鴢",32],["f940","鵃",62],["f980","鶂",32],["fa40","鶣",62],["fa80","鷢",32],["fb40","鸃",27,"鸤鸧鸮鸰鸴鸻鸼鹀鹍鹐鹒鹓鹔鹖鹙鹝鹟鹠鹡鹢鹥鹮鹯鹲鹴",9,"麀"],["fb80","麁麃麄麅麆麉麊麌",5,"麔",8,"麞麠",5,"麧麨麩麪"],["fc40","麫",8,"麵麶麷麹麺麼麿",4,"黅黆黇黈黊黋黌黐黒黓黕黖黗黙黚點黡黣黤黦黨黫黬黭黮黰",8,"黺黽黿",6],["fc80","鼆",4,"鼌鼏鼑鼒鼔鼕鼖鼘鼚",5,"鼡鼣",8,"鼭鼮鼰鼱"],["fd40","鼲",4,"鼸鼺鼼鼿",4,"齅",10,"齒",38],["fd80","齹",5,"龁龂龍",11,"龜龝龞龡",4,"郎凉秊裏隣"],["fe40","兀嗀﨎﨏﨑﨓﨔礼﨟蘒﨡﨣﨤﨧﨨﨩"]]},802:function(e,t,n){"use strict";var i=n(986).Buffer;var o=n(165),r=e.exports;r.encodings=null;r.defaultCharUnicode="�";r.defaultCharSingleByte="?";r.encode=function encode(e,t,n){e=""+(e||"");var o=r.getEncoder(t,n);var s=o.write(e);var c=o.end();return c&&c.length>0?i.concat([s,c]):s};r.decode=function decode(e,t,n){if(typeof e==="string"){if(!r.skipDecodeWarning){console.error("Iconv-lite warning: decode()-ing strings is deprecated. Refer to https://github.com/ashtuchkin/iconv-lite/wiki/Use-Buffers-when-decoding");r.skipDecodeWarning=true}e=i.from(""+(e||""),"binary")}var o=r.getDecoder(t,n);var s=o.write(e);var c=o.end();return c?s+c:s};r.encodingExists=function encodingExists(e){try{r.getCodec(e);return true}catch(e){return false}};r.toEncoding=r.encode;r.fromEncoding=r.decode;r._codecDataCache={};r.getCodec=function getCodec(e){if(!r.encodings)r.encodings=n(467);var t=r._canonicalizeEncoding(e);var i={};while(true){var o=r._codecDataCache[t];if(o)return o;var s=r.encodings[t];switch(typeof s){case"string":t=s;break;case"object":for(var c in s)i[c]=s[c];if(!i.encodingName)i.encodingName=t;t=s.type;break;case"function":if(!i.encodingName)i.encodingName=t;o=new s(i,r);r._codecDataCache[i.encodingName]=o;return o;default:throw new Error("Encoding not recognized: '"+e+"' (searched as: '"+t+"')")}}};r._canonicalizeEncoding=function(e){return(""+e).toLowerCase().replace(/:\d{4}$|[^0-9a-z]/g,"")};r.getEncoder=function getEncoder(e,t){var n=r.getCodec(e),i=new n.encoder(t,n);if(n.bomAware&&t&&t.addBOM)i=new o.PrependBOM(i,t);return i};r.getDecoder=function getDecoder(e,t){var n=r.getCodec(e),i=new n.decoder(t,n);if(n.bomAware&&!(t&&t.stripBOM===false))i=new o.StripBOM(i,t);return i};var s=typeof process!=="undefined"&&process.versions&&process.versions.node;if(s){var c=s.split(".").map(Number);if(c[0]>0||c[1]>=10){n(189)(r)}n(655)(r)}if(false){}},811:function(e,t,n){"use strict";var i=n(986).Buffer;t.utf7=Utf7Codec;t.unicode11utf7="utf7";function Utf7Codec(e,t){this.iconv=t}Utf7Codec.prototype.encoder=Utf7Encoder;Utf7Codec.prototype.decoder=Utf7Decoder;Utf7Codec.prototype.bomAware=true;var o=/[^A-Za-z0-9'\(\),-\.\/:\? \n\r\t]+/g;function Utf7Encoder(e,t){this.iconv=t.iconv}Utf7Encoder.prototype.write=function(e){return i.from(e.replace(o,function(e){return"+"+(e==="+"?"":this.iconv.encode(e,"utf16-be").toString("base64").replace(/=+$/,""))+"-"}.bind(this)))};Utf7Encoder.prototype.end=function(){};function Utf7Decoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=""}var r=/[A-Za-z0-9\/+]/;var s=[];for(var c=0;c<256;c++)s[c]=r.test(String.fromCharCode(c));var a="+".charCodeAt(0),f="-".charCodeAt(0),h="&".charCodeAt(0);Utf7Decoder.prototype.write=function(e){var t="",n=0,o=this.inBase64,r=this.base64Accum;for(var c=0;c<e.length;c++){if(!o){if(e[c]==a){t+=this.iconv.decode(e.slice(n,c),"ascii");n=c+1;o=true}}else{if(!s[e[c]]){if(c==n&&e[c]==f){t+="+"}else{var h=r+e.slice(n,c).toString();t+=this.iconv.decode(i.from(h,"base64"),"utf16-be")}if(e[c]!=f)c--;n=c+1;o=false;r=""}}}if(!o){t+=this.iconv.decode(e.slice(n),"ascii")}else{var h=r+e.slice(n).toString();var p=h.length-h.length%8;r=h.slice(p);h=h.slice(0,p);t+=this.iconv.decode(i.from(h,"base64"),"utf16-be")}this.inBase64=o;this.base64Accum=r;return t};Utf7Decoder.prototype.end=function(){var e="";if(this.inBase64&&this.base64Accum.length>0)e=this.iconv.decode(i.from(this.base64Accum,"base64"),"utf16-be");this.inBase64=false;this.base64Accum="";return e};t.utf7imap=Utf7IMAPCodec;function Utf7IMAPCodec(e,t){this.iconv=t}Utf7IMAPCodec.prototype.encoder=Utf7IMAPEncoder;Utf7IMAPCodec.prototype.decoder=Utf7IMAPDecoder;Utf7IMAPCodec.prototype.bomAware=true;function Utf7IMAPEncoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=i.alloc(6);this.base64AccumIdx=0}Utf7IMAPEncoder.prototype.write=function(e){var t=this.inBase64,n=this.base64Accum,o=this.base64AccumIdx,r=i.alloc(e.length*5+10),s=0;for(var c=0;c<e.length;c++){var a=e.charCodeAt(c);if(32<=a&&a<=126){if(t){if(o>0){s+=r.write(n.slice(0,o).toString("base64").replace(/\//g,",").replace(/=+$/,""),s);o=0}r[s++]=f;t=false}if(!t){r[s++]=a;if(a===h)r[s++]=f}}else{if(!t){r[s++]=h;t=true}if(t){n[o++]=a>>8;n[o++]=a&255;if(o==n.length){s+=r.write(n.toString("base64").replace(/\//g,","),s);o=0}}}}this.inBase64=t;this.base64AccumIdx=o;return r.slice(0,s)};Utf7IMAPEncoder.prototype.end=function(){var e=i.alloc(10),t=0;if(this.inBase64){if(this.base64AccumIdx>0){t+=e.write(this.base64Accum.slice(0,this.base64AccumIdx).toString("base64").replace(/\//g,",").replace(/=+$/,""),t);this.base64AccumIdx=0}e[t++]=f;this.inBase64=false}return e.slice(0,t)};function Utf7IMAPDecoder(e,t){this.iconv=t.iconv;this.inBase64=false;this.base64Accum=""}var p=s.slice();p[",".charCodeAt(0)]=true;Utf7IMAPDecoder.prototype.write=function(e){var t="",n=0,o=this.inBase64,r=this.base64Accum;for(var s=0;s<e.length;s++){if(!o){if(e[s]==h){t+=this.iconv.decode(e.slice(n,s),"ascii");n=s+1;o=true}}else{if(!p[e[s]]){if(s==n&&e[s]==f){t+="&"}else{var c=r+e.slice(n,s).toString().replace(/,/g,"/");t+=this.iconv.decode(i.from(c,"base64"),"utf16-be")}if(e[s]!=f)s--;n=s+1;o=false;r=""}}}if(!o){t+=this.iconv.decode(e.slice(n),"ascii")}else{var c=r+e.slice(n).toString().replace(/,/g,"/");var a=c.length-c.length%8;r=c.slice(a);c=c.slice(0,a);t+=this.iconv.decode(i.from(c,"base64"),"utf16-be")}this.inBase64=o;this.base64Accum=r;return t};Utf7IMAPDecoder.prototype.end=function(){var e="";if(this.inBase64&&this.base64Accum.length>0)e=this.iconv.decode(i.from(this.base64Accum,"base64"),"utf16-be");this.inBase64=false;this.base64Accum="";return e}},835:function(e){e.exports=__webpack_require__("bzos")},910:function(e){e.exports={uChars:[128,165,169,178,184,216,226,235,238,244,248,251,253,258,276,284,300,325,329,334,364,463,465,467,469,471,473,475,477,506,594,610,712,716,730,930,938,962,970,1026,1104,1106,8209,8215,8218,8222,8231,8241,8244,8246,8252,8365,8452,8454,8458,8471,8482,8556,8570,8596,8602,8713,8720,8722,8726,8731,8737,8740,8742,8748,8751,8760,8766,8777,8781,8787,8802,8808,8816,8854,8858,8870,8896,8979,9322,9372,9548,9588,9616,9622,9634,9652,9662,9672,9676,9680,9702,9735,9738,9793,9795,11906,11909,11913,11917,11928,11944,11947,11951,11956,11960,11964,11979,12284,12292,12312,12319,12330,12351,12436,12447,12535,12543,12586,12842,12850,12964,13200,13215,13218,13253,13263,13267,13270,13384,13428,13727,13839,13851,14617,14703,14801,14816,14964,15183,15471,15585,16471,16736,17208,17325,17330,17374,17623,17997,18018,18212,18218,18301,18318,18760,18811,18814,18820,18823,18844,18848,18872,19576,19620,19738,19887,40870,59244,59336,59367,59413,59417,59423,59431,59437,59443,59452,59460,59478,59493,63789,63866,63894,63976,63986,64016,64018,64021,64025,64034,64037,64042,65074,65093,65107,65112,65127,65132,65375,65510,65536],gbChars:[0,36,38,45,50,81,89,95,96,100,103,104,105,109,126,133,148,172,175,179,208,306,307,308,309,310,311,312,313,341,428,443,544,545,558,741,742,749,750,805,819,820,7922,7924,7925,7927,7934,7943,7944,7945,7950,8062,8148,8149,8152,8164,8174,8236,8240,8262,8264,8374,8380,8381,8384,8388,8390,8392,8393,8394,8396,8401,8406,8416,8419,8424,8437,8439,8445,8482,8485,8496,8521,8603,8936,8946,9046,9050,9063,9066,9076,9092,9100,9108,9111,9113,9131,9162,9164,9218,9219,11329,11331,11334,11336,11346,11361,11363,11366,11370,11372,11375,11389,11682,11686,11687,11692,11694,11714,11716,11723,11725,11730,11736,11982,11989,12102,12336,12348,12350,12384,12393,12395,12397,12510,12553,12851,12962,12973,13738,13823,13919,13933,14080,14298,14585,14698,15583,15847,16318,16434,16438,16481,16729,17102,17122,17315,17320,17402,17418,17859,17909,17911,17915,17916,17936,17939,17961,18664,18703,18814,18962,19043,33469,33470,33471,33484,33485,33490,33497,33501,33505,33513,33520,33536,33550,37845,37921,37948,38029,38038,38064,38065,38066,38069,38075,38076,38078,39108,39109,39113,39114,39115,39116,39265,39394,189e3]}},945:function(e,t,n){"use strict";var i=n(986).Buffer;t.utf16be=Utf16BECodec;function Utf16BECodec(){}Utf16BECodec.prototype.encoder=Utf16BEEncoder;Utf16BECodec.prototype.decoder=Utf16BEDecoder;Utf16BECodec.prototype.bomAware=true;function Utf16BEEncoder(){}Utf16BEEncoder.prototype.write=function(e){var t=i.from(e,"ucs2");for(var n=0;n<t.length;n+=2){var o=t[n];t[n]=t[n+1];t[n+1]=o}return t};Utf16BEEncoder.prototype.end=function(){};function Utf16BEDecoder(){this.overflowByte=-1}Utf16BEDecoder.prototype.write=function(e){if(e.length==0)return"";var t=i.alloc(e.length+1),n=0,o=0;if(this.overflowByte!==-1){t[0]=e[0];t[1]=this.overflowByte;n=1;o=2}for(;n<e.length-1;n+=2,o+=2){t[o]=e[n+1];t[o+1]=e[n]}this.overflowByte=n==e.length-1?e[e.length-1]:-1;return t.slice(0,o).toString("ucs2")};Utf16BEDecoder.prototype.end=function(){};t.utf16=Utf16Codec;function Utf16Codec(e,t){this.iconv=t}Utf16Codec.prototype.encoder=Utf16Encoder;Utf16Codec.prototype.decoder=Utf16Decoder;function Utf16Encoder(e,t){e=e||{};if(e.addBOM===undefined)e.addBOM=true;this.encoder=t.iconv.getEncoder("utf-16le",e)}Utf16Encoder.prototype.write=function(e){return this.encoder.write(e)};Utf16Encoder.prototype.end=function(){return this.encoder.end()};function Utf16Decoder(e,t){this.decoder=null;this.initialBytes=[];this.initialBytesLen=0;this.options=e||{};this.iconv=t.iconv}Utf16Decoder.prototype.write=function(e){if(!this.decoder){this.initialBytes.push(e);this.initialBytesLen+=e.length;if(this.initialBytesLen<16)return"";var e=i.concat(this.initialBytes),t=detectEncoding(e,this.options.defaultEncoding);this.decoder=this.iconv.getDecoder(t,this.options);this.initialBytes.length=this.initialBytesLen=0}return this.decoder.write(e)};Utf16Decoder.prototype.end=function(){if(!this.decoder){var e=i.concat(this.initialBytes),t=detectEncoding(e,this.options.defaultEncoding);this.decoder=this.iconv.getDecoder(t,this.options);var n=this.decoder.write(e),o=this.decoder.end();return o?n+o:n}return this.decoder.end()};function detectEncoding(e,t){var n=t||"utf-16le";if(e.length>=2){if(e[0]==254&&e[1]==255)n="utf-16be";else if(e[0]==255&&e[1]==254)n="utf-16le";else{var i=0,o=0,r=Math.min(e.length-e.length%2,64);for(var s=0;s<r;s+=2){if(e[s]===0&&e[s+1]!==0)o++;if(e[s]!==0&&e[s+1]===0)i++}if(o>i)n="utf-16be";else if(o<i)n="utf-16le"}}return n}},986:function(e,t,n){"use strict";var i=n(293);var o=i.Buffer;var r={};var s;for(s in i){if(!i.hasOwnProperty(s))continue;if(s==="SlowBuffer"||s==="Buffer")continue;r[s]=i[s]}var c=r.Buffer={};for(s in o){if(!o.hasOwnProperty(s))continue;if(s==="allocUnsafe"||s==="allocUnsafeSlow")continue;c[s]=o[s]}r.Buffer.prototype=o.prototype;if(!c.from||c.from===Uint8Array.from){c.from=function(e,t,n){if(typeof e==="number"){throw new TypeError('The "value" argument must not be of type number. Received type '+typeof e)}if(e&&typeof e.length==="undefined"){throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type "+typeof e)}return o(e,t,n)}}if(!c.alloc){c.alloc=function(e,t,n){if(typeof e!=="number"){throw new TypeError('The "size" argument must be of type number. Received type '+typeof e)}if(e<0||e>=2*(1<<30)){throw new RangeError('The value "'+e+'" is invalid for option "size"')}var i=o(e);if(!t||t.length===0){i.fill(0)}else if(typeof n==="string"){i.fill(t,n)}else{i.fill(t)}return i}}if(!r.kStringMaxLength){try{r.kStringMaxLength=process.binding("buffer").kStringMaxLength}catch(e){}}if(!r.constants){r.constants={MAX_LENGTH:r.kMaxLength};if(r.kStringMaxLength){r.constants.MAX_STRING_LENGTH=r.kStringMaxLength}}e.exports=r}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "Z3Jd":
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(t,e){"use strict";var r={};function __webpack_require__(e){if(r[e]){return r[e].exports}var n=r[e]={i:e,l:false,exports:{}};t[e].call(n.exports,n,n.exports,__webpack_require__);n.l=true;return n.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(580)}return startup()}({417:function(t){t.exports=__webpack_require__("PJMN")},580:function(t,e,r){"use strict";t.exports=etag;var n=r(417);var i=r(747).Stats;var a=Object.prototype.toString;function entitytag(t){if(t.length===0){return'"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"'}var e=n.createHash("sha1").update(t,"utf8").digest("base64").substring(0,27);var r=typeof t==="string"?Buffer.byteLength(t,"utf8"):t.length;return'"'+r.toString(16)+"-"+e+'"'}function etag(t,e){if(t==null){throw new TypeError("argument entity is required")}var r=isstats(t);var n=e&&typeof e.weak==="boolean"?e.weak:r;if(!r&&typeof t!=="string"&&!Buffer.isBuffer(t)){throw new TypeError("argument entity must be string, Buffer, or fs.Stats")}var i=r?stattag(t):entitytag(t);return n?"W/"+i:i}function isstats(t){if(typeof i==="function"&&t instanceof i){return true}return t&&typeof t==="object"&&"ctime"in t&&a.call(t.ctime)==="[object Date]"&&"mtime"in t&&a.call(t.mtime)==="[object Date]"&&"ino"in t&&typeof t.ino==="number"&&"size"in t&&typeof t.size==="number"}function stattag(t){var e=t.mtime.getTime().toString(16);var r=t.size.toString(16);return'"'+r+"-"+e+'"'}},747:function(t){t.exports=__webpack_require__("mw/K")}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "Z9M3":
/***/ (function(module, exports, __webpack_require__) {

const { inherits } = __webpack_require__("jK02")

const { Reporter } = __webpack_require__("1WHo")

function DecoderBuffer (base, options) {
  Reporter.call(this, options)
  if (!Buffer.isBuffer(base)) {
    this.error('Input not Buffer')
    return
  }

  this.base = base
  this.offset = 0
  this.length = base.length
}
inherits(DecoderBuffer, Reporter)

DecoderBuffer.isDecoderBuffer = function isDecoderBuffer (data) {
  if (data instanceof DecoderBuffer) {
    return true
  }

  // Or accept compatible API
  const isCompatible = typeof data === 'object' &&
    Buffer.isBuffer(data.base) &&
    data.constructor.name === 'DecoderBuffer' &&
    typeof data.offset === 'number' &&
    typeof data.length === 'number' &&
    typeof data.save === 'function' &&
    typeof data.restore === 'function' &&
    typeof data.isEmpty === 'function' &&
    typeof data.readUInt8 === 'function' &&
    typeof data.skip === 'function' &&
    typeof data.raw === 'function'

  return isCompatible
}

DecoderBuffer.prototype.save = function save () {
  return { offset: this.offset, reporter: Reporter.prototype.save.call(this) }
}

DecoderBuffer.prototype.restore = function restore (save) {
  // Return skipped data
  const res = new DecoderBuffer(this.base)
  res.offset = save.offset
  res.length = this.offset

  this.offset = save.offset
  Reporter.prototype.restore.call(this, save.reporter)

  return res
}

DecoderBuffer.prototype.isEmpty = function isEmpty () {
  return this.offset === this.length
}

DecoderBuffer.prototype.readUInt8 = function readUInt8 (fail) {
  if (this.offset + 1 <= this.length) { return this.base.readUInt8(this.offset++, true) } else { return this.error(fail || 'DecoderBuffer overrun') }
}

DecoderBuffer.prototype.skip = function skip (bytes, fail) {
  if (!(this.offset + bytes <= this.length)) { return this.error(fail || 'DecoderBuffer overrun') }

  const res = new DecoderBuffer(this.base)

  // Share reporter state
  res._reporterState = this._reporterState

  res.offset = this.offset
  res.length = this.offset + bytes
  this.offset += bytes
  return res
}

DecoderBuffer.prototype.raw = function raw (save) {
  return this.base.slice(save ? save.offset : this.offset, this.length)
}

function EncoderBuffer (value, reporter) {
  if (Array.isArray(value)) {
    this.length = 0
    this.value = value.map(function (item) {
      if (!EncoderBuffer.isEncoderBuffer(item)) { item = new EncoderBuffer(item, reporter) }
      this.length += item.length
      return item
    }, this)
  } else if (typeof value === 'number') {
    if (!(value >= 0 && value <= 0xff)) { return reporter.error('non-byte EncoderBuffer value') }
    this.value = value
    this.length = 1
  } else if (typeof value === 'string') {
    this.value = value
    this.length = Buffer.byteLength(value)
  } else if (Buffer.isBuffer(value)) {
    this.value = value
    this.length = value.length
  } else {
    return reporter.error(`Unsupported type: ${typeof value}`)
  }
}

EncoderBuffer.isEncoderBuffer = function isEncoderBuffer (data) {
  if (data instanceof EncoderBuffer) {
    return true
  }

  // Or accept compatible API
  const isCompatible = typeof data === 'object' &&
    data.constructor.name === 'EncoderBuffer' &&
    typeof data.length === 'number' &&
    typeof data.join === 'function'

  return isCompatible
}

EncoderBuffer.prototype.join = function join (out, offset) {
  if (!out) { out = Buffer.alloc(this.length) }
  if (!offset) { offset = 0 }

  if (this.length === 0) { return out }

  if (Array.isArray(this.value)) {
    this.value.forEach(function (item) {
      item.join(out, offset)
      offset += item.length
    })
  } else {
    if (typeof this.value === 'number') { out[offset] = this.value } else if (typeof this.value === 'string') { out.write(this.value, offset) } else if (Buffer.isBuffer(this.value)) { this.value.copy(out, offset) }
    offset += this.length
  }

  return out
}

module.exports = {
  DecoderBuffer,
  EncoderBuffer
}


/***/ }),

/***/ "ZUdF":
/***/ (function(module, exports, __webpack_require__) {

/* global BigInt */
const { inherits } = __webpack_require__("jK02")

const Node = __webpack_require__("k+0e")
const der = __webpack_require__("1Gj5")

function DEREncoder (entity) {
  this.enc = 'der'
  this.name = entity.name
  this.entity = entity

  // Construct base tree
  this.tree = new DERNode()
  this.tree._init(entity.body)
}

DEREncoder.prototype.encode = function encode (data, reporter) {
  return this.tree._encode(data, reporter).join()
}

// Tree methods

function DERNode (parent) {
  Node.call(this, 'der', parent)
}
inherits(DERNode, Node)

DERNode.prototype._encodeComposite = function encodeComposite (tag,
  primitive,
  cls,
  content) {
  const encodedTag = encodeTag(tag, primitive, cls, this.reporter)

  // Short form
  if (content.length < 0x80) {
    const header = Buffer.alloc(2)
    header[0] = encodedTag
    header[1] = content.length
    return this._createEncoderBuffer([header, content])
  }

  // Long form
  // Count octets required to store length
  let lenOctets = 1
  for (let i = content.length; i >= 0x100; i >>= 8) { lenOctets++ }

  const header = Buffer.alloc(1 + 1 + lenOctets)
  header[0] = encodedTag
  header[1] = 0x80 | lenOctets

  for (let i = 1 + lenOctets, j = content.length; j > 0; i--, j >>= 8) { header[i] = j & 0xff }

  return this._createEncoderBuffer([header, content])
}

DERNode.prototype._encodeStr = function encodeStr (str, tag) {
  if (tag === 'bitstr') {
    return this._createEncoderBuffer([str.unused | 0, str.data])
  } else if (tag === 'bmpstr') {
    const buf = Buffer.alloc(str.length * 2)
    for (let i = 0; i < str.length; i++) {
      buf.writeUInt16BE(str.charCodeAt(i), i * 2)
    }
    return this._createEncoderBuffer(buf)
  } else if (tag === 'numstr') {
    if (!this._isNumstr(str)) {
      return this.reporter.error('Encoding of string type: numstr supports only digits and space')
    }
    return this._createEncoderBuffer(str)
  } else if (tag === 'printstr') {
    if (!this._isPrintstr(str)) {
      return this.reporter.error('Encoding of string type: printstr supports only latin upper and lower case letters, digits, space, apostrophe, left and rigth parenthesis, plus sign, comma, hyphen, dot, slash, colon, equal sign, question mark')
    }
    return this._createEncoderBuffer(str)
  } else if (/str$/.test(tag)) {
    return this._createEncoderBuffer(str)
  } else if (tag === 'objDesc') {
    return this._createEncoderBuffer(str)
  } else {
    return this.reporter.error(`Encoding of string type: ${tag} unsupported`)
  }
}

DERNode.prototype._encodeObjid = function encodeObjid (id, values, relative) {
  if (typeof id === 'string') {
    if (!values) { return this.reporter.error('string objid given, but no values map found') }
    if (!Object.prototype.hasOwnProperty.call(values, id)) { return this.reporter.error('objid not found in values map') }
    id = values[id].split(/[\s.]+/g)
    for (let i = 0; i < id.length; i++) { id[i] |= 0 }
  } else if (Array.isArray(id)) {
    id = id.slice()
    for (let i = 0; i < id.length; i++) { id[i] |= 0 }
  }

  if (!Array.isArray(id)) {
    return this.reporter.error(`objid() should be either array or string, got: ${JSON.stringify(id)}`)
  }

  if (!relative) {
    if (id[1] >= 40) { return this.reporter.error('Second objid identifier OOB') }
    id.splice(0, 2, id[0] * 40 + id[1])
  }

  // Count number of octets
  let size = 0
  for (let i = 0; i < id.length; i++) {
    let ident = id[i]
    for (size++; ident >= 0x80; ident >>= 7) { size++ }
  }

  const objid = Buffer.alloc(size)
  let offset = objid.length - 1
  for (let i = id.length - 1; i >= 0; i--) {
    let ident = id[i]
    objid[offset--] = ident & 0x7f
    while ((ident >>= 7) > 0) { objid[offset--] = 0x80 | (ident & 0x7f) }
  }

  return this._createEncoderBuffer(objid)
}

function two (num) {
  if (num < 10) { return `0${num}` } else { return num }
}

DERNode.prototype._encodeTime = function encodeTime (time, tag) {
  let str
  const date = new Date(time)

  if (tag === 'gentime') {
    str = [
      two(date.getUTCFullYear()),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('')
  } else if (tag === 'utctime') {
    str = [
      two(date.getUTCFullYear() % 100),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('')
  } else {
    this.reporter.error(`Encoding ${tag} time is not supported yet`)
  }

  return this._encodeStr(str, 'octstr')
}

DERNode.prototype._encodeNull = function encodeNull () {
  return this._createEncoderBuffer('')
}

function bnToBuf (bn) {
  var hex = BigInt(bn).toString(16)
  if (hex.length % 2) { hex = '0' + hex }

  var len = hex.length / 2
  var u8 = new Uint8Array(len)

  var i = 0
  var j = 0
  while (i < len) {
    u8[i] = parseInt(hex.slice(j, j + 2), 16)
    i += 1
    j += 2
  }

  return u8
}

DERNode.prototype._encodeInt = function encodeInt (num, values) {
  if (typeof num === 'string') {
    if (!values) { return this.reporter.error('String int or enum given, but no values map') }
    if (!Object.prototype.hasOwnProperty.call(values, num)) {
      return this.reporter.error(`Values map doesn't contain: ${JSON.stringify(num)}`)
    }
    num = values[num]
  }

  if (typeof num === 'bigint') {
    const numArray = [...bnToBuf(num)]
    if (numArray[0] & 0x80) {
      numArray.unshift(0)
    }
    num = Buffer.from(numArray)
  }

  if (Buffer.isBuffer(num)) {
    let size = num.length
    if (num.length === 0) { size++ }

    const out = Buffer.alloc(size)
    num.copy(out)
    if (num.length === 0) { out[0] = 0 }
    return this._createEncoderBuffer(out)
  }

  if (num < 0x80) { return this._createEncoderBuffer(num) }

  if (num < 0x100) { return this._createEncoderBuffer([0, num]) }

  let size = 1
  for (let i = num; i >= 0x100; i >>= 8) { size++ }

  const out = new Array(size)
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = num & 0xff
    num >>= 8
  }
  if (out[0] & 0x80) {
    out.unshift(0)
  }

  return this._createEncoderBuffer(Buffer.from(out))
}

DERNode.prototype._encodeBool = function encodeBool (value) {
  return this._createEncoderBuffer(value ? 0xff : 0)
}

DERNode.prototype._use = function use (entity, obj) {
  if (typeof entity === 'function') { entity = entity(obj) }
  return entity._getEncoder('der').tree
}

DERNode.prototype._skipDefault = function skipDefault (dataBuffer, reporter, parent) {
  const state = this._baseState
  let i
  if (state.default === null) { return false }

  const data = dataBuffer.join()
  if (state.defaultBuffer === undefined) { state.defaultBuffer = this._encodeValue(state.default, reporter, parent).join() }

  if (data.length !== state.defaultBuffer.length) { return false }

  for (i = 0; i < data.length; i++) {
    if (data[i] !== state.defaultBuffer[i]) { return false }
  }

  return true
}

// Utility methods

function encodeTag (tag, primitive, cls, reporter) {
  let res

  if (tag === 'seqof') { tag = 'seq' } else if (tag === 'setof') { tag = 'set' }

  if (Object.prototype.hasOwnProperty.call(der.tagByName, tag)) { res = der.tagByName[tag] } else if (typeof tag === 'number' && (tag | 0) === tag) { res = tag } else { return reporter.error(`Unknown tag: ${tag}`) }

  if (res >= 0x1f) { return reporter.error('Multi-octet tag encoding unsupported') }

  if (!primitive) { res |= 0x20 }

  res |= (der.tagClassByName[cls || 'universal'] << 6)

  return res
}

module.exports = DEREncoder


/***/ }),

/***/ "ZXG7":
/***/ (function(module, exports, __webpack_require__) {

const { EOL } = __webpack_require__("jle/")

const base64url = __webpack_require__("Xab3")
const isDisjoint = __webpack_require__("KQbz")
const isObject = __webpack_require__("kF1/")
let validateCrit = __webpack_require__("urXW")
const getKey = __webpack_require__("oGTz")
const { KeyStore } = __webpack_require__("WPgm")
const errors = __webpack_require__("yt7c")
const { check, verify } = __webpack_require__("FUB/")
const JWK = __webpack_require__("lA9T")

const { detect: resolveSerialization } = __webpack_require__("SwXk")

validateCrit = validateCrit.bind(undefined, errors.JWSInvalid)
const SINGLE_RECIPIENT = new Set(['compact', 'flattened', 'preparsed'])

/*
 * @public
 */
const jwsVerify = (skipDisjointCheck, serialization, jws, key, { crit = [], complete = false, algorithms, parse = true, encoding = 'utf8' } = {}) => {
  key = getKey(key, true)

  if (algorithms !== undefined && (!Array.isArray(algorithms) || algorithms.some(s => typeof s !== 'string' || !s))) {
    throw new TypeError('"algorithms" option must be an array of non-empty strings')
  } else if (algorithms) {
    algorithms = new Set(algorithms)
  }

  if (!Array.isArray(crit) || crit.some(s => typeof s !== 'string' || !s)) {
    throw new TypeError('"crit" option must be an array of non-empty strings')
  }

  if (!serialization) {
    serialization = resolveSerialization(jws)
  }

  let prot // protected header
  let header // unprotected header
  let payload
  let signature
  let alg

  // treat general format with one recipient as flattened
  // skips iteration and avoids multi errors in this case
  if (serialization === 'general' && jws.signatures.length === 1) {
    serialization = 'flattened'
    const { signatures, ...root } = jws
    jws = { ...root, ...signatures[0] }
  }

  let decoded

  if (SINGLE_RECIPIENT.has(serialization)) {
    let parsedProt = {}

    switch (serialization) {
      case 'compact': // compact serialization format
        ([prot, payload, signature] = jws.split('.'))
        break
      case 'flattened': // flattened serialization format
        ({ protected: prot, payload, signature, header } = jws)
        break
      case 'preparsed': { // from the JWT module
        ({ decoded } = jws);
        ([prot, payload, signature] = jws.token.split('.'))
        break
      }
    }

    if (!header) {
      skipDisjointCheck = true
    }

    if (decoded) {
      parsedProt = decoded.header
    } else if (prot) {
      try {
        parsedProt = base64url.JSON.decode(prot)
      } catch (err) {
        throw new errors.JWSInvalid('could not parse JWS protected header')
      }
    } else {
      skipDisjointCheck = skipDisjointCheck || true
    }

    if (!skipDisjointCheck && !isDisjoint(parsedProt, header)) {
      throw new errors.JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint')
    }

    const combinedHeader = { ...parsedProt, ...header }
    validateCrit(parsedProt, header, crit)

    alg = parsedProt.alg || (header && header.alg)
    if (!alg) {
      throw new errors.JWSInvalid('missing JWS signature algorithm')
    } else if (algorithms && !algorithms.has(alg)) {
      throw new errors.JOSEAlgNotWhitelisted('alg not whitelisted')
    }

    if (key instanceof KeyStore) {
      const keystore = key
      const keys = keystore.all({ kid: combinedHeader.kid, alg: combinedHeader.alg, key_ops: ['verify'] })
      switch (keys.length) {
        case 0:
          throw new errors.JWKSNoMatchingKey()
        case 1:
          // treat the call as if a Key instance was passed in
          // skips iteration and avoids multi errors in this case
          key = keys[0]
          break
        default: {
          const errs = []
          for (const key of keys) {
            try {
              return jwsVerify(true, serialization, jws, key, { crit, complete, encoding, parse, algorithms: algorithms ? [...algorithms] : undefined })
            } catch (err) {
              errs.push(err)
              continue
            }
          }

          const multi = new errors.JOSEMultiError(errs)
          if ([...multi].some(e => e instanceof errors.JWSVerificationFailed)) {
            throw new errors.JWSVerificationFailed()
          }
          throw multi
        }
      }
    }

    if (key === JWK.EmbeddedJWK) {
      if (!isObject(combinedHeader.jwk)) {
        throw new errors.JWSInvalid('JWS Header Parameter "jwk" must be a JSON object')
      }
      key = JWK.asKey(combinedHeader.jwk)
      if (key.type !== 'public') {
        throw new errors.JWSInvalid('JWS Header Parameter "jwk" must be a public key')
      }
    } else if (key === JWK.EmbeddedX5C) {
      if (!Array.isArray(combinedHeader.x5c) || !combinedHeader.x5c.length || combinedHeader.x5c.some(c => typeof c !== 'string' || !c)) {
        throw new errors.JWSInvalid('JWS Header Parameter "x5c" must be a JSON array of certificate value strings')
      }
      key = JWK.asKey(
        `-----BEGIN CERTIFICATE-----${EOL}${(combinedHeader.x5c[0].match(/.{1,64}/g) || []).join(EOL)}${EOL}-----END CERTIFICATE-----`,
        { x5c: combinedHeader.x5c }
      )
    }

    check(key, 'verify', alg)

    const toBeVerified = Buffer.concat([
      Buffer.from(prot || ''),
      Buffer.from('.'),
      Buffer.isBuffer(payload) ? payload : Buffer.from(payload)
    ])

    if (!verify(alg, key, toBeVerified, base64url.decodeToBuffer(signature))) {
      throw new errors.JWSVerificationFailed()
    }

    if (!combinedHeader.crit || !combinedHeader.crit.includes('b64') || combinedHeader.b64) {
      if (parse) {
        payload = decoded ? decoded.payload : base64url.JSON.decode.try(payload, encoding)
      } else {
        payload = base64url.decodeToBuffer(payload)
      }
    }

    if (complete) {
      const result = { payload, key }
      if (prot) result.protected = parsedProt
      if (header) result.header = header
      return result
    }

    return payload
  }

  // general serialization format
  const { signatures, ...root } = jws
  const errs = []
  for (const recipient of signatures) {
    try {
      return jwsVerify(false, 'flattened', { ...root, ...recipient }, key, { crit, complete, encoding, parse, algorithms: algorithms ? [...algorithms] : undefined })
    } catch (err) {
      errs.push(err)
      continue
    }
  }

  const multi = new errors.JOSEMultiError(errs)
  if ([...multi].some(e => e instanceof errors.JWSVerificationFailed)) {
    throw new errors.JWSVerificationFailed()
  } else if ([...multi].every(e => e instanceof errors.JWKSNoMatchingKey)) {
    throw new errors.JWKSNoMatchingKey()
  }
  throw multi
}

module.exports = {
  bare: jwsVerify,
  verify: jwsVerify.bind(undefined, false, undefined)
}


/***/ }),

/***/ "ZfBq":
/***/ (function(module, exports, __webpack_require__) {

const { strict: assert } = __webpack_require__("Qs3B");
const { createHash } = __webpack_require__("PJMN");
const { format } = __webpack_require__("jK02");

const shake256 = __webpack_require__("5sMl");

const fromBase64 = (base64) => base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const encode = (input) => fromBase64(input.toString('base64'));

/** SPECIFICATION
 * Its (_hash) value is the base64url encoding of the left-most half of the hash of the octets of
 * the ASCII representation of the token value, where the hash algorithm used is the hash algorithm
 * used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is
 * RS256, hash the token value with SHA-256, then take the left-most 128 bits and base64url encode
 * them. The _hash value is a case sensitive string.
 */

/**
 * @name getHash
 * @api private
 *
 * returns the sha length based off the JOSE alg heade value, defaults to sha256
 *
 * @param token {String} token value to generate the hash from
 * @param alg {String} ID Token JOSE header alg value (i.e. RS256, HS384, ES512, PS256)
 * @param [crv] {String} For EdDSA the curve decides what hash algorithm is used. Required for EdDSA
 */
function getHash(alg, crv) {
  switch (alg) {
    case 'HS256':
    case 'RS256':
    case 'PS256':
    case 'ES256':
    case 'ES256K':
      return createHash('sha256');

    case 'HS384':
    case 'RS384':
    case 'PS384':
    case 'ES384':
      return createHash('sha384');

    case 'HS512':
    case 'RS512':
    case 'PS512':
    case 'ES512':
      return createHash('sha512');

    case 'EdDSA':
      switch (crv) {
        case 'Ed25519':
          return createHash('sha512');
        case 'Ed448':
          if (!shake256) {
            throw new TypeError('Ed448 *_hash calculation is not supported in your Node.js runtime version');
          }

          return createHash('shake256', { outputLength: 114 });
        default:
          throw new TypeError('unrecognized or invalid EdDSA curve provided');
      }

    default:
      throw new TypeError('unrecognized or invalid JWS algorithm provided');
  }
}

function generate(token, alg, crv) {
  const digest = getHash(alg, crv).update(token).digest();
  return encode(digest.slice(0, digest.length / 2));
}

function validate(names, actual, source, alg, crv) {
  if (typeof names.claim !== 'string' || !names.claim) {
    throw new TypeError('names.claim must be a non-empty string');
  }

  if (typeof names.source !== 'string' || !names.source) {
    throw new TypeError('names.source must be a non-empty string');
  }

  assert(typeof actual === 'string' && actual, `${names.claim} must be a non-empty string`);
  assert(typeof source === 'string' && source, `${names.source} must be a non-empty string`);

  let expected;
  let msg;
  try {
    expected = generate(source, alg, crv);
  } catch (err) {
    msg = format('%s could not be validated (%s)', names.claim, err.message);
  }

  msg = msg || format('%s mismatch, expected %s, got: %s', names.claim, expected, actual);

  assert.equal(expected, actual, msg);
}

module.exports = {
  validate,
  generate,
};


/***/ }),

/***/ "aIoy":
/***/ (function(module, exports, __webpack_require__) {

const { deprecate, inspect } = __webpack_require__("jK02")

const isObject = __webpack_require__("kF1/")
const { generate, generateSync } = __webpack_require__("LDEB")
const { USES_MAPPING } = __webpack_require__("ehsS")
const { isKey, asKey: importKey } = __webpack_require__("lA9T")

const keyscore = (key, { alg, use, ops }) => {
  let score = 0

  if (alg && key.alg) {
    score++
  }

  if (use && key.use) {
    score++
  }

  if (ops && key.key_ops) {
    score++
  }

  return score
}

class KeyStore {
  constructor (...keys) {
    while (keys.some(Array.isArray)) {
      keys = keys.flat ? keys.flat() : keys.reduce((acc, val) => {
        if (Array.isArray(val)) {
          return [...acc, ...val]
        }

        acc.push(val)
        return acc
      }, [])
    }
    if (keys.some(k => !isKey(k) || !k.kty)) {
      throw new TypeError('all keys must be instances of a key instantiated by JWK.asKey')
    }

    this._keys = new Set(keys)
  }

  all ({ alg, kid, thumbprint, use, kty, key_ops: ops, x5t, 'x5t#S256': x5t256, crv } = {}) {
    if (ops !== undefined && (!Array.isArray(ops) || !ops.length || ops.some(x => typeof x !== 'string'))) {
      throw new TypeError('`key_ops` must be a non-empty array of strings')
    }

    const search = { alg, use, ops }
    return [...this._keys]
      .filter((key) => {
        let candidate = true

        if (candidate && kid !== undefined && key.kid !== kid) {
          candidate = false
        }

        if (candidate && thumbprint !== undefined && key.thumbprint !== thumbprint) {
          candidate = false
        }

        if (candidate && x5t !== undefined && key.x5t !== x5t) {
          candidate = false
        }

        if (candidate && x5t256 !== undefined && key['x5t#S256'] !== x5t256) {
          candidate = false
        }

        if (candidate && kty !== undefined && key.kty !== kty) {
          candidate = false
        }

        if (candidate && crv !== undefined && (key.crv !== crv)) {
          candidate = false
        }

        if (alg !== undefined && !key.algorithms().has(alg)) {
          candidate = false
        }

        if (candidate && use !== undefined && (key.use !== undefined && key.use !== use)) {
          candidate = false
        }

        // TODO:
        if (candidate && ops !== undefined && (key.key_ops !== undefined || key.use !== undefined)) {
          let keyOps
          if (key.key_ops) {
            keyOps = new Set(key.key_ops)
          } else {
            keyOps = USES_MAPPING[key.use]
          }
          if (ops.some(x => !keyOps.has(x))) {
            candidate = false
          }
        }

        return candidate
      })
      .sort((first, second) => keyscore(second, search) - keyscore(first, search))
  }

  get (...args) {
    return this.all(...args)[0]
  }

  add (key) {
    if (!isKey(key) || !key.kty) {
      throw new TypeError('key must be an instance of a key instantiated by JWK.asKey')
    }

    this._keys.add(key)
  }

  remove (key) {
    if (!isKey(key)) {
      throw new TypeError('key must be an instance of a key instantiated by JWK.asKey')
    }

    this._keys.delete(key)
  }

  toJWKS (priv = false) {
    return {
      keys: [...this._keys.values()].map(
        key => key.toJWK(priv && (key.private || (key.secret && key.k)))
      )
    }
  }

  async generate (...args) {
    this._keys.add(await generate(...args))
  }

  generateSync (...args) {
    this._keys.add(generateSync(...args))
  }

  get size () {
    return this._keys.size
  }

  /* c8 ignore next 8 */
  [inspect.custom] () {
    return `${this.constructor.name} ${inspect(this.toJWKS(false), {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true
    })}`
  }

  * [Symbol.iterator] () {
    for (const key of this._keys) {
      yield key
    }
  }
}

function asKeyStore (jwks, { ignoreErrors = false, calculateMissingRSAPrimes = false } = {}) {
  if (!isObject(jwks) || !Array.isArray(jwks.keys) || jwks.keys.some(k => !isObject(k) || !('kty' in k))) {
    throw new TypeError('jwks must be a JSON Web Key Set formatted object')
  }

  const keys = jwks.keys.map((jwk) => {
    try {
      return importKey(jwk, { calculateMissingRSAPrimes })
    } catch (err) {
      if (!ignoreErrors) {
        throw err
      }
    }
  }).filter(Boolean)

  return new KeyStore(...keys)
}

Object.defineProperty(KeyStore, 'fromJWKS', {
  value: deprecate(jwks => asKeyStore(jwks, { calculateMissingRSAPrimes: true }), 'JWKS.KeyStore.fromJWKS() is deprecated, use JWKS.asKeyStore() instead'),
  enumerable: false
})

module.exports = { KeyStore, asKeyStore }


/***/ }),

/***/ "aOmh":
/***/ (function(module, exports) {

module.exports = new Map()


/***/ }),

/***/ "awVX":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (promise) {

    return !!promise && typeof promise.then === 'function';
};


/***/ }),

/***/ "b1HN":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
// ISC @ Julien Fontanet



// ===================================================================

var construct = typeof Reflect !== "undefined" ? Reflect.construct : undefined;
var defineProperty = Object.defineProperty;

// -------------------------------------------------------------------

var captureStackTrace = Error.captureStackTrace;
if (captureStackTrace === undefined) {
  captureStackTrace = function captureStackTrace(error) {
    var container = new Error();

    defineProperty(error, "stack", {
      configurable: true,
      get: function getStack() {
        var stack = container.stack;

        // Replace property with value for faster future accesses.
        defineProperty(this, "stack", {
          configurable: true,
          value: stack,
          writable: true,
        });

        return stack;
      },
      set: function setStack(stack) {
        defineProperty(error, "stack", {
          configurable: true,
          value: stack,
          writable: true,
        });
      },
    });
  };
}

// -------------------------------------------------------------------

function BaseError(message) {
  if (message !== undefined) {
    defineProperty(this, "message", {
      configurable: true,
      value: message,
      writable: true,
    });
  }

  var cname = this.constructor.name;
  if (cname !== undefined && cname !== this.name) {
    defineProperty(this, "name", {
      configurable: true,
      value: cname,
      writable: true,
    });
  }

  captureStackTrace(this, this.constructor);
}

BaseError.prototype = Object.create(Error.prototype, {
  // See: https://github.com/JsCommunity/make-error/issues/4
  constructor: {
    configurable: true,
    value: BaseError,
    writable: true,
  },
});

// -------------------------------------------------------------------

// Sets the name of a function if possible (depends of the JS engine).
var setFunctionName = (function() {
  function setFunctionName(fn, name) {
    return defineProperty(fn, "name", {
      configurable: true,
      value: name,
    });
  }
  try {
    var f = function() {};
    setFunctionName(f, "foo");
    if (f.name === "foo") {
      return setFunctionName;
    }
  } catch (_) {}
})();

// -------------------------------------------------------------------

function makeError(constructor, super_) {
  if (super_ == null || super_ === Error) {
    super_ = BaseError;
  } else if (typeof super_ !== "function") {
    throw new TypeError("super_ should be a function");
  }

  var name;
  if (typeof constructor === "string") {
    name = constructor;
    constructor =
      construct !== undefined
        ? function() {
            return construct(super_, arguments, this.constructor);
          }
        : function() {
            super_.apply(this, arguments);
          };

    // If the name can be set, do it once and for all.
    if (setFunctionName !== undefined) {
      setFunctionName(constructor, name);
      name = undefined;
    }
  } else if (typeof constructor !== "function") {
    throw new TypeError("constructor should be either a string or a function");
  }

  // Also register the super constructor also as `constructor.super_` just
  // like Node's `util.inherits()`.
  //
  // eslint-disable-next-line dot-notation
  constructor.super_ = constructor["super"] = super_;

  var properties = {
    constructor: {
      configurable: true,
      value: constructor,
      writable: true,
    },
  };

  // If the name could not be set on the constructor, set it on the
  // prototype.
  if (name !== undefined) {
    properties.name = {
      configurable: true,
      value: name,
      writable: true,
    };
  }
  constructor.prototype = Object.create(super_.prototype, properties);

  return constructor;
}
exports = module.exports = makeError;
exports.BaseError = BaseError;


/***/ }),

/***/ "b1mx":
/***/ (function(module, exports, __webpack_require__) {

var once = __webpack_require__("VmuJ")
var eos = __webpack_require__("q1Jy")
var fs = __webpack_require__("mw/K") // we only need fs to get the ReadStream and WriteStream prototypes

var noop = function () {}
var ancient = /^v?\.0/.test(process.version)

var isFn = function (fn) {
  return typeof fn === 'function'
}

var isFS = function (stream) {
  if (!ancient) return false // newer node version do not need to care about fs is a special way
  if (!fs) return false // browser
  return (stream instanceof (fs.ReadStream || noop) || stream instanceof (fs.WriteStream || noop)) && isFn(stream.close)
}

var isRequest = function (stream) {
  return stream.setHeader && isFn(stream.abort)
}

var destroyer = function (stream, reading, writing, callback) {
  callback = once(callback)

  var closed = false
  stream.on('close', function () {
    closed = true
  })

  eos(stream, {readable: reading, writable: writing}, function (err) {
    if (err) return callback(err)
    closed = true
    callback()
  })

  var destroyed = false
  return function (err) {
    if (closed) return
    if (destroyed) return
    destroyed = true

    if (isFS(stream)) return stream.close(noop) // use close for fs streams to avoid fd leaks
    if (isRequest(stream)) return stream.abort() // request.destroy just do .end - .abort is what we want

    if (isFn(stream.destroy)) return stream.destroy()

    callback(err || new Error('stream was destroyed'))
  }
}

var call = function (fn) {
  fn()
}

var pipe = function (from, to) {
  return from.pipe(to)
}

var pump = function () {
  var streams = Array.prototype.slice.call(arguments)
  var callback = isFn(streams[streams.length - 1] || noop) && streams.pop() || noop

  if (Array.isArray(streams[0])) streams = streams[0]
  if (streams.length < 2) throw new Error('pump requires two streams per minimum')

  var error
  var destroys = streams.map(function (stream, i) {
    var reading = i < streams.length - 1
    var writing = i > 0
    return destroyer(stream, reading, writing, function (err) {
      if (!error) error = err
      if (err) destroys.forEach(call)
      if (reading) return
      destroys.forEach(call)
      callback(error)
    })
  })

  return streams.reduce(pipe)
}

module.exports = pump


/***/ }),

/***/ "b9eJ":
/***/ (function(module, exports, __webpack_require__) {

const { getCurves } = __webpack_require__("PJMN")

const { name: secp256k1 } = __webpack_require__("F/JS")

const curves = new Set()

if (getCurves().includes('prime256v1')) {
  curves.add('P-256')
}

if (getCurves().includes('secp256k1')) {
  curves.add(secp256k1)
}

if (getCurves().includes('secp384r1')) {
  curves.add('P-384')
}

if (getCurves().includes('secp521r1')) {
  curves.add('P-521')
}

module.exports = curves


/***/ }),

/***/ "bDas":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    const lessThan = 0x3C;
    const greaterThan = 0x3E;
    const andSymbol = 0x26;
    const lineSeperator = 0x2028;

    // replace method
    let charCode;
    return input.replace(/[<>&\u2028\u2029]/g, (match) => {

        charCode = match.charCodeAt(0);

        if (charCode === lessThan) {
            return '\\u003c';
        }

        if (charCode === greaterThan) {
            return '\\u003e';
        }

        if (charCode === andSymbol) {
            return '\\u0026';
        }

        if (charCode === lineSeperator) {
            return '\\u2028';
        }

        return '\\u2029';
    });
};


/***/ }),

/***/ "bUME":
/***/ (function(module, exports, __webpack_require__) {

const { createCipheriv, createDecipheriv, getCiphers } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const { asInput } = __webpack_require__("1ALl")

const checkInput = (data) => {
  if (data !== undefined && data.length % 8 !== 0) {
    throw new Error('invalid data length')
  }
}

const wrapKey = (alg, { [KEYOBJECT]: keyObject }, payload) => {
  const key = asInput(keyObject, false)
  const cipher = createCipheriv(alg, key, Buffer.alloc(8, 'a6', 'hex'))

  return { wrapped: Buffer.concat([cipher.update(payload), cipher.final()]) }
}

const unwrapKey = (alg, { [KEYOBJECT]: keyObject }, payload) => {
  const key = asInput(keyObject, false)
  checkInput(payload)
  const cipher = createDecipheriv(alg, key, Buffer.alloc(8, 'a6', 'hex'))

  return Buffer.concat([cipher.update(payload), cipher.final()])
}

module.exports = (JWA, JWK) => {
  ['A128KW', 'A192KW', 'A256KW'].forEach((jwaAlg) => {
    const size = parseInt(jwaAlg.substr(1, 3), 10)
    const alg = `aes${size}-wrap`
    if (getCiphers().includes(alg)) {
      JWA.keyManagementEncrypt.set(jwaAlg, wrapKey.bind(undefined, alg))
      JWA.keyManagementDecrypt.set(jwaAlg, unwrapKey.bind(undefined, alg))
      JWK.oct.wrapKey[jwaAlg] = JWK.oct.unwrapKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.length === size
    }
  })
}


/***/ }),

/***/ "bkX/":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Types = __webpack_require__("8g7u");


const internals = {
    mismatched: null
};


module.exports = function (obj, ref, options) {

    options = Object.assign({ prototype: true }, options);

    return !!internals.isDeepEqual(obj, ref, options, []);
};


internals.isDeepEqual = function (obj, ref, options, seen) {

    if (obj === ref) {                                                      // Copied from Deep-eql, copyright(c) 2013 Jake Luer, jake@alogicalparadox.com, MIT Licensed, https://github.com/chaijs/deep-eql
        return obj !== 0 || 1 / obj === 1 / ref;
    }

    const type = typeof obj;

    if (type !== typeof ref) {
        return false;
    }

    if (obj === null ||
        ref === null) {

        return false;
    }

    if (type === 'function') {
        if (!options.deepFunction ||
            obj.toString() !== ref.toString()) {

            return false;
        }

        // Continue as object
    }
    else if (type !== 'object') {
        return obj !== obj && ref !== ref;                                  // NaN
    }

    const instanceType = internals.getSharedType(obj, ref, !!options.prototype);
    switch (instanceType) {
        case Types.buffer:
            return Buffer && Buffer.prototype.equals.call(obj, ref);        // $lab:coverage:ignore$
        case Types.promise:
            return obj === ref;
        case Types.regex:
            return obj.toString() === ref.toString();
        case internals.mismatched:
            return false;
    }

    for (let i = seen.length - 1; i >= 0; --i) {
        if (seen[i].isSame(obj, ref)) {
            return true;                                                    // If previous comparison failed, it would have stopped execution
        }
    }

    seen.push(new internals.SeenEntry(obj, ref));

    try {
        return !!internals.isDeepEqualObj(instanceType, obj, ref, options, seen);
    }
    finally {
        seen.pop();
    }
};


internals.getSharedType = function (obj, ref, checkPrototype) {

    if (checkPrototype) {
        if (Object.getPrototypeOf(obj) !== Object.getPrototypeOf(ref)) {
            return internals.mismatched;
        }

        return Types.getInternalProto(obj);
    }

    const type = Types.getInternalProto(obj);
    if (type !== Types.getInternalProto(ref)) {
        return internals.mismatched;
    }

    return type;
};


internals.valueOf = function (obj) {

    const objValueOf = obj.valueOf;
    if (objValueOf === undefined) {
        return obj;
    }

    try {
        return objValueOf.call(obj);
    }
    catch (err) {
        return err;
    }
};


internals.hasOwnEnumerableProperty = function (obj, key) {

    return Object.prototype.propertyIsEnumerable.call(obj, key);
};


internals.isSetSimpleEqual = function (obj, ref) {

    for (const entry of obj) {
        if (!ref.has(entry)) {
            return false;
        }
    }

    return true;
};


internals.isDeepEqualObj = function (instanceType, obj, ref, options, seen) {

    const { isDeepEqual, valueOf, hasOwnEnumerableProperty } = internals;
    const { keys, getOwnPropertySymbols } = Object;

    if (instanceType === Types.array) {
        if (options.part) {

            // Check if any index match any other index

            for (const objValue of obj) {
                for (const refValue of ref) {
                    if (isDeepEqual(objValue, refValue, options, seen)) {
                        return true;
                    }
                }
            }
        }
        else {
            if (obj.length !== ref.length) {
                return false;
            }

            for (let i = 0; i < obj.length; ++i) {
                if (!isDeepEqual(obj[i], ref[i], options, seen)) {
                    return false;
                }
            }

            return true;
        }
    }
    else if (instanceType === Types.set) {
        if (obj.size !== ref.size) {
            return false;
        }

        if (!internals.isSetSimpleEqual(obj, ref)) {

            // Check for deep equality

            const ref2 = new Set(ref);
            for (const objEntry of obj) {
                if (ref2.delete(objEntry)) {
                    continue;
                }

                let found = false;
                for (const refEntry of ref2) {
                    if (isDeepEqual(objEntry, refEntry, options, seen)) {
                        ref2.delete(refEntry);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    return false;
                }
            }
        }
    }
    else if (instanceType === Types.map) {
        if (obj.size !== ref.size) {
            return false;
        }

        for (const [key, value] of obj) {
            if (value === undefined && !ref.has(key)) {
                return false;
            }

            if (!isDeepEqual(value, ref.get(key), options, seen)) {
                return false;
            }
        }
    }
    else if (instanceType === Types.error) {

        // Always check name and message

        if (obj.name !== ref.name ||
            obj.message !== ref.message) {

            return false;
        }
    }

    // Check .valueOf()

    const valueOfObj = valueOf(obj);
    const valueOfRef = valueOf(ref);
    if ((obj !== valueOfObj || ref !== valueOfRef) &&
        !isDeepEqual(valueOfObj, valueOfRef, options, seen)) {

        return false;
    }

    // Check properties

    const objKeys = keys(obj);
    if (!options.part &&
        objKeys.length !== keys(ref).length &&
        !options.skip) {

        return false;
    }

    let skipped = 0;
    for (const key of objKeys) {
        if (options.skip &&
            options.skip.includes(key)) {

            if (ref[key] === undefined) {
                ++skipped;
            }

            continue;
        }

        if (!hasOwnEnumerableProperty(ref, key)) {
            return false;
        }

        if (!isDeepEqual(obj[key], ref[key], options, seen)) {
            return false;
        }
    }

    if (!options.part &&
        objKeys.length - skipped !== keys(ref).length) {

        return false;
    }

    // Check symbols

    if (options.symbols !== false) {                                // Defaults to true
        const objSymbols = getOwnPropertySymbols(obj);
        const refSymbols = new Set(getOwnPropertySymbols(ref));

        for (const key of objSymbols) {
            if (!options.skip ||
                !options.skip.includes(key)) {

                if (hasOwnEnumerableProperty(obj, key)) {
                    if (!hasOwnEnumerableProperty(ref, key)) {
                        return false;
                    }

                    if (!isDeepEqual(obj[key], ref[key], options, seen)) {
                        return false;
                    }
                }
                else if (hasOwnEnumerableProperty(ref, key)) {
                    return false;
                }
            }

            refSymbols.delete(key);
        }

        for (const key of refSymbols) {
            if (hasOwnEnumerableProperty(ref, key)) {
                return false;
            }
        }
    }

    return true;
};


internals.SeenEntry = class {

    constructor(obj, ref) {

        this.obj = obj;
        this.ref = ref;
    }

    isSame(obj, ref) {

        return this.obj === obj && this.ref === ref;
    }
};


/***/ }),

/***/ "bzos":
/***/ (function(module, exports) {

module.exports = require("url");

/***/ }),

/***/ "c1/D":
/***/ (function(module, exports, __webpack_require__) {

const { inherits } = __webpack_require__("jK02")

const DEREncoder = __webpack_require__("ZUdF")

function PEMEncoder (entity) {
  DEREncoder.call(this, entity)
  this.enc = 'pem'
}
inherits(PEMEncoder, DEREncoder)

PEMEncoder.prototype.encode = function encode (data, options) {
  const buf = DEREncoder.prototype.encode.call(this, data)

  const p = buf.toString('base64')
  const out = [`-----BEGIN ${options.label}-----`]
  for (let i = 0; i < p.length; i += 64) { out.push(p.slice(i, i + 64)) }
  out.push(`-----END ${options.label}-----`)
  return out.join('\n')
}

module.exports = PEMEncoder


/***/ }),

/***/ "canG":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const errors = __webpack_require__("9Fi5");
const asStream = __webpack_require__("kjw5");
const asPromise = __webpack_require__("4UWp");
const normalizeArguments = __webpack_require__("whhB");
const merge = __webpack_require__("AW8e");
const deepFreeze = __webpack_require__("z/H/");

const getPromiseOrStream = options => options.stream ? asStream(options) : asPromise(options);

const aliases = [
	'get',
	'post',
	'put',
	'patch',
	'head',
	'delete'
];

const create = defaults => {
	defaults = merge({}, defaults);
	normalizeArguments.preNormalize(defaults.options);

	if (!defaults.handler) {
		// This can't be getPromiseOrStream, because when merging
		// the chain would stop at this point and no further handlers would be called.
		defaults.handler = (options, next) => next(options);
	}

	function got(url, options) {
		try {
			return defaults.handler(normalizeArguments(url, options, defaults), getPromiseOrStream);
		} catch (error) {
			if (options && options.stream) {
				throw error;
			} else {
				return Promise.reject(error);
			}
		}
	}

	got.create = create;
	got.extend = options => {
		let mutableDefaults;
		if (options && Reflect.has(options, 'mutableDefaults')) {
			mutableDefaults = options.mutableDefaults;
			delete options.mutableDefaults;
		} else {
			mutableDefaults = defaults.mutableDefaults;
		}

		return create({
			options: merge.options(defaults.options, options),
			handler: defaults.handler,
			mutableDefaults
		});
	};

	got.mergeInstances = (...args) => create(merge.instances(args));

	got.stream = (url, options) => got(url, {...options, stream: true});

	for (const method of aliases) {
		got[method] = (url, options) => got(url, {...options, method});
		got.stream[method] = (url, options) => got.stream(url, {...options, method});
	}

	Object.assign(got, {...errors, mergeOptions: merge.options});
	Object.defineProperty(got, 'defaults', {
		value: defaults.mutableDefaults ? defaults : deepFreeze(defaults),
		writable: defaults.mutableDefaults,
		configurable: defaults.mutableDefaults,
		enumerable: true
	});

	return got;
};

module.exports = create;


/***/ }),

/***/ "d4WF":
/***/ (function(module, exports, __webpack_require__) {

const { createCipheriv, createDecipheriv, getCiphers } = __webpack_require__("PJMN")

const uint64be = __webpack_require__("PsWn")
const timingSafeEqual = __webpack_require__("kuaU")
const { KEYOBJECT } = __webpack_require__("ehsS")
const { JWEInvalid, JWEDecryptionFailed } = __webpack_require__("yt7c")

const checkInput = function (size, iv, tag) {
  if (iv.length !== 16) {
    throw new JWEInvalid('invalid iv')
  }
  if (arguments.length === 3) {
    if (tag.length !== size / 8) {
      throw new JWEInvalid('invalid tag')
    }
  }
}

const encrypt = (size, sign, { [KEYOBJECT]: keyObject }, cleartext, { iv, aad = Buffer.alloc(0) }) => {
  const key = keyObject.export()
  checkInput(size, iv)

  const keySize = size / 8
  const encKey = key.slice(keySize)
  const cipher = createCipheriv(`aes-${size}-cbc`, encKey, iv)
  const ciphertext = Buffer.concat([cipher.update(cleartext), cipher.final()])
  const macData = Buffer.concat([aad, iv, ciphertext, uint64be(aad.length * 8)])

  const macKey = key.slice(0, keySize)
  const tag = sign({ [KEYOBJECT]: macKey }, macData).slice(0, keySize)

  return { ciphertext, tag }
}

const decrypt = (size, sign, { [KEYOBJECT]: keyObject }, ciphertext, { iv, tag = Buffer.alloc(0), aad = Buffer.alloc(0) }) => {
  checkInput(size, iv, tag)

  const keySize = size / 8
  const key = keyObject.export()
  const encKey = key.slice(keySize)
  const macKey = key.slice(0, keySize)

  const macData = Buffer.concat([aad, iv, ciphertext, uint64be(aad.length * 8)])
  const expectedTag = sign({ [KEYOBJECT]: macKey }, macData, tag).slice(0, keySize)
  const macCheckPassed = timingSafeEqual(tag, expectedTag)

  let cleartext
  try {
    const cipher = createDecipheriv(`aes-${size}-cbc`, encKey, iv)
    cleartext = Buffer.concat([cipher.update(ciphertext), cipher.final()])
  } catch (err) {}

  if (!cleartext || !macCheckPassed) {
    throw new JWEDecryptionFailed()
  }

  return cleartext
}

module.exports = (JWA, JWK) => {
  ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'].forEach((jwaAlg) => {
    const size = parseInt(jwaAlg.substr(1, 3), 10)
    const sign = JWA.sign.get(`HS${size * 2}`)
    if (getCiphers().includes(`aes-${size}-cbc`)) {
      JWA.encrypt.set(jwaAlg, encrypt.bind(undefined, size, sign))
      JWA.decrypt.set(jwaAlg, decrypt.bind(undefined, size, sign))
      JWK.oct.encrypt[jwaAlg] = JWK.oct.decrypt[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.length / 2 === size
    }
  })
}


/***/ }),

/***/ "dKo8":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function getSessionFromTokenSet(tokenSet) {
    // Get the claims without any OIDC specific claim.
    const claims = tokenSet.claims();
    if (claims.aud) {
        delete claims.aud;
    }
    if (claims.exp) {
        delete claims.exp;
    }
    if (claims.iat) {
        delete claims.iat;
    }
    if (claims.iss) {
        delete claims.iss;
    }
    // Create the session.
    return {
        user: Object.assign({}, claims),
        idToken: tokenSet.id_token,
        accessToken: tokenSet.access_token,
        accessTokenScope: tokenSet.scope,
        accessTokenExpiresAt: tokenSet.expires_at,
        refreshToken: tokenSet.refresh_token,
        createdAt: Date.now()
    };
}
exports.default = getSessionFromTokenSet;
//# sourceMappingURL=session.js.map

/***/ }),

/***/ "dOMb":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Ignore = __webpack_require__("kDq4");


const internals = {};


module.exports = function () {

    return new Promise(Ignore);         // $lab:coverage:ignore$
};


/***/ }),

/***/ "dr85":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


class CancelError extends Error {
	constructor(reason) {
		super(reason || 'Promise was canceled');
		this.name = 'CancelError';
	}

	get isCanceled() {
		return true;
	}
}

class PCancelable {
	static fn(userFn) {
		return (...arguments_) => {
			return new PCancelable((resolve, reject, onCancel) => {
				arguments_.push(onCancel);
				// eslint-disable-next-line promise/prefer-await-to-then
				userFn(...arguments_).then(resolve, reject);
			});
		};
	}

	constructor(executor) {
		this._cancelHandlers = [];
		this._isPending = true;
		this._isCanceled = false;
		this._rejectOnCancel = true;

		this._promise = new Promise((resolve, reject) => {
			this._reject = reject;

			const onResolve = value => {
				this._isPending = false;
				resolve(value);
			};

			const onReject = error => {
				this._isPending = false;
				reject(error);
			};

			const onCancel = handler => {
				if (!this._isPending) {
					throw new Error('The `onCancel` handler was attached after the promise settled.');
				}

				this._cancelHandlers.push(handler);
			};

			Object.defineProperties(onCancel, {
				shouldReject: {
					get: () => this._rejectOnCancel,
					set: boolean => {
						this._rejectOnCancel = boolean;
					}
				}
			});

			return executor(onResolve, onReject, onCancel);
		});
	}

	then(onFulfilled, onRejected) {
		// eslint-disable-next-line promise/prefer-await-to-then
		return this._promise.then(onFulfilled, onRejected);
	}

	catch(onRejected) {
		return this._promise.catch(onRejected);
	}

	finally(onFinally) {
		return this._promise.finally(onFinally);
	}

	cancel(reason) {
		if (!this._isPending || this._isCanceled) {
			return;
		}

		if (this._cancelHandlers.length > 0) {
			try {
				for (const handler of this._cancelHandlers) {
					handler();
				}
			} catch (error) {
				this._reject(error);
			}
		}

		this._isCanceled = true;
		if (this._rejectOnCancel) {
			this._reject(new CancelError(reason));
		}
	}

	get isCanceled() {
		return this._isCanceled;
	}
}

Object.setPrototypeOf(PCancelable.prototype, Promise.prototype);

module.exports = PCancelable;
module.exports.CancelError = CancelError;


/***/ }),

/***/ "e95r":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = {
    applyToDefaults: __webpack_require__("qRSN"),
    assert: __webpack_require__("q4ve"),
    Bench: __webpack_require__("hX4a"),
    block: __webpack_require__("dOMb"),
    clone: __webpack_require__("W5Ll"),
    contain: __webpack_require__("ngYE"),
    deepEqual: __webpack_require__("1VP5"),
    Error: __webpack_require__("FURP"),
    escapeHeaderAttribute: __webpack_require__("QBaJ"),
    escapeHtml: __webpack_require__("4Njv"),
    escapeJson: __webpack_require__("Hu8U"),
    escapeRegex: __webpack_require__("Ug5E"),
    flatten: __webpack_require__("BS6f"),
    ignore: __webpack_require__("kDq4"),
    intersect: __webpack_require__("4mwe"),
    isPromise: __webpack_require__("7kea"),
    merge: __webpack_require__("Fssn"),
    once: __webpack_require__("JXcb"),
    reach: __webpack_require__("zjbl"),
    reachTemplate: __webpack_require__("Fp5f"),
    stringify: __webpack_require__("VHkT"),
    wait: __webpack_require__("R0c8")
};


/***/ }),

/***/ "eC53":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const EventEmitter = __webpack_require__("/0p4");
const urlLib = __webpack_require__("bzos");
const normalizeUrl = __webpack_require__("VzzF");
const getStream = __webpack_require__("gK4g");
const CachePolicy = __webpack_require__("lERV");
const Response = __webpack_require__("O9zF");
const lowercaseKeys = __webpack_require__("D5mk");
const cloneResponse = __webpack_require__("21rS");
const Keyv = __webpack_require__("mxNO");

class CacheableRequest {
	constructor(request, cacheAdapter) {
		if (typeof request !== 'function') {
			throw new TypeError('Parameter `request` must be a function');
		}

		this.cache = new Keyv({
			uri: typeof cacheAdapter === 'string' && cacheAdapter,
			store: typeof cacheAdapter !== 'string' && cacheAdapter,
			namespace: 'cacheable-request'
		});

		return this.createCacheableRequest(request);
	}

	createCacheableRequest(request) {
		return (opts, cb) => {
			let url;
			if (typeof opts === 'string') {
				url = normalizeUrlObject(urlLib.parse(opts));
				opts = {};
			} else if (opts instanceof urlLib.URL) {
				url = normalizeUrlObject(urlLib.parse(opts.toString()));
				opts = {};
			} else {
				const [pathname, ...searchParts] = (opts.path || '').split('?');
				const search = searchParts.length > 0 ?
					`?${searchParts.join('?')}` :
					'';
				url = normalizeUrlObject({ ...opts, pathname, search });
			}

			opts = {
				headers: {},
				method: 'GET',
				cache: true,
				strictTtl: false,
				automaticFailover: false,
				...opts,
				...urlObjectToRequestOptions(url)
			};
			opts.headers = lowercaseKeys(opts.headers);

			const ee = new EventEmitter();
			const normalizedUrlString = normalizeUrl(
				urlLib.format(url),
				{
					stripWWW: false,
					removeTrailingSlash: false,
					stripAuthentication: false
				}
			);
			const key = `${opts.method}:${normalizedUrlString}`;
			let revalidate = false;
			let madeRequest = false;

			const makeRequest = opts => {
				madeRequest = true;
				let requestErrored = false;
				let requestErrorCallback;

				const requestErrorPromise = new Promise(resolve => {
					requestErrorCallback = () => {
						if (!requestErrored) {
							requestErrored = true;
							resolve();
						}
					};
				});

				const handler = response => {
					if (revalidate && !opts.forceRefresh) {
						response.status = response.statusCode;
						const revalidatedPolicy = CachePolicy.fromObject(revalidate.cachePolicy).revalidatedPolicy(opts, response);
						if (!revalidatedPolicy.modified) {
							const headers = revalidatedPolicy.policy.responseHeaders();
							response = new Response(revalidate.statusCode, headers, revalidate.body, revalidate.url);
							response.cachePolicy = revalidatedPolicy.policy;
							response.fromCache = true;
						}
					}

					if (!response.fromCache) {
						response.cachePolicy = new CachePolicy(opts, response, opts);
						response.fromCache = false;
					}

					let clonedResponse;
					if (opts.cache && response.cachePolicy.storable()) {
						clonedResponse = cloneResponse(response);

						(async () => {
							try {
								const bodyPromise = getStream.buffer(response);

								await Promise.race([
									requestErrorPromise,
									new Promise(resolve => response.once('end', resolve))
								]);

								if (requestErrored) {
									return;
								}

								const body = await bodyPromise;

								const value = {
									cachePolicy: response.cachePolicy.toObject(),
									url: response.url,
									statusCode: response.fromCache ? revalidate.statusCode : response.statusCode,
									body
								};

								let ttl = opts.strictTtl ? response.cachePolicy.timeToLive() : undefined;
								if (opts.maxTtl) {
									ttl = ttl ? Math.min(ttl, opts.maxTtl) : opts.maxTtl;
								}

								await this.cache.set(key, value, ttl);
							} catch (error) {
								ee.emit('error', new CacheableRequest.CacheError(error));
							}
						})();
					} else if (opts.cache && revalidate) {
						(async () => {
							try {
								await this.cache.delete(key);
							} catch (error) {
								ee.emit('error', new CacheableRequest.CacheError(error));
							}
						})();
					}

					ee.emit('response', clonedResponse || response);
					if (typeof cb === 'function') {
						cb(clonedResponse || response);
					}
				};

				try {
					const req = request(opts, handler);
					req.once('error', requestErrorCallback);
					req.once('abort', requestErrorCallback);
					ee.emit('request', req);
				} catch (error) {
					ee.emit('error', new CacheableRequest.RequestError(error));
				}
			};

			(async () => {
				const get = async opts => {
					await Promise.resolve();

					const cacheEntry = opts.cache ? await this.cache.get(key) : undefined;
					if (typeof cacheEntry === 'undefined') {
						return makeRequest(opts);
					}

					const policy = CachePolicy.fromObject(cacheEntry.cachePolicy);
					if (policy.satisfiesWithoutRevalidation(opts) && !opts.forceRefresh) {
						const headers = policy.responseHeaders();
						const response = new Response(cacheEntry.statusCode, headers, cacheEntry.body, cacheEntry.url);
						response.cachePolicy = policy;
						response.fromCache = true;

						ee.emit('response', response);
						if (typeof cb === 'function') {
							cb(response);
						}
					} else {
						revalidate = cacheEntry;
						opts.headers = policy.revalidationHeaders(opts);
						makeRequest(opts);
					}
				};

				const errorHandler = error => ee.emit('error', new CacheableRequest.CacheError(error));
				this.cache.once('error', errorHandler);
				ee.on('response', () => this.cache.removeListener('error', errorHandler));

				try {
					await get(opts);
				} catch (error) {
					if (opts.automaticFailover && !madeRequest) {
						makeRequest(opts);
					}

					ee.emit('error', new CacheableRequest.CacheError(error));
				}
			})();

			return ee;
		};
	}
}

function urlObjectToRequestOptions(url) {
	const options = { ...url };
	options.path = `${url.pathname || '/'}${url.search || ''}`;
	delete options.pathname;
	delete options.search;
	return options;
}

function normalizeUrlObject(url) {
	// If url was parsed by url.parse or new URL:
	// - hostname will be set
	// - host will be hostname[:port]
	// - port will be set if it was explicit in the parsed string
	// Otherwise, url was from request options:
	// - hostname or host may be set
	// - host shall not have port encoded
	return {
		protocol: url.protocol,
		auth: url.auth,
		hostname: url.hostname || url.host || 'localhost',
		port: url.port,
		pathname: url.pathname,
		search: url.search
	};
}

CacheableRequest.RequestError = class extends Error {
	constructor(error) {
		super(error.message);
		this.name = 'RequestError';
		Object.assign(this, error);
	}
};

CacheableRequest.CacheError = class extends Error {
	constructor(error) {
		super(error.message);
		this.name = 'CacheError';
		Object.assign(this, error);
	}
};

module.exports = CacheableRequest;


/***/ }),

/***/ "eEdi":
/***/ (function(module, exports, __webpack_require__) {

const { inspect } = __webpack_require__("jK02")

const Key = __webpack_require__("//Cd")

class EmbeddedJWK extends Key {
  constructor () {
    super({ type: 'embedded' })
    Object.defineProperties(this, {
      kid: { value: undefined },
      kty: { value: undefined },
      thumbprint: { value: undefined },
      toJWK: { value: undefined },
      toPEM: { value: undefined }
    })
  }

  /* c8 ignore next 3 */
  [inspect.custom] () {
    return 'Embedded.JWK {}'
  }

  algorithms () {
    return new Set()
  }
}

module.exports = new EmbeddedJWK()


/***/ }),

/***/ "eHfw":
/***/ (function(module, exports, __webpack_require__) {

/* global BigInt */

const { randomBytes } = __webpack_require__("PJMN")

const base64url = __webpack_require__("Xab3")
const errors = __webpack_require__("yt7c")

const ZERO = BigInt(0)
const ONE = BigInt(1)
const TWO = BigInt(2)

const toJWKParameter = (n) => {
  const hex = n.toString(16)
  return base64url.encodeBuffer(Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex'))
}
const fromBuffer = buf => BigInt(`0x${buf.toString('hex')}`)
const bitLength = n => n.toString(2).length

const eGcdX = (a, b) => {
  let x = ZERO
  let y = ONE
  let u = ONE
  let v = ZERO

  while (a !== ZERO) {
    const q = b / a
    const r = b % a
    const m = x - (u * q)
    const n = y - (v * q)
    b = a
    a = r
    x = u
    y = v
    u = m
    v = n
  }
  return x
}

const gcd = (a, b) => {
  let shift = ZERO
  while (!((a | b) & ONE)) {
    a >>= ONE
    b >>= ONE
    shift++
  }
  while (!(a & ONE)) {
    a >>= ONE
  }
  do {
    while (!(b & ONE)) {
      b >>= ONE
    }
    if (a > b) {
      const x = a
      a = b
      b = x
    }
    b -= a
  } while (b)

  return a << shift
}

const modPow = (a, b, n) => {
  a = toZn(a, n)
  let result = ONE
  let x = a
  while (b > 0) {
    var leastSignificantBit = b % TWO
    b = b / TWO
    if (leastSignificantBit === ONE) {
      result = result * x
      result = result % n
    }
    x = x * x
    x = x % n
  }
  return result
}

const randBetween = (min, max) => {
  const interval = max - min
  const bitLen = bitLength(interval)
  let rnd
  do {
    rnd = fromBuffer(randBits(bitLen))
  } while (rnd > interval)
  return rnd + min
}

const randBits = (bitLength) => {
  const byteLength = Math.ceil(bitLength / 8)
  const rndBytes = randomBytes(byteLength)
  // Fill with 0's the extra bits
  rndBytes[0] = rndBytes[0] & (2 ** (bitLength % 8) - 1)
  return rndBytes
}

const toZn = (a, n) => {
  a = a % n
  return (a < 0) ? a + n : a
}

const odd = (n) => {
  let r = n
  while (r % TWO === ZERO) {
    r = r / TWO
  }
  return r
}

// not sold on these values
const maxCountWhileNoY = 30
const maxCountWhileInot0 = 22

const getPrimeFactors = (e, d, n) => {
  const r = odd(e * d - ONE)

  let countWhileNoY = 0
  let y
  do {
    countWhileNoY++
    if (countWhileNoY === maxCountWhileNoY) {
      throw new errors.JWKImportFailed('failed to calculate missing primes')
    }

    let countWhileInot0 = 0
    let i = modPow(randBetween(TWO, n), r, n)
    let o = ZERO
    while (i !== ONE) {
      countWhileInot0++
      if (countWhileInot0 === maxCountWhileInot0) {
        throw new errors.JWKImportFailed('failed to calculate missing primes')
      }
      o = i
      i = (i * i) % n
    }
    if (o !== (n - ONE)) {
      y = o
    }
  } while (!y)

  const p = gcd(y - ONE, n)
  const q = n / p

  return p > q ? { p, q } : { p: q, q: p }
}

module.exports = (jwk) => {
  const e = fromBuffer(base64url.decodeToBuffer(jwk.e))
  const d = fromBuffer(base64url.decodeToBuffer(jwk.d))
  const n = fromBuffer(base64url.decodeToBuffer(jwk.n))

  if (d >= n) {
    throw new errors.JWKInvalid('invalid RSA private exponent')
  }

  const { p, q } = getPrimeFactors(e, d, n)
  const dp = d % (p - ONE)
  const dq = d % (q - ONE)
  const qi = toZn(eGcdX(toZn(q, p), p), p)

  return {
    ...jwk,
    p: toJWKParameter(p),
    q: toJWKParameter(q),
    dp: toJWKParameter(dp),
    dq: toJWKParameter(dq),
    qi: toJWKParameter(qi)
  }
}


/***/ }),

/***/ "ecj1":
/***/ (function(module, exports, __webpack_require__) {

const Issuer = __webpack_require__("A93I");
const { OPError, RPError } = __webpack_require__("L71r");
const Registry = __webpack_require__("0Aai");
const Strategy = __webpack_require__("/co4");
const TokenSet = __webpack_require__("IgmS");
const { CLOCK_TOLERANCE, HTTP_OPTIONS } = __webpack_require__("TJm8");
const generators = __webpack_require__("iAgo");
const { setDefaults } = __webpack_require__("UwMm");

module.exports = {
  Issuer,
  Registry,
  Strategy,
  TokenSet,
  errors: {
    OPError,
    RPError,
  },
  custom: {
    setHttpOptionsDefaults: setDefaults,
    http_options: HTTP_OPTIONS,
    clock_tolerance: CLOCK_TOLERANCE,
  },
  generators,
};


/***/ }),

/***/ "ehsS":
/***/ (function(module, exports) {

module.exports.KEYOBJECT = Symbol('KEYOBJECT')
module.exports.PRIVATE_MEMBERS = Symbol('PRIVATE_MEMBERS')
module.exports.PUBLIC_MEMBERS = Symbol('PUBLIC_MEMBERS')
module.exports.THUMBPRINT_MATERIAL = Symbol('THUMBPRINT_MATERIAL')
module.exports.JWK_MEMBERS = Symbol('JWK_MEMBERS')
module.exports.KEY_MANAGEMENT_ENCRYPT = Symbol('KEY_MANAGEMENT_ENCRYPT')
module.exports.KEY_MANAGEMENT_DECRYPT = Symbol('KEY_MANAGEMENT_DECRYPT')

const USES_MAPPING = {
  sig: new Set(['sign', 'verify']),
  enc: new Set(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey'])
}
const OPS = new Set([...USES_MAPPING.sig, ...USES_MAPPING.enc])
const USES = new Set(Object.keys(USES_MAPPING))

module.exports.USES_MAPPING = USES_MAPPING
module.exports.OPS = OPS
module.exports.USES = USES


/***/ }),

/***/ "eq/D":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("2BAz");


const internals = {};


module.exports = function (obj, chain, options) {

    if (chain === false ||
        chain === null ||
        chain === undefined) {

        return obj;
    }

    options = options || {};
    if (typeof options === 'string') {
        options = { separator: options };
    }

    const isChainArray = Array.isArray(chain);

    Assert(!isChainArray || !options.separator, 'Separator option no valid for array-based chain');

    const path = isChainArray ? chain : chain.split(options.separator || '.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        let key = path[i];
        const type = options.iterables && internals.iterables(ref);

        if (Array.isArray(ref) ||
            type === 'set') {

            const number = Number(key);
            if (Number.isInteger(number)) {
                key = number < 0 ? ref.length + number : number;
            }
        }

        if (!ref ||
            typeof ref === 'function' && options.functions === false ||         // Defaults to true
            !type && ref[key] === undefined) {

            Assert(!options.strict || i + 1 === path.length, 'Missing segment', key, 'in reach path ', chain);
            Assert(typeof ref === 'object' || options.functions === true || typeof ref !== 'function', 'Invalid segment', key, 'in reach path ', chain);
            ref = options.default;
            break;
        }

        if (!type) {
            ref = ref[key];
        }
        else if (type === 'set') {
            ref = [...ref][key];
        }
        else {  // type === 'map'
            ref = ref.get(key);
        }
    }

    return ref;
};


internals.iterables = function (ref) {

    if (ref instanceof Set) {
        return 'set';
    }

    if (ref instanceof Map) {
        return 'map';
    }
};


/***/ }),

/***/ "f/5Z":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("0LeV");


const internals = {};


exports.keys = function (obj, options = {}) {

    return options.symbols !== false ? Reflect.ownKeys(obj) : Object.getOwnPropertyNames(obj);  // Defaults to true
};


exports.store = function (source, keys) {

    const storage = new Map();
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        const value = Reach(source, key);
        if (typeof value === 'object' ||
            typeof value === 'function') {

            storage.set(key, value);
            internals.reachSet(source, key, undefined);
        }
    }

    return storage;
};


exports.restore = function (copy, source, storage) {

    for (const [key, value] of storage) {
        internals.reachSet(copy, key, value);
        internals.reachSet(source, key, value);
    }
};


internals.reachSet = function (obj, key, value) {

    const path = Array.isArray(key) ? key : key.split('.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        const segment = path[i];
        if (i + 1 === path.length) {
            ref[segment] = value;
        }

        ref = ref[segment];
    }
};


/***/ }),

/***/ "f0Nx":
/***/ (function(module, exports) {

const MAX_OCTET = 0x80
const CLASS_UNIVERSAL = 0
const PRIMITIVE_BIT = 0x20
const TAG_SEQ = 0x10
const TAG_INT = 0x02
const ENCODED_TAG_SEQ = (TAG_SEQ | PRIMITIVE_BIT) | (CLASS_UNIVERSAL << 6)
const ENCODED_TAG_INT = TAG_INT | (CLASS_UNIVERSAL << 6)

const getParamSize = keySize => ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1)

const paramBytesForAlg = {
  ES256: getParamSize(256),
  ES256K: getParamSize(256),
  ES384: getParamSize(384),
  ES512: getParamSize(521)
}

const countPadding = (buf, start, stop) => {
  let padding = 0
  while (start + padding < stop && buf[start + padding] === 0) {
    ++padding
  }

  const needsSign = buf[start + padding] >= MAX_OCTET
  if (needsSign) {
    --padding
  }

  return padding
}

module.exports.derToJose = (signature, alg) => {
  if (!Buffer.isBuffer(signature)) {
    throw new TypeError('ECDSA signature must be a Buffer')
  }

  if (!paramBytesForAlg[alg]) {
    throw new Error(`Unknown algorithm "${alg}"`)
  }

  const paramBytes = paramBytesForAlg[alg]

  // the DER encoded param should at most be the param size, plus a padding
  // zero, since due to being a signed integer
  const maxEncodedParamLength = paramBytes + 1

  const inputLength = signature.length

  let offset = 0
  if (signature[offset++] !== ENCODED_TAG_SEQ) {
    throw new Error('Could not find expected "seq"')
  }

  let seqLength = signature[offset++]
  if (seqLength === (MAX_OCTET | 1)) {
    seqLength = signature[offset++]
  }

  if (inputLength - offset < seqLength) {
    throw new Error(`"seq" specified length of ${seqLength}", only ${inputLength - offset}" remaining`)
  }

  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "r"')
  }

  const rLength = signature[offset++]

  if (inputLength - offset - 2 < rLength) {
    throw new Error(`"r" specified length of "${rLength}", only "${inputLength - offset - 2}" available`)
  }

  if (maxEncodedParamLength < rLength) {
    throw new Error(`"r" specified length of "${rLength}", max of "${maxEncodedParamLength}" is acceptable`)
  }

  const rOffset = offset
  offset += rLength

  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "s"')
  }

  const sLength = signature[offset++]

  if (inputLength - offset !== sLength) {
    throw new Error(`"s" specified length of "${sLength}", expected "${inputLength - offset}"`)
  }

  if (maxEncodedParamLength < sLength) {
    throw new Error(`"s" specified length of "${sLength}", max of "${maxEncodedParamLength}" is acceptable`)
  }

  const sOffset = offset
  offset += sLength

  if (offset !== inputLength) {
    throw new Error(`Expected to consume entire buffer, but "${inputLength - offset}" bytes remain`)
  }

  const rPadding = paramBytes - rLength

  const sPadding = paramBytes - sLength

  const dst = Buffer.allocUnsafe(rPadding + rLength + sPadding + sLength)

  for (offset = 0; offset < rPadding; ++offset) {
    dst[offset] = 0
  }
  signature.copy(dst, offset, rOffset + Math.max(-rPadding, 0), rOffset + rLength)

  offset = paramBytes

  for (const o = offset; offset < o + sPadding; ++offset) {
    dst[offset] = 0
  }
  signature.copy(dst, offset, sOffset + Math.max(-sPadding, 0), sOffset + sLength)

  return dst
}

module.exports.joseToDer = (signature, alg) => {
  if (!Buffer.isBuffer(signature)) {
    throw new TypeError('ECDSA signature must be a Buffer')
  }

  if (!paramBytesForAlg[alg]) {
    throw new TypeError(`Unknown algorithm "${alg}"`)
  }

  const paramBytes = paramBytesForAlg[alg]

  const signatureBytes = signature.length
  if (signatureBytes !== paramBytes * 2) {
    throw new Error(`"${alg}" signatures must be "${paramBytes * 2}" bytes, saw "${signatureBytes}"`)
  }

  const rPadding = countPadding(signature, 0, paramBytes)
  const sPadding = countPadding(signature, paramBytes, signature.length)
  const rLength = paramBytes - rPadding
  const sLength = paramBytes - sPadding

  const rsBytes = 1 + 1 + rLength + 1 + 1 + sLength

  const shortLength = rsBytes < MAX_OCTET

  const dst = Buffer.allocUnsafe((shortLength ? 2 : 3) + rsBytes)

  let offset = 0
  dst[offset++] = ENCODED_TAG_SEQ
  if (shortLength) {
    // Bit 8 has value "0"
    // bits 7-1 give the length.
    dst[offset++] = rsBytes
  } else {
    // Bit 8 of first octet has value "1"
    // bits 7-1 give the number of additional length octets.
    dst[offset++] = MAX_OCTET	| 1 // eslint-disable-line no-tabs
    // length, base 256
    dst[offset++] = rsBytes & 0xff
  }
  dst[offset++] = ENCODED_TAG_INT
  dst[offset++] = rLength
  if (rPadding < 0) {
    dst[offset++] = 0
    offset += signature.copy(dst, offset, 0, paramBytes)
  } else {
    offset += signature.copy(dst, offset, rPadding, paramBytes)
  }
  dst[offset++] = ENCODED_TAG_INT
  dst[offset++] = sLength
  if (sPadding < 0) {
    dst[offset++] = 0
    signature.copy(dst, offset, paramBytes)
  } else {
    signature.copy(dst, offset, paramBytes + sPadding)
  }

  return dst
}


/***/ }),

/***/ "fXeI":
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(n,r){"use strict";var e={};function __webpack_require__(r){if(e[r]){return e[r].exports}var t=e[r]={i:r,l:false,exports:{}};n[r].call(t.exports,t,t.exports,__webpack_require__);t.l=true;return t.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(903)}r(__webpack_require__);return startup()}({148:function(n){"use strict";var r=function(n){var r=n.ignoreProcessEnv?{}:process.env;var e=function(t){var o=t.match(/(.?\${?(?:[a-zA-Z0-9_]+)?}?)/g)||[];return o.reduce(function(t,o){var c=/(.?)\${?([a-zA-Z0-9_]+)?}?/g.exec(o);var s=c[1];var i,f;if(s==="\\"){f=c[0];i=f.replace("\\$","$")}else{var p=c[2];f=c[0].substring(s.length);i=r.hasOwnProperty(p)?r[p]:n.parsed[p]||"";i=e(i)}return t.replace(f,i)},t)};for(var t in n.parsed){var o=r.hasOwnProperty(t)?r[t]:n.parsed[t];n.parsed[t]=e(o)}for(var c in n.parsed){r[c]=n.parsed[c]}return n};n.exports=r},548:function(n,r,e){const t=e(747);const o=e(622);function log(n){console.log(`[dotenv][DEBUG] ${n}`)}const c="\n";const s=/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/;const i=/\\n/g;const f=/\n|\r|\r\n/;function parse(n,r){const e=Boolean(r&&r.debug);const t={};n.toString().split(f).forEach(function(n,r){const o=n.match(s);if(o!=null){const n=o[1];let r=o[2]||"";const e=r.length-1;const s=r[0]==='"'&&r[e]==='"';const f=r[0]==="'"&&r[e]==="'";if(f||s){r=r.substring(1,e);if(s){r=r.replace(i,c)}}else{r=r.trim()}t[n]=r}else if(e){log(`did not match key and value when parsing line ${r+1}: ${n}`)}});return t}function config(n){let r=o.resolve(process.cwd(),".env");let e="utf8";let c=false;if(n){if(n.path!=null){r=n.path}if(n.encoding!=null){e=n.encoding}if(n.debug!=null){c=true}}try{const n=parse(t.readFileSync(r,{encoding:e}),{debug:c});Object.keys(n).forEach(function(r){if(!Object.prototype.hasOwnProperty.call(process.env,r)){process.env[r]=n[r]}else if(c){log(`"${r}" is already defined in \`process.env\` and will not be overwritten`)}});return{parsed:n}}catch(n){return{error:n}}}n.exports.config=config;n.exports.parse=parse},622:function(n){n.exports=__webpack_require__("oyvS")},747:function(n){n.exports=__webpack_require__("mw/K")},903:function(n,r,e){"use strict";e.r(r);e.d(r,"processEnv",function(){return processEnv});e.d(r,"loadEnvConfig",function(){return loadEnvConfig});var t=e(747);var o=e.n(t);var c=e(622);var s=e.n(c);var i=e(548);var f=e.n(i);var p=e(148);var u=e.n(p);let a=undefined;let d=[];function processEnv(n,r,e=console){var t;if(process.env.__NEXT_PROCESSED_ENV||n.length===0){return process.env}process.env.__NEXT_PROCESSED_ENV="true";const o=Object.assign({},process.env);const s={};for(const f of n){try{let n={};n.parsed=i.parse(f.contents);n=u()(n);if(n.parsed){e.info(`Loaded env from ${c.join(r||"",f.path)}`)}for(const r of Object.keys(n.parsed||{})){if(typeof s[r]==="undefined"&&typeof o[r]==="undefined"){s[r]=(t=n.parsed)===null||t===void 0?void 0:t[r]}}}catch(n){e.error(`Failed to load env from ${c.join(r||"",f.path)}`,n)}}return Object.assign(process.env,s)}function loadEnvConfig(n,r,e=console){if(a)return{combinedEnv:a,loadedEnvFiles:d};const o="production"==="test";const s=o?"test":r?"development":"production";const i=[`.env.${s}.local`,s!=="test"&&`.env.local`,`.env.${s}`,".env"].filter(Boolean);for(const r of i){const o=c.join(n,r);try{const n=t.statSync(o);if(!n.isFile()){continue}const c=t.readFileSync(o,"utf8");d.push({path:r,contents:c})}catch(n){if(n.code!=="ENOENT"){e.error(`Failed to load env from ${r}`,n)}}}a=processEnv(d,n);return{combinedEnv:a,loadedEnvFiles:d}}}},function(n){"use strict";!function(){n.r=function(n){if(typeof Symbol!=="undefined"&&Symbol.toStringTag){Object.defineProperty(n,Symbol.toStringTag,{value:"Module"})}Object.defineProperty(n,"__esModule",{value:true})}}();!function(){n.n=function(r){var e=r&&r.__esModule?function getDefault(){return r["default"]}:function getModuleExports(){return r};n.d(e,"a",e);return e}}();!function(){var r=Object.prototype.hasOwnProperty;n.d=function(n,e,t){if(!r.call(n,e)){Object.defineProperty(n,e,{enumerable:true,get:t})}}}()});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "faWz":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const is = __webpack_require__("6mOv");

module.exports = body => is.nodeStream(body) && is.function(body.getBoundary);


/***/ }),

/***/ "fk1j":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (array1, array2, options = {}) {

    if (!array1 ||
        !array2) {

        return (options.first ? null : []);
    }

    const common = [];
    const hash = (Array.isArray(array1) ? new Set(array1) : array1);
    const found = new Set();
    for (const value of array2) {
        if (internals.has(hash, value) &&
            !found.has(value)) {

            if (options.first) {
                return value;
            }

            common.push(value);
            found.add(value);
        }
    }

    return (options.first ? null : common);
};


internals.has = function (ref, key) {

    if (typeof ref.has === 'function') {
        return ref.has(key);
    }

    return ref[key] !== undefined;
};


/***/ }),

/***/ "fkL1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
var _nodeFetch=_interopRequireWildcard(__webpack_require__("YUvC"));function _getRequireWildcardCache(){if(typeof WeakMap!=="function")return null;var cache=new WeakMap();_getRequireWildcardCache=function(){return cache;};return cache;}function _interopRequireWildcard(obj){if(obj&&obj.__esModule){return obj;}if(obj===null||typeof obj!=="object"&&typeof obj!=="function"){return{default:obj};}var cache=_getRequireWildcardCache();if(cache&&cache.has(obj)){return cache.get(obj);}var newObj={};var hasPropertyDescriptor=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(var key in obj){if(Object.prototype.hasOwnProperty.call(obj,key)){var desc=hasPropertyDescriptor?Object.getOwnPropertyDescriptor(obj,key):null;if(desc&&(desc.get||desc.set)){Object.defineProperty(newObj,key,desc);}else{newObj[key]=obj[key];}}}newObj.default=obj;if(cache){cache.set(obj,newObj);}return newObj;}// Polyfill fetch() in the Node.js environment
if(!global.fetch){global.fetch=_nodeFetch.default;global.Headers=_nodeFetch.Headers;global.Request=_nodeFetch.Request;global.Response=_nodeFetch.Response;}
//# sourceMappingURL=node-polyfill-fetch.js.map

/***/ }),

/***/ "g/15":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;
exports.execOnce = execOnce;
exports.getLocationOrigin = getLocationOrigin;
exports.getURL = getURL;
exports.getDisplayName = getDisplayName;
exports.isResSent = isResSent;
exports.loadGetInitialProps = loadGetInitialProps;
exports.formatWithValidation = formatWithValidation;
exports.ST = exports.SP = exports.urlObjectKeys = void 0;

var _formatUrl = __webpack_require__("6D7l");
/**
* Utils
*/


function execOnce(fn) {
  let used = false;
  let result;
  return (...args) => {
    if (!used) {
      used = true;
      result = fn(...args);
    }

    return result;
  };
}

function getLocationOrigin() {
  const {
    protocol,
    hostname,
    port
  } = window.location;
  return `${protocol}//${hostname}${port ? ':' + port : ''}`;
}

function getURL() {
  const {
    href
  } = window.location;
  const origin = getLocationOrigin();
  return href.substring(origin.length);
}

function getDisplayName(Component) {
  return typeof Component === 'string' ? Component : Component.displayName || Component.name || 'Unknown';
}

function isResSent(res) {
  return res.finished || res.headersSent;
}

async function loadGetInitialProps(App, ctx) {
  if (false) { var _App$prototype; } // when called from _app `ctx` is nested in `ctx`


  const res = ctx.res || ctx.ctx && ctx.ctx.res;

  if (!App.getInitialProps) {
    if (ctx.ctx && ctx.Component) {
      // @ts-ignore pageProps default
      return {
        pageProps: await loadGetInitialProps(ctx.Component, ctx.ctx)
      };
    }

    return {};
  }

  const props = await App.getInitialProps(ctx);

  if (res && isResSent(res)) {
    return props;
  }

  if (!props) {
    const message = `"${getDisplayName(App)}.getInitialProps()" should resolve to an object. But found "${props}" instead.`;
    throw new Error(message);
  }

  if (false) {}

  return props;
}

const urlObjectKeys = ['auth', 'hash', 'host', 'hostname', 'href', 'path', 'pathname', 'port', 'protocol', 'query', 'search', 'slashes'];
exports.urlObjectKeys = urlObjectKeys;

function formatWithValidation(url) {
  if (false) {}

  return (0, _formatUrl.formatUrl)(url);
}

const SP = typeof performance !== 'undefined';
exports.SP = SP;
const ST = SP && typeof performance.mark === 'function' && typeof performance.measure === 'function';
exports.ST = ST;

/***/ }),

/***/ "g6Ax":
/***/ (function(module, exports) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,r){"use strict";var t={};function __webpack_require__(r){if(t[r]){return t[r].exports}var a=t[r]={i:r,l:false,exports:{}};e[r].call(a.exports,a,a.exports,__webpack_require__);a.l=true;return a.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(982)}return startup()}({982:function(e,r){"use strict";var t=/; *([!#$%&'*+.^_`|~0-9A-Za-z-]+) *= *("(?:[\u000b\u0020\u0021\u0023-\u005b\u005d-\u007e\u0080-\u00ff]|\\[\u000b\u0020-\u00ff])*"|[!#$%&'*+.^_`|~0-9A-Za-z-]+) */g;var a=/^[\u000b\u0020-\u007e\u0080-\u00ff]+$/;var n=/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;var i=/\\([\u000b\u0020-\u00ff])/g;var o=/([\\"])/g;var u=/^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;r.format=format;r.parse=parse;function format(e){if(!e||typeof e!=="object"){throw new TypeError("argument obj is required")}var r=e.parameters;var t=e.type;if(!t||!u.test(t)){throw new TypeError("invalid type")}var a=t;if(r&&typeof r==="object"){var i;var o=Object.keys(r).sort();for(var p=0;p<o.length;p++){i=o[p];if(!n.test(i)){throw new TypeError("invalid parameter name")}a+="; "+i+"="+qstring(r[i])}}return a}function parse(e){if(!e){throw new TypeError("argument string is required")}var r=typeof e==="object"?getcontenttype(e):e;if(typeof r!=="string"){throw new TypeError("argument string is required to be a string")}var a=r.indexOf(";");var n=a!==-1?r.substr(0,a).trim():r.trim();if(!u.test(n)){throw new TypeError("invalid media type")}var o=new ContentType(n.toLowerCase());if(a!==-1){var p;var s;var f;t.lastIndex=a;while(s=t.exec(r)){if(s.index!==a){throw new TypeError("invalid parameter format")}a+=s[0].length;p=s[1].toLowerCase();f=s[2];if(f[0]==='"'){f=f.substr(1,f.length-2).replace(i,"$1")}o.parameters[p]=f}if(a!==r.length){throw new TypeError("invalid parameter format")}}return o}function getcontenttype(e){var r;if(typeof e.getHeader==="function"){r=e.getHeader("content-type")}else if(typeof e.headers==="object"){r=e.headers&&e.headers["content-type"]}if(typeof r!=="string"){throw new TypeError("content-type header is missing from object")}return r}function qstring(e){var r=String(e);if(n.test(r)){return r}if(r.length>0&&!a.test(r)){throw new TypeError("invalid parameter value")}return'"'+r.replace(o,"\\$1")+'"'}function ContentType(e){this.parameters=Object.create(null);this.type=e}}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "gJmk":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function () { };


/***/ }),

/***/ "gK4g":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {constants: BufferConstants} = __webpack_require__("NkYg");
const pump = __webpack_require__("b1mx");
const bufferStream = __webpack_require__("iGjV");

class MaxBufferError extends Error {
	constructor() {
		super('maxBuffer exceeded');
		this.name = 'MaxBufferError';
	}
}

async function getStream(inputStream, options) {
	if (!inputStream) {
		return Promise.reject(new Error('Expected a stream'));
	}

	options = {
		maxBuffer: Infinity,
		...options
	};

	const {maxBuffer} = options;

	let stream;
	await new Promise((resolve, reject) => {
		const rejectPromise = error => {
			// Don't retrieve an oversized buffer.
			if (error && stream.getBufferedLength() <= BufferConstants.MAX_LENGTH) {
				error.bufferedData = stream.getBufferedValue();
			}

			reject(error);
		};

		stream = pump(inputStream, bufferStream(options), error => {
			if (error) {
				rejectPromise(error);
				return;
			}

			resolve();
		});

		stream.on('data', () => {
			if (stream.getBufferedLength() > maxBuffer) {
				rejectPromise(new MaxBufferError());
			}
		});
	});

	return stream.getBufferedValue();
}

module.exports = getStream;
// TODO: Remove this for the next major release
module.exports.default = getStream;
module.exports.buffer = (stream, options) => getStream(stream, {...options, encoding: 'buffer'});
module.exports.array = (stream, options) => getStream(stream, {...options, array: true});
module.exports.MaxBufferError = MaxBufferError;


/***/ }),

/***/ "gKi1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const cookie_1 = __webpack_require__("iVi/");
/**
 * Parses the cookies from an API Route or from Pages and returns a key/value object containing all the cookies.
 * @param req Incoming HTTP request.
 */
function parseCookies(req) {
    const { cookies } = req;
    // For API Routes we don't need to parse the cookies.
    if (cookies) {
        return cookies;
    }
    // For pages we still need to parse the cookies.
    const cookie = req && req.headers && req.headers.cookie;
    return cookie_1.parse(cookie || '');
}
exports.parseCookies = parseCookies;
/**
 * Based on the environment and the request we know if a secure cookie can be set.
 */
function isSecureEnvironment(req) {
    if (!req || !req.headers || !req.headers.host) {
        throw new Error('The "host" request header is not available');
    }
    if (false) {}
    const host = (req.headers.host.indexOf(':') > -1 && req.headers.host.split(':')[0]) || req.headers.host;
    if (['localhost', '127.0.0.1'].indexOf(host) > -1) {
        return false;
    }
    return true;
}
/**
 * Serialize a cookie to a string.
 * @param cookie The cookie to serialize
 * @param secure Create a secure cookie.
 */
function serializeCookie(cookie, secure) {
    return cookie_1.serialize(cookie.name, cookie.value, {
        maxAge: cookie.maxAge,
        expires: new Date(Date.now() + cookie.maxAge * 1000),
        httpOnly: true,
        secure,
        path: cookie.path,
        domain: cookie.domain,
        sameSite: cookie.sameSite
    });
}
/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 * @returns {void}
 */
function setCookies(req, res, cookies) {
    const strCookies = cookies.map((c) => serializeCookie(c, isSecureEnvironment(req)));
    const previousCookies = res.getHeader('Set-Cookie');
    if (previousCookies) {
        if (previousCookies instanceof Array) {
            Array.prototype.push.apply(strCookies, previousCookies);
        }
        else if (typeof previousCookies === 'string') {
            strCookies.push(previousCookies);
        }
    }
    res.setHeader('Set-Cookie', strCookies);
}
exports.setCookies = setCookies;
/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 * @returns {void}
 */
function setCookie(req, res, cookie) {
    setCookies(req, res, [cookie]);
}
exports.setCookie = setCookie;
//# sourceMappingURL=cookies.js.map

/***/ }),

/***/ "gXwc":
/***/ (function(module, exports, __webpack_require__) {

/* global BigInt */

const { EOL } = __webpack_require__("jle/")

const errors = __webpack_require__("yt7c")

const { keyObjectSupported } = __webpack_require__("pDDt")
const { createPublicKey } = __webpack_require__("1ALl")
const base64url = __webpack_require__("Xab3")
const asn1 = __webpack_require__("u88T")
const computePrimes = __webpack_require__("eHfw")
const { OKP_CURVES, EC_CURVES } = __webpack_require__("N+nT")

const formatPem = (base64pem, descriptor) => `-----BEGIN ${descriptor} KEY-----${EOL}${(base64pem.match(/.{1,64}/g) || []).join(EOL)}${EOL}-----END ${descriptor} KEY-----`

const okpToJWK = {
  private (crv, keyObject) {
    const der = keyObject.export({ type: 'pkcs8', format: 'der' })
    const OneAsymmetricKey = asn1.get('OneAsymmetricKey')
    const { privateKey: { privateKey: d } } = OneAsymmetricKey.decode(der)

    return {
      ...okpToJWK.public(crv, createPublicKey(keyObject)),
      d: base64url.encodeBuffer(d)
    }
  },
  public (crv, keyObject) {
    const der = keyObject.export({ type: 'spki', format: 'der' })

    const PublicKeyInfo = asn1.get('PublicKeyInfo')

    const { publicKey: { data: x } } = PublicKeyInfo.decode(der)

    return {
      kty: 'OKP',
      crv,
      x: base64url.encodeBuffer(x)
    }
  }
}

const keyObjectToJWK = {
  rsa: {
    private (keyObject) {
      const der = keyObject.export({ type: 'pkcs8', format: 'der' })

      const PrivateKeyInfo = asn1.get('PrivateKeyInfo')
      const RSAPrivateKey = asn1.get('RSAPrivateKey')

      const { privateKey } = PrivateKeyInfo.decode(der)
      const { version, n, e, d, p, q, dp, dq, qi } = RSAPrivateKey.decode(privateKey)

      if (version !== 'two-prime') {
        throw new errors.JOSENotSupported('Private RSA keys with more than two primes are not supported')
      }

      return {
        kty: 'RSA',
        n: base64url.encodeBigInt(n),
        e: base64url.encodeBigInt(e),
        d: base64url.encodeBigInt(d),
        p: base64url.encodeBigInt(p),
        q: base64url.encodeBigInt(q),
        dp: base64url.encodeBigInt(dp),
        dq: base64url.encodeBigInt(dq),
        qi: base64url.encodeBigInt(qi)
      }
    },
    public (keyObject) {
      const der = keyObject.export({ type: 'spki', format: 'der' })

      const PublicKeyInfo = asn1.get('PublicKeyInfo')
      const RSAPublicKey = asn1.get('RSAPublicKey')

      const { publicKey: { data: publicKey } } = PublicKeyInfo.decode(der)
      const { n, e } = RSAPublicKey.decode(publicKey)

      return {
        kty: 'RSA',
        n: base64url.encodeBigInt(n),
        e: base64url.encodeBigInt(e)
      }
    }
  },
  ec: {
    private (keyObject) {
      const der = keyObject.export({ type: 'pkcs8', format: 'der' })

      const PrivateKeyInfo = asn1.get('PrivateKeyInfo')
      const ECPrivateKey = asn1.get('ECPrivateKey')

      const { privateKey, algorithm: { parameters: { value: crv } } } = PrivateKeyInfo.decode(der)
      const { privateKey: d, publicKey } = ECPrivateKey.decode(privateKey)

      if (typeof publicKey === 'undefined') {
        if (keyObjectSupported) {
          return {
            ...keyObjectToJWK.ec.public(createPublicKey(keyObject)),
            d: base64url.encodeBuffer(d)
          }
        }

        throw new errors.JOSENotSupported('Private EC keys without the public key embedded are not supported in your Node.js runtime version')
      }

      const x = publicKey.data.slice(1, ((publicKey.data.length - 1) / 2) + 1)
      const y = publicKey.data.slice(((publicKey.data.length - 1) / 2) + 1)

      return {
        kty: 'EC',
        crv,
        d: base64url.encodeBuffer(d),
        x: base64url.encodeBuffer(x),
        y: base64url.encodeBuffer(y)
      }
    },
    public (keyObject) {
      const der = keyObject.export({ type: 'spki', format: 'der' })

      const PublicKeyInfo = asn1.get('PublicKeyInfo')

      const { publicKey: { data: publicKey }, algorithm: { parameters: { value: crv } } } = PublicKeyInfo.decode(der)

      const x = publicKey.slice(1, ((publicKey.length - 1) / 2) + 1)
      const y = publicKey.slice(((publicKey.length - 1) / 2) + 1)

      return {
        kty: 'EC',
        crv,
        x: base64url.encodeBuffer(x),
        y: base64url.encodeBuffer(y)
      }
    }
  },
  ed25519: {
    private (keyObject) {
      return okpToJWK.private('Ed25519', keyObject)
    },
    public (keyObject) {
      return okpToJWK.public('Ed25519', keyObject)
    }
  },
  ed448: {
    private (keyObject) {
      return okpToJWK.private('Ed448', keyObject)
    },
    public (keyObject) {
      return okpToJWK.public('Ed448', keyObject)
    }
  },
  x25519: {
    private (keyObject) {
      return okpToJWK.private('X25519', keyObject)
    },
    public (keyObject) {
      return okpToJWK.public('X25519', keyObject)
    }
  },
  x448: {
    private (keyObject) {
      return okpToJWK.private('X448', keyObject)
    },
    public (keyObject) {
      return okpToJWK.public('X448', keyObject)
    }
  }
}

module.exports.keyObjectToJWK = (keyObject) => {
  if (keyObject.type === 'private') {
    return keyObjectToJWK[keyObject.asymmetricKeyType].private(keyObject)
  }

  return keyObjectToJWK[keyObject.asymmetricKeyType].public(keyObject)
}

const concatEcPublicKey = (x, y) => ({
  unused: 0,
  data: Buffer.concat([
    Buffer.alloc(1, 4),
    base64url.decodeToBuffer(x),
    base64url.decodeToBuffer(y)
  ])
})

const jwkToPem = {
  RSA: {
    private (jwk, { calculateMissingRSAPrimes }) {
      const RSAPrivateKey = asn1.get('RSAPrivateKey')

      if ('oth' in jwk) {
        throw new errors.JOSENotSupported('Private RSA keys with more than two primes are not supported')
      }

      if (jwk.p || jwk.q || jwk.dp || jwk.dq || jwk.qi) {
        if (!(jwk.p && jwk.q && jwk.dp && jwk.dq && jwk.qi)) {
          throw new errors.JWKInvalid('all other private key parameters must be present when any one of them is present')
        }
      } else if (calculateMissingRSAPrimes) {
        jwk = computePrimes(jwk)
      } else if (!calculateMissingRSAPrimes) {
        throw new errors.JOSENotSupported('importing private RSA keys without all other private key parameters is not enabled, see documentation and its advisory on how and when its ok to enable it')
      }

      return RSAPrivateKey.encode({
        version: 0,
        n: BigInt(`0x${base64url.decodeToBuffer(jwk.n).toString('hex')}`),
        e: BigInt(`0x${base64url.decodeToBuffer(jwk.e).toString('hex')}`),
        d: BigInt(`0x${base64url.decodeToBuffer(jwk.d).toString('hex')}`),
        p: BigInt(`0x${base64url.decodeToBuffer(jwk.p).toString('hex')}`),
        q: BigInt(`0x${base64url.decodeToBuffer(jwk.q).toString('hex')}`),
        dp: BigInt(`0x${base64url.decodeToBuffer(jwk.dp).toString('hex')}`),
        dq: BigInt(`0x${base64url.decodeToBuffer(jwk.dq).toString('hex')}`),
        qi: BigInt(`0x${base64url.decodeToBuffer(jwk.qi).toString('hex')}`)
      }, 'pem', { label: 'RSA PRIVATE KEY' })
    },
    public (jwk) {
      const RSAPublicKey = asn1.get('RSAPublicKey')

      return RSAPublicKey.encode({
        version: 0,
        n: BigInt(`0x${base64url.decodeToBuffer(jwk.n).toString('hex')}`),
        e: BigInt(`0x${base64url.decodeToBuffer(jwk.e).toString('hex')}`)
      }, 'pem', { label: 'RSA PUBLIC KEY' })
    }
  },
  EC: {
    private (jwk) {
      const ECPrivateKey = asn1.get('ECPrivateKey')

      return ECPrivateKey.encode({
        version: 1,
        privateKey: base64url.decodeToBuffer(jwk.d),
        parameters: { type: 'namedCurve', value: jwk.crv },
        publicKey: concatEcPublicKey(jwk.x, jwk.y)
      }, 'pem', { label: 'EC PRIVATE KEY' })
    },
    public (jwk) {
      const PublicKeyInfo = asn1.get('PublicKeyInfo')

      return PublicKeyInfo.encode({
        algorithm: {
          algorithm: 'ecPublicKey',
          parameters: { type: 'namedCurve', value: jwk.crv }
        },
        publicKey: concatEcPublicKey(jwk.x, jwk.y)
      }, 'pem', { label: 'PUBLIC KEY' })
    }
  },
  OKP: {
    private (jwk) {
      const OneAsymmetricKey = asn1.get('OneAsymmetricKey')

      const b64 = OneAsymmetricKey.encode({
        version: 0,
        privateKey: { privateKey: base64url.decodeToBuffer(jwk.d) },
        algorithm: { algorithm: jwk.crv }
      }, 'der')

      // TODO: WHYYY? https://github.com/indutny/asn1.js/issues/110
      b64.write('04', 12, 1, 'hex')

      return formatPem(b64.toString('base64'), 'PRIVATE')
    },
    public (jwk) {
      const PublicKeyInfo = asn1.get('PublicKeyInfo')

      return PublicKeyInfo.encode({
        algorithm: { algorithm: jwk.crv },
        publicKey: {
          unused: 0,
          data: base64url.decodeToBuffer(jwk.x)
        }
      }, 'pem', { label: 'PUBLIC KEY' })
    }
  }
}

module.exports.jwkToPem = (jwk, { calculateMissingRSAPrimes = false } = {}) => {
  switch (jwk.kty) {
    case 'EC':
      if (!EC_CURVES.has(jwk.crv)) {
        throw new errors.JOSENotSupported(`unsupported EC key curve: ${jwk.crv}`)
      }
      break
    case 'OKP':
      if (!OKP_CURVES.has(jwk.crv)) {
        throw new errors.JOSENotSupported(`unsupported OKP key curve: ${jwk.crv}`)
      }
      break
    case 'RSA':
      break
    default:
      throw new errors.JOSENotSupported(`unsupported key type: ${jwk.kty}`)
  }

  if (jwk.d) {
    return jwkToPem[jwk.kty].private(jwk, { calculateMissingRSAPrimes })
  }

  return jwkToPem[jwk.kty].public(jwk)
}


/***/ }),

/***/ "gt9x":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class Session {
    constructor(user, createdAt) {
        this.user = user;
        if (createdAt) {
            this.createdAt = createdAt;
        }
        else {
            this.createdAt = Date.now();
        }
    }
}
exports.default = Session;
//# sourceMappingURL=session.js.map

/***/ }),

/***/ "h+i2":
/***/ (function(module, exports, __webpack_require__) {

module.exports = {
  der: __webpack_require__("1Gj5")
}


/***/ }),

/***/ "hS4m":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;
exports.parseRelativeUrl = parseRelativeUrl;

var _utils = __webpack_require__("g/15");

var _querystring = __webpack_require__("3WeD");

const DUMMY_BASE = new URL(true ? 'http://n' : undefined);
/**
* Parses path-relative urls (e.g. `/hello/world?foo=bar`). If url isn't path-relative
* (e.g. `./hello`) then at least base must be.
* Absolute urls are rejected with one exception, in the browser, absolute urls that are on
* the current origin will be parsed as relative
*/

function parseRelativeUrl(url, base) {
  const resolvedBase = base ? new URL(base, DUMMY_BASE) : DUMMY_BASE;
  const {
    pathname,
    searchParams,
    search,
    hash,
    href,
    origin,
    protocol
  } = new URL(url, resolvedBase);

  if (origin !== DUMMY_BASE.origin || protocol !== 'http:' && protocol !== 'https:') {
    throw new Error('invariant: invalid relative URL');
  }

  return {
    pathname,
    query: (0, _querystring.searchParamsToUrlQuery)(searchParams),
    search,
    hash,
    href: href.slice(DUMMY_BASE.origin.length)
  };
}

/***/ }),

/***/ "hX4a":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.Bench = class {

    constructor() {

        this.ts = 0;
        this.reset();
    }

    reset() {

        this.ts = internals.Bench.now();
    }

    elapsed() {

        return internals.Bench.now() - this.ts;
    }

    static now() {

        const ts = process.hrtime();
        return (ts[0] * 1e3) + (ts[1] / 1e6);
    }
};


/***/ }),

/***/ "hk9D":
/***/ (function(module, exports, __webpack_require__) {

const { publicEncrypt, privateDecrypt, constants } = __webpack_require__("PJMN")

const { oaepHashSupported } = __webpack_require__("pDDt")
const { KEYOBJECT } = __webpack_require__("ehsS")
const { asInput } = __webpack_require__("1ALl")

const resolvePadding = (alg) => {
  switch (alg) {
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      return constants.RSA_PKCS1_OAEP_PADDING
    case 'RSA1_5':
      return constants.RSA_PKCS1_PADDING
  }
}

const resolveOaepHash = (alg) => {
  switch (alg) {
    case 'RSA-OAEP':
      return 'sha1'
    case 'RSA-OAEP-256':
      return 'sha256'
    case 'RSA-OAEP-384':
      return 'sha384'
    case 'RSA-OAEP-512':
      return 'sha512'
    default:
      return undefined
  }
}

const wrapKey = (padding, oaepHash, { [KEYOBJECT]: keyObject }, payload) => {
  const key = asInput(keyObject, true)
  return { wrapped: publicEncrypt({ key, oaepHash, padding }, payload) }
}

const unwrapKey = (padding, oaepHash, { [KEYOBJECT]: keyObject }, payload) => {
  const key = asInput(keyObject, false)
  return privateDecrypt({ key, oaepHash, padding }, payload)
}

const LENGTHS = {
  RSA1_5: 0,
  'RSA-OAEP': 592,
  'RSA-OAEP-256': 784,
  'RSA-OAEP-384': 1040,
  'RSA-OAEP-512': 1296
}

module.exports = (JWA, JWK) => {
  const algs = ['RSA-OAEP', 'RSA1_5']

  if (oaepHashSupported) {
    algs.splice(1, 0, 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512')
  }

  algs.forEach((jwaAlg) => {
    const padding = resolvePadding(jwaAlg)
    const oaepHash = resolveOaepHash(jwaAlg)
    JWA.keyManagementEncrypt.set(jwaAlg, wrapKey.bind(undefined, padding, oaepHash))
    JWA.keyManagementDecrypt.set(jwaAlg, unwrapKey.bind(undefined, padding, oaepHash))
    JWK.RSA.wrapKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.length >= LENGTHS[jwaAlg]
    JWK.RSA.unwrapKey[jwaAlg] = key => key.private && (key.use === 'enc' || key.use === undefined) && key.length >= LENGTHS[jwaAlg]
  })
}


/***/ }),

/***/ "hnhG":
/***/ (function(module, exports, __webpack_require__) {

const {
  createSign,
  createVerify,
  constants
} = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const resolveNodeAlg = __webpack_require__("uGJc")
const { asInput } = __webpack_require__("1ALl")

const sign = (nodeAlg, { [KEYOBJECT]: keyObject }, payload) => {
  const key = asInput(keyObject, false)
  return createSign(nodeAlg).update(payload).sign({
    key,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST
  })
}

const verify = (nodeAlg, { [KEYOBJECT]: keyObject }, payload, signature) => {
  const key = asInput(keyObject, true)
  return createVerify(nodeAlg).update(payload).verify({
    key,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST
  }, signature)
}

const LENGTHS = {
  PS256: 528,
  PS384: 784,
  PS512: 1040
}

module.exports = (JWA, JWK) => {
  ['PS256', 'PS384', 'PS512'].forEach((jwaAlg) => {
    const nodeAlg = resolveNodeAlg(jwaAlg)
    JWA.sign.set(jwaAlg, sign.bind(undefined, nodeAlg))
    JWA.verify.set(jwaAlg, verify.bind(undefined, nodeAlg))
    JWK.RSA.sign[jwaAlg] = key => key.private && JWK.RSA.verify[jwaAlg](key)
    JWK.RSA.verify[jwaAlg] = key => (key.use === 'sig' || key.use === undefined) && key.length >= LENGTHS[jwaAlg]
  })
}


/***/ }),

/***/ "htIY":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const AggregateError = __webpack_require__("xh2E");
const PCancelable = __webpack_require__("dr85");

class FilterError extends Error { }

const pSome = (iterable, options) => new PCancelable((resolve, reject, onCancel) => {
	const {
		count,
		filter = () => true
	} = options;

	if (!Number.isFinite(count)) {
		reject(new TypeError(`Expected a finite number, got ${typeof options.count}`));
		return;
	}

	const values = [];
	const errors = [];
	let elementCount = 0;
	let isSettled = false;

	const completed = new Set();
	const maybeSettle = () => {
		if (values.length === count) {
			resolve(values);
			isSettled = true;
		}

		if (elementCount - errors.length < count) {
			reject(new AggregateError(errors));
			isSettled = true;
		}

		return isSettled;
	};

	const cancelPending = () => {
		for (const promise of iterable) {
			if (!completed.has(promise) && typeof promise.cancel === 'function') {
				promise.cancel();
			}
		}
	};

	onCancel(cancelPending);

	for (const element of iterable) {
		elementCount++;

		(async () => {
			try {
				const value = await element;

				if (isSettled) {
					return;
				}

				if (!filter(value)) {
					throw new FilterError('Value does not satisfy filter');
				}

				values.push(value);
			} catch (error) {
				errors.push(error);
			} finally {
				completed.add(element);

				if (!isSettled && maybeSettle()) {
					cancelPending();
				}
			}
		})();
	}

	if (count > elementCount) {
		reject(new RangeError(`Expected input to contain at least ${options.count} items, but contains ${elementCount} items`));
		cancelPending();
	}
});

module.exports = pSome;
module.exports.AggregateError = AggregateError;
module.exports.FilterError = FilterError;


/***/ }),

/***/ "iAgo":
/***/ (function(module, exports, __webpack_require__) {

const { createHash, randomBytes } = __webpack_require__("PJMN");

const { encode: base64url } = __webpack_require__("+00W");

const random = (bytes = 32) => base64url(randomBytes(bytes));

module.exports = {
  random,
  state: random,
  nonce: random,
  codeVerifier: random,
  codeChallenge: (codeVerifier) => base64url(createHash('sha256').update(codeVerifier).digest()),
};


/***/ }),

/***/ "iGjV":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {PassThrough: PassThroughStream} = __webpack_require__("msIP");

module.exports = options => {
	options = {...options};

	const {array} = options;
	let {encoding} = options;
	const isBuffer = encoding === 'buffer';
	let objectMode = false;

	if (array) {
		objectMode = !(encoding || isBuffer);
	} else {
		encoding = encoding || 'utf8';
	}

	if (isBuffer) {
		encoding = null;
	}

	const stream = new PassThroughStream({objectMode});

	if (encoding) {
		stream.setEncoding(encoding);
	}

	let length = 0;
	const chunks = [];

	stream.on('data', chunk => {
		chunks.push(chunk);

		if (objectMode) {
			length = chunks.length;
		} else {
			length += chunk.length;
		}
	});

	stream.getBufferedValue = () => {
		if (array) {
			return chunks;
		}

		return isBuffer ? Buffer.concat(chunks, length) : chunks.join('');
	};

	stream.getBufferedLength = () => length;

	return stream;
};


/***/ }),

/***/ "iVi/":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/*!
 * cookie
 * Copyright(c) 2012-2014 Roman Shtylman
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */



/**
 * Module exports.
 * @public
 */

exports.parse = parse;
exports.serialize = serialize;

/**
 * Module variables.
 * @private
 */

var decode = decodeURIComponent;
var encode = encodeURIComponent;
var pairSplitRegExp = /; */;

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

/**
 * Parse a cookie header.
 *
 * Parse the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 *
 * @param {string} str
 * @param {object} [options]
 * @return {object}
 * @public
 */

function parse(str, options) {
  if (typeof str !== 'string') {
    throw new TypeError('argument str must be a string');
  }

  var obj = {}
  var opt = options || {};
  var pairs = str.split(pairSplitRegExp);
  var dec = opt.decode || decode;

  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i];
    var eq_idx = pair.indexOf('=');

    // skip things that don't look like key=value
    if (eq_idx < 0) {
      continue;
    }

    var key = pair.substr(0, eq_idx).trim()
    var val = pair.substr(++eq_idx, pair.length).trim();

    // quoted values
    if ('"' == val[0]) {
      val = val.slice(1, -1);
    }

    // only assign once
    if (undefined == obj[key]) {
      obj[key] = tryDecode(val, dec);
    }
  }

  return obj;
}

/**
 * Serialize data into a cookie header.
 *
 * Serialize the a name value pair into a cookie string suitable for
 * http headers. An optional options object specified cookie parameters.
 *
 * serialize('foo', 'bar', { httpOnly: true })
 *   => "foo=bar; httpOnly"
 *
 * @param {string} name
 * @param {string} val
 * @param {object} [options]
 * @return {string}
 * @public
 */

function serialize(name, val, options) {
  var opt = options || {};
  var enc = opt.encode || encode;

  if (typeof enc !== 'function') {
    throw new TypeError('option encode is invalid');
  }

  if (!fieldContentRegExp.test(name)) {
    throw new TypeError('argument name is invalid');
  }

  var value = enc(val);

  if (value && !fieldContentRegExp.test(value)) {
    throw new TypeError('argument val is invalid');
  }

  var str = name + '=' + value;

  if (null != opt.maxAge) {
    var maxAge = opt.maxAge - 0;

    if (isNaN(maxAge) || !isFinite(maxAge)) {
      throw new TypeError('option maxAge is invalid')
    }

    str += '; Max-Age=' + Math.floor(maxAge);
  }

  if (opt.domain) {
    if (!fieldContentRegExp.test(opt.domain)) {
      throw new TypeError('option domain is invalid');
    }

    str += '; Domain=' + opt.domain;
  }

  if (opt.path) {
    if (!fieldContentRegExp.test(opt.path)) {
      throw new TypeError('option path is invalid');
    }

    str += '; Path=' + opt.path;
  }

  if (opt.expires) {
    if (typeof opt.expires.toUTCString !== 'function') {
      throw new TypeError('option expires is invalid');
    }

    str += '; Expires=' + opt.expires.toUTCString();
  }

  if (opt.httpOnly) {
    str += '; HttpOnly';
  }

  if (opt.secure) {
    str += '; Secure';
  }

  if (opt.sameSite) {
    var sameSite = typeof opt.sameSite === 'string'
      ? opt.sameSite.toLowerCase() : opt.sameSite;

    switch (sameSite) {
      case true:
        str += '; SameSite=Strict';
        break;
      case 'lax':
        str += '; SameSite=Lax';
        break;
      case 'strict':
        str += '; SameSite=Strict';
        break;
      case 'none':
        str += '; SameSite=None';
        break;
      default:
        throw new TypeError('option sameSite is invalid');
    }
  }

  return str;
}

/**
 * Try decoding a string using a decoding function.
 *
 * @param {string} str
 * @param {function} decode
 * @private
 */

function tryDecode(str, decode) {
  try {
    return decode(str);
  } catch (e) {
    return str;
  }
}


/***/ }),

/***/ "ieHi":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Crypto = __webpack_require__("PJMN");

const Boom = __webpack_require__("WTaE");


const internals = {};


// Generate a cryptographically strong pseudo-random data

exports.randomString = function (size) {

    const buffer = exports.randomBits((size + 1) * 6);
    const string = buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return string.slice(0, size);
};


// Return a random string of digits

exports.randomDigits = function (size) {

    const digits = [];

    let buffer = internals.random(size * 2);            // Provision twice the amount of bytes needed to increase chance of single pass
    let pos = 0;

    while (digits.length < size) {
        if (pos >= buffer.length) {
            buffer = internals.random(size * 2);
            pos = 0;
        }

        if (buffer[pos] < 250) {
            digits.push(buffer[pos] % 10);
        }

        ++pos;
    }

    return digits.join('');
};


// Generate a buffer of random bits

exports.randomBits = function (bits) {

    if (!bits ||
        bits < 0) {

        throw Boom.internal('Invalid random bits count');
    }

    const bytes = Math.ceil(bits / 8);
    return internals.random(bytes);
};


exports.fixedTimeComparison = function (a, b) {

    try {
        return Crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }
    catch (err) {
        return false;
    }
};


internals.random = function (bytes) {

    try {
        return Crypto.randomBytes(bytes);
    }
    catch (err) {
        throw Boom.internal('Failed generating random bits: ' + err.message);
    }
};


/***/ }),

/***/ "ijcl":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


class CancelError extends Error {
	constructor(reason) {
		super(reason || 'Promise was canceled');
		this.name = 'CancelError';
	}

	get isCanceled() {
		return true;
	}
}

class PCancelable {
	static fn(userFn) {
		return (...args) => {
			return new PCancelable((resolve, reject, onCancel) => {
				args.push(onCancel);
				userFn(...args).then(resolve, reject);
			});
		};
	}

	constructor(executor) {
		this._cancelHandlers = [];
		this._isPending = true;
		this._isCanceled = false;
		this._rejectOnCancel = true;

		this._promise = new Promise((resolve, reject) => {
			this._reject = reject;

			const onResolve = value => {
				this._isPending = false;
				resolve(value);
			};

			const onReject = error => {
				this._isPending = false;
				reject(error);
			};

			const onCancel = handler => {
				this._cancelHandlers.push(handler);
			};

			Object.defineProperties(onCancel, {
				shouldReject: {
					get: () => this._rejectOnCancel,
					set: bool => {
						this._rejectOnCancel = bool;
					}
				}
			});

			return executor(onResolve, onReject, onCancel);
		});
	}

	then(onFulfilled, onRejected) {
		return this._promise.then(onFulfilled, onRejected);
	}

	catch(onRejected) {
		return this._promise.catch(onRejected);
	}

	finally(onFinally) {
		return this._promise.finally(onFinally);
	}

	cancel(reason) {
		if (!this._isPending || this._isCanceled) {
			return;
		}

		if (this._cancelHandlers.length > 0) {
			try {
				for (const handler of this._cancelHandlers) {
					handler();
				}
			} catch (error) {
				this._reject(error);
			}
		}

		this._isCanceled = true;
		if (this._rejectOnCancel) {
			this._reject(new CancelError(reason));
		}
	}

	get isCanceled() {
		return this._isCanceled;
	}
}

Object.setPrototypeOf(PCancelable.prototype, Promise.prototype);

module.exports = PCancelable;
module.exports.default = PCancelable;

module.exports.CancelError = CancelError;


/***/ }),

/***/ "j0Yl":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const deferToConnect = __webpack_require__("xZ+y");

module.exports = request => {
	const timings = {
		start: Date.now(),
		socket: null,
		lookup: null,
		connect: null,
		upload: null,
		response: null,
		end: null,
		error: null,
		phases: {
			wait: null,
			dns: null,
			tcp: null,
			request: null,
			firstByte: null,
			download: null,
			total: null
		}
	};

	const handleError = origin => {
		const emit = origin.emit.bind(origin);
		origin.emit = (event, ...args) => {
			// Catches the `error` event
			if (event === 'error') {
				timings.error = Date.now();
				timings.phases.total = timings.error - timings.start;

				origin.emit = emit;
			}

			// Saves the original behavior
			return emit(event, ...args);
		};
	};

	let uploadFinished = false;
	const onUpload = () => {
		timings.upload = Date.now();
		timings.phases.request = timings.upload - timings.connect;
	};

	handleError(request);

	request.once('socket', socket => {
		timings.socket = Date.now();
		timings.phases.wait = timings.socket - timings.start;

		const lookupListener = () => {
			timings.lookup = Date.now();
			timings.phases.dns = timings.lookup - timings.socket;
		};

		socket.once('lookup', lookupListener);

		deferToConnect(socket, () => {
			timings.connect = Date.now();

			if (timings.lookup === null) {
				socket.removeListener('lookup', lookupListener);
				timings.lookup = timings.connect;
				timings.phases.dns = timings.lookup - timings.socket;
			}

			timings.phases.tcp = timings.connect - timings.lookup;

			if (uploadFinished && !timings.upload) {
				onUpload();
			}
		});
	});

	request.once('finish', () => {
		uploadFinished = true;

		if (timings.connect) {
			onUpload();
		}
	});

	request.once('response', response => {
		timings.response = Date.now();
		timings.phases.firstByte = timings.response - timings.upload;

		handleError(response);

		response.once('end', () => {
			timings.end = Date.now();
			timings.phases.download = timings.end - timings.response;
			timings.phases.total = timings.end - timings.start;
		});
	});

	return timings;
};


/***/ }),

/***/ "j5q1":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("0LeV");


const internals = {};


module.exports = function (obj, template, options) {

    return template.replace(/{([^}]+)}/g, ($0, chain) => {

        const value = Reach(obj, chain, options);
        return (value === undefined || value === null ? '' : value);
    });
};


/***/ }),

/***/ "jK02":
/***/ (function(module, exports) {

module.exports = require("util");

/***/ }),

/***/ "jUDV":
/***/ (function(module, exports, __webpack_require__) {

const { inherits } = __webpack_require__("jK02")
const encoders = __webpack_require__("E8LI")
const decoders = __webpack_require__("zspo")

module.exports.define = function define (name, body) {
  return new Entity(name, body)
}

function Entity (name, body) {
  this.name = name
  this.body = body

  this.decoders = {}
  this.encoders = {}
}

Entity.prototype._createNamed = function createNamed (Base) {
  const name = this.name

  function Generated (entity) {
    this._initNamed(entity, name)
  }
  inherits(Generated, Base)
  Generated.prototype._initNamed = function _initNamed (entity, name) {
    Base.call(this, entity, name)
  }

  return new Generated(this)
}

Entity.prototype._getDecoder = function _getDecoder (enc) {
  enc = enc || 'der'
  // Lazily create decoder
  if (!Object.prototype.hasOwnProperty.call(this.decoders, enc)) { this.decoders[enc] = this._createNamed(decoders[enc]) }
  return this.decoders[enc]
}

Entity.prototype.decode = function decode (data, enc, options) {
  return this._getDecoder(enc).decode(data, options)
}

Entity.prototype._getEncoder = function _getEncoder (enc) {
  enc = enc || 'der'
  // Lazily create encoder
  if (!Object.prototype.hasOwnProperty.call(this.encoders, enc)) { this.encoders[enc] = this._createNamed(encoders[enc]) }
  return this.encoders[enc]
}

Entity.prototype.encode = function encode (data, enc, /* internal */ reporter) {
  return this._getEncoder(enc).encode(data, reporter)
}


/***/ }),

/***/ "jVnL":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (input) {

    if (!input) {
        return '';
    }

    let escaped = '';

    for (let i = 0; i < input.length; ++i) {

        const charCode = input.charCodeAt(i);

        if (internals.isSafe(charCode)) {
            escaped += input[i];
        }
        else {
            escaped += internals.escapeHtmlChar(charCode);
        }
    }

    return escaped;
};


internals.escapeHtmlChar = function (charCode) {

    const namedEscape = internals.namedHtml[charCode];
    if (typeof namedEscape !== 'undefined') {
        return namedEscape;
    }

    if (charCode >= 256) {
        return '&#' + charCode + ';';
    }

    const hexValue = charCode.toString(16).padStart(2, '0');
    return `&#x${hexValue};`;
};


internals.isSafe = function (charCode) {

    return (typeof internals.safeCharCodes[charCode] !== 'undefined');
};


internals.namedHtml = {
    '38': '&amp;',
    '60': '&lt;',
    '62': '&gt;',
    '34': '&quot;',
    '160': '&nbsp;',
    '162': '&cent;',
    '163': '&pound;',
    '164': '&curren;',
    '169': '&copy;',
    '174': '&reg;'
};


internals.safeCharCodes = (function () {

    const safe = {};

    for (let i = 32; i < 123; ++i) {

        if ((i >= 97) ||                    // a-z
            (i >= 65 && i <= 90) ||         // A-Z
            (i >= 48 && i <= 57) ||         // 0-9
            i === 32 ||                     // space
            i === 46 ||                     // .
            i === 44 ||                     // ,
            i === 45 ||                     // -
            i === 58 ||                     // :
            i === 95) {                     // _

            safe[i] = null;
        }
    }

    return safe;
}());


/***/ }),

/***/ "jle/":
/***/ (function(module, exports) {

module.exports = require("os");

/***/ }),

/***/ "jvMF":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Reach = __webpack_require__("zjbl");


const internals = {};


exports.keys = function (obj, options = {}) {

    return options.symbols !== false ? Reflect.ownKeys(obj) : Object.getOwnPropertyNames(obj);  // Defaults to true
};


exports.store = function (source, keys) {

    const storage = new Map();
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        const value = Reach(source, key);
        if (typeof value === 'object' ||
            typeof value === 'function') {

            storage.set(key, value);
            internals.reachSet(source, key, undefined);
        }
    }

    return storage;
};


exports.restore = function (copy, source, storage) {

    for (const [key, value] of storage) {
        internals.reachSet(copy, key, value);
        internals.reachSet(source, key, value);
    }
};


internals.reachSet = function (obj, key, value) {

    const path = Array.isArray(key) ? key : key.split('.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        const segment = path[i];
        if (i + 1 === path.length) {
            ref[segment] = value;
        }

        ref = ref[segment];
    }
};


/***/ }),

/***/ "k+0e":
/***/ (function(module, exports, __webpack_require__) {

const { strict: assert } = __webpack_require__("Qs3B")

const { Reporter } = __webpack_require__("1WHo")
const { DecoderBuffer, EncoderBuffer } = __webpack_require__("Z9M3")

// Supported tags
const tags = [
  'seq', 'seqof', 'set', 'setof', 'objid', 'bool',
  'gentime', 'utctime', 'null_', 'enum', 'int', 'objDesc',
  'bitstr', 'bmpstr', 'charstr', 'genstr', 'graphstr', 'ia5str', 'iso646str',
  'numstr', 'octstr', 'printstr', 't61str', 'unistr', 'utf8str', 'videostr'
]

// Public methods list
const methods = [
  'key', 'obj', 'use', 'optional', 'explicit', 'implicit', 'def', 'choice',
  'any', 'contains'
].concat(tags)

// Overrided methods list
const overrided = [
  '_peekTag', '_decodeTag', '_use',
  '_decodeStr', '_decodeObjid', '_decodeTime',
  '_decodeNull', '_decodeInt', '_decodeBool', '_decodeList',

  '_encodeComposite', '_encodeStr', '_encodeObjid', '_encodeTime',
  '_encodeNull', '_encodeInt', '_encodeBool'
]

function Node (enc, parent, name) {
  const state = {}
  this._baseState = state

  state.name = name
  state.enc = enc

  state.parent = parent || null
  state.children = null

  // State
  state.tag = null
  state.args = null
  state.reverseArgs = null
  state.choice = null
  state.optional = false
  state.any = false
  state.obj = false
  state.use = null
  state.useDecoder = null
  state.key = null
  state.default = null
  state.explicit = null
  state.implicit = null
  state.contains = null

  // Should create new instance on each method
  if (!state.parent) {
    state.children = []
    this._wrap()
  }
}

const stateProps = [
  'enc', 'parent', 'children', 'tag', 'args', 'reverseArgs', 'choice',
  'optional', 'any', 'obj', 'use', 'alteredUse', 'key', 'default', 'explicit',
  'implicit', 'contains'
]

Node.prototype.clone = function clone () {
  const state = this._baseState
  const cstate = {}
  stateProps.forEach(function (prop) {
    cstate[prop] = state[prop]
  })
  const res = new this.constructor(cstate.parent)
  res._baseState = cstate
  return res
}

Node.prototype._wrap = function wrap () {
  const state = this._baseState
  methods.forEach(function (method) {
    this[method] = function _wrappedMethod () {
      const clone = new this.constructor(this)
      state.children.push(clone)
      return clone[method].apply(clone, arguments)
    }
  }, this)
}

Node.prototype._init = function init (body) {
  const state = this._baseState

  assert(state.parent === null)
  body.call(this)

  // Filter children
  state.children = state.children.filter(function (child) {
    return child._baseState.parent === this
  }, this)
  assert.equal(state.children.length, 1, 'Root node can have only one child')
}

Node.prototype._useArgs = function useArgs (args) {
  const state = this._baseState

  // Filter children and args
  const children = args.filter(function (arg) {
    return arg instanceof this.constructor
  }, this)
  args = args.filter(function (arg) {
    return !(arg instanceof this.constructor)
  }, this)

  if (children.length !== 0) {
    assert(state.children === null)
    state.children = children

    // Replace parent to maintain backward link
    children.forEach(function (child) {
      child._baseState.parent = this
    }, this)
  }
  if (args.length !== 0) {
    assert(state.args === null)
    state.args = args
    state.reverseArgs = args.map(function (arg) {
      if (typeof arg !== 'object' || arg.constructor !== Object) { return arg }

      const res = {}
      Object.keys(arg).forEach(function (key) {
        if (key == (key | 0)) { key |= 0 } // eslint-disable-line eqeqeq
        const value = arg[key]
        res[value] = key
      })
      return res
    })
  }
}

//
// Overrided methods
//

overrided.forEach(function (method) {
  Node.prototype[method] = function _overrided () {
    const state = this._baseState
    throw new Error(`${method} not implemented for encoding: ${state.enc}`)
  }
})

//
// Public methods
//

tags.forEach(function (tag) {
  Node.prototype[tag] = function _tagMethod () {
    const state = this._baseState
    const args = Array.prototype.slice.call(arguments)

    assert(state.tag === null)
    state.tag = tag

    this._useArgs(args)

    return this
  }
})

Node.prototype.use = function use (item) {
  assert(item)
  const state = this._baseState

  assert(state.use === null)
  state.use = item

  return this
}

Node.prototype.optional = function optional () {
  const state = this._baseState

  state.optional = true

  return this
}

Node.prototype.def = function def (val) {
  const state = this._baseState

  assert(state.default === null)
  state.default = val
  state.optional = true

  return this
}

Node.prototype.explicit = function explicit (num) {
  const state = this._baseState

  assert(state.explicit === null && state.implicit === null)
  state.explicit = num

  return this
}

Node.prototype.implicit = function implicit (num) {
  const state = this._baseState

  assert(state.explicit === null && state.implicit === null)
  state.implicit = num

  return this
}

Node.prototype.obj = function obj () {
  const state = this._baseState
  const args = Array.prototype.slice.call(arguments)

  state.obj = true

  if (args.length !== 0) { this._useArgs(args) }

  return this
}

Node.prototype.key = function key (newKey) {
  const state = this._baseState

  assert(state.key === null)
  state.key = newKey

  return this
}

Node.prototype.any = function any () {
  const state = this._baseState

  state.any = true

  return this
}

Node.prototype.choice = function choice (obj) {
  const state = this._baseState

  assert(state.choice === null)
  state.choice = obj
  this._useArgs(Object.keys(obj).map(function (key) {
    return obj[key]
  }))

  return this
}

Node.prototype.contains = function contains (item) {
  const state = this._baseState

  assert(state.use === null)
  state.contains = item

  return this
}

//
// Decoding
//

Node.prototype._decode = function decode (input, options) {
  const state = this._baseState

  // Decode root node
  if (state.parent === null) { return input.wrapResult(state.children[0]._decode(input, options)) }

  let result = state.default
  let present = true

  let prevKey = null
  if (state.key !== null) { prevKey = input.enterKey(state.key) }

  // Check if tag is there
  if (state.optional) {
    let tag = null
    if (state.explicit !== null) { tag = state.explicit } else if (state.implicit !== null) { tag = state.implicit } else if (state.tag !== null) { tag = state.tag }

    if (tag === null && !state.any) {
      // Trial and Error
      const save = input.save()
      try {
        if (state.choice === null) { this._decodeGeneric(state.tag, input, options) } else { this._decodeChoice(input, options) }
        present = true
      } catch (e) {
        present = false
      }
      input.restore(save)
    } else {
      present = this._peekTag(input, tag, state.any)

      if (input.isError(present)) { return present }
    }
  }

  // Push object on stack
  let prevObj
  if (state.obj && present) { prevObj = input.enterObject() }

  if (present) {
    // Unwrap explicit values
    if (state.explicit !== null) {
      const explicit = this._decodeTag(input, state.explicit)
      if (input.isError(explicit)) { return explicit }
      input = explicit
    }

    const start = input.offset

    // Unwrap implicit and normal values
    if (state.use === null && state.choice === null) {
      let save
      if (state.any) { save = input.save() }
      const body = this._decodeTag(
        input,
        state.implicit !== null ? state.implicit : state.tag,
        state.any
      )
      if (input.isError(body)) { return body }

      if (state.any) { result = input.raw(save) } else { input = body }
    }

    if (options && options.track && state.tag !== null) { options.track(input.path(), start, input.length, 'tagged') }

    if (options && options.track && state.tag !== null) { options.track(input.path(), input.offset, input.length, 'content') }

    // Select proper method for tag
    if (state.any) {
      // no-op
    } else if (state.choice === null) {
      result = this._decodeGeneric(state.tag, input, options)
    } else {
      result = this._decodeChoice(input, options)
    }

    if (input.isError(result)) { return result }

    // Decode children
    if (!state.any && state.choice === null && state.children !== null) {
      state.children.forEach(function decodeChildren (child) {
        // NOTE: We are ignoring errors here, to let parser continue with other
        // parts of encoded data
        child._decode(input, options)
      })
    }

    // Decode contained/encoded by schema, only in bit or octet strings
    if (state.contains && (state.tag === 'octstr' || state.tag === 'bitstr')) {
      const data = new DecoderBuffer(result)
      result = this._getUse(state.contains, input._reporterState.obj)
        ._decode(data, options)
    }
  }

  // Pop object
  if (state.obj && present) { result = input.leaveObject(prevObj) }

  // Set key
  if (state.key !== null && (result !== null || present === true)) { input.leaveKey(prevKey, state.key, result) } else if (prevKey !== null) { input.exitKey(prevKey) }

  return result
}

Node.prototype._decodeGeneric = function decodeGeneric (tag, input, options) {
  const state = this._baseState

  if (tag === 'seq' || tag === 'set') { return null }
  if (tag === 'seqof' || tag === 'setof') { return this._decodeList(input, tag, state.args[0], options) } else if (/str$/.test(tag)) { return this._decodeStr(input, tag, options) } else if (tag === 'objid' && state.args) { return this._decodeObjid(input, state.args[0], state.args[1], options) } else if (tag === 'objid') { return this._decodeObjid(input, null, null, options) } else if (tag === 'gentime' || tag === 'utctime') { return this._decodeTime(input, tag, options) } else if (tag === 'null_') { return this._decodeNull(input, options) } else if (tag === 'bool') { return this._decodeBool(input, options) } else if (tag === 'objDesc') { return this._decodeStr(input, tag, options) } else if (tag === 'int' || tag === 'enum') { return this._decodeInt(input, state.args && state.args[0], options) }

  if (state.use !== null) {
    return this._getUse(state.use, input._reporterState.obj)
      ._decode(input, options)
  } else {
    return input.error(`unknown tag: ${tag}`)
  }
}

Node.prototype._getUse = function _getUse (entity, obj) {
  const state = this._baseState
  // Create altered use decoder if implicit is set
  state.useDecoder = this._use(entity, obj)
  assert(state.useDecoder._baseState.parent === null)
  state.useDecoder = state.useDecoder._baseState.children[0]
  if (state.implicit !== state.useDecoder._baseState.implicit) {
    state.useDecoder = state.useDecoder.clone()
    state.useDecoder._baseState.implicit = state.implicit
  }
  return state.useDecoder
}

Node.prototype._decodeChoice = function decodeChoice (input, options) {
  const state = this._baseState
  let result = null
  let match = false

  Object.keys(state.choice).some(function (key) {
    const save = input.save()
    const node = state.choice[key]
    try {
      const value = node._decode(input, options)
      if (input.isError(value)) { return false }

      result = { type: key, value: value }
      match = true
    } catch (e) {
      input.restore(save)
      return false
    }
    return true
  }, this)

  if (!match) { return input.error('Choice not matched') }

  return result
}

//
// Encoding
//

Node.prototype._createEncoderBuffer = function createEncoderBuffer (data) {
  return new EncoderBuffer(data, this.reporter)
}

Node.prototype._encode = function encode (data, reporter, parent) {
  const state = this._baseState
  if (state.default !== null && state.default === data) { return }

  const result = this._encodeValue(data, reporter, parent)
  if (result === undefined) { return }

  if (this._skipDefault(result, reporter, parent)) { return }

  return result
}

Node.prototype._encodeValue = function encode (data, reporter, parent) {
  const state = this._baseState

  // Decode root node
  if (state.parent === null) { return state.children[0]._encode(data, reporter || new Reporter()) }

  let result = null

  // Set reporter to share it with a child class
  this.reporter = reporter

  // Check if data is there
  if (state.optional && data === undefined) {
    if (state.default !== null) { data = state.default } else { return }
  }

  // Encode children first
  let content = null
  let primitive = false
  if (state.any) {
    // Anything that was given is translated to buffer
    result = this._createEncoderBuffer(data)
  } else if (state.choice) {
    result = this._encodeChoice(data, reporter)
  } else if (state.contains) {
    content = this._getUse(state.contains, parent)._encode(data, reporter)
    primitive = true
  } else if (state.children) {
    content = state.children.map(function (child) {
      if (child._baseState.tag === 'null_') { return child._encode(null, reporter, data) }

      if (child._baseState.key === null) { return reporter.error('Child should have a key') }
      const prevKey = reporter.enterKey(child._baseState.key)

      if (typeof data !== 'object') { return reporter.error('Child expected, but input is not object') }

      const res = child._encode(data[child._baseState.key], reporter, data)
      reporter.leaveKey(prevKey)

      return res
    }, this).filter(function (child) {
      return child
    })
    content = this._createEncoderBuffer(content)
  } else {
    if (state.tag === 'seqof' || state.tag === 'setof') {
      if (!(state.args && state.args.length === 1)) { return reporter.error(`Too many args for: ${state.tag}`) }

      if (!Array.isArray(data)) { return reporter.error('seqof/setof, but data is not Array') }

      const child = this.clone()
      child._baseState.implicit = null
      content = this._createEncoderBuffer(data.map(function (item) {
        const state = this._baseState

        return this._getUse(state.args[0], data)._encode(item, reporter)
      }, child))
    } else if (state.use !== null) {
      result = this._getUse(state.use, parent)._encode(data, reporter)
    } else {
      content = this._encodePrimitive(state.tag, data)
      primitive = true
    }
  }

  // Encode data itself
  if (!state.any && state.choice === null) {
    const tag = state.implicit !== null ? state.implicit : state.tag
    const cls = state.implicit === null ? 'universal' : 'context'

    if (tag === null) {
      if (state.use === null) { reporter.error('Tag could be omitted only for .use()') }
    } else {
      if (state.use === null) { result = this._encodeComposite(tag, primitive, cls, content) }
    }
  }

  // Wrap in explicit
  if (state.explicit !== null) { result = this._encodeComposite(state.explicit, false, 'context', result) }

  return result
}

Node.prototype._encodeChoice = function encodeChoice (data, reporter) {
  const state = this._baseState

  const node = state.choice[data.type]
  if (!node) {
    assert(
      false,
      `${data.type} not found in ${JSON.stringify(Object.keys(state.choice))}`
    )
  }
  return node._encode(data.value, reporter)
}

Node.prototype._encodePrimitive = function encodePrimitive (tag, data) {
  const state = this._baseState

  if (/str$/.test(tag)) { return this._encodeStr(data, tag) } else if (tag === 'objid' && state.args) { return this._encodeObjid(data, state.reverseArgs[0], state.args[1]) } else if (tag === 'objid') { return this._encodeObjid(data, null, null) } else if (tag === 'gentime' || tag === 'utctime') { return this._encodeTime(data, tag) } else if (tag === 'null_') { return this._encodeNull() } else if (tag === 'int' || tag === 'enum') { return this._encodeInt(data, state.args && state.reverseArgs[0]) } else if (tag === 'bool') { return this._encodeBool(data) } else if (tag === 'objDesc') { return this._encodeStr(data, tag) } else { throw new Error(`Unsupported tag: ${tag}`) }
}

Node.prototype._isNumstr = function isNumstr (str) {
  return /^[0-9 ]*$/.test(str)
}

Node.prototype._isPrintstr = function isPrintstr (str) {
  return /^[A-Za-z0-9 '()+,-./:=?]*$/.test(str)
}

module.exports = Node


/***/ }),

/***/ "k9s9":
/***/ (function(module, exports) {

module.exports = function () {
  this.seq().obj(
    this.key('n').int(),
    this.key('e').int()
  )
}


/***/ }),

/***/ "kDq4":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function () { };


/***/ }),

/***/ "kF1/":
/***/ (function(module, exports) {

module.exports = a => !!a && a.constructor === Object


/***/ }),

/***/ "kYX4":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("2BAz");


const internals = {};


module.exports = function (attribute) {

    // Allowed value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "

    Assert(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\]*$/.test(attribute), 'Bad attribute value (' + attribute + ')');

    return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');                             // Escape quotes and slash
};


/***/ }),

/***/ "kZLX":
/***/ (function(module, exports, __webpack_require__) {

const { createHash } = __webpack_require__("PJMN")
const ecdhComputeSecret = __webpack_require__("RFts")

const concat = (key, length, value) => {
  const iterations = Math.ceil(length / 32)
  let res

  for (let iter = 1; iter <= iterations; iter++) {
    const buf = Buffer.allocUnsafe(4 + key.length + value.length)
    buf.writeUInt32BE(iter, 0)
    key.copy(buf, 4)
    value.copy(buf, 4 + key.length)
    if (!res) {
      res = createHash('sha256').update(buf).digest()
    } else {
      res = Buffer.concat([res, createHash('sha256').update(buf).digest()])
    }
  }

  return res.slice(0, length)
}

const uint32be = (value, buf = Buffer.allocUnsafe(4)) => {
  buf.writeUInt32BE(value)
  return buf
}

const lengthAndInput = input => Buffer.concat([uint32be(input.length), input])

module.exports = (alg, keyLen, privKey, pubKey, { apu = Buffer.alloc(0), apv = Buffer.alloc(0) } = {}, computeSecret = ecdhComputeSecret) => {
  const value = Buffer.concat([
    lengthAndInput(Buffer.from(alg)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLen)
  ])

  const sharedSecret = computeSecret(privKey, pubKey)
  return concat(sharedSecret, keyLen / 8, value)
}


/***/ }),

/***/ "kjw5":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {PassThrough} = __webpack_require__("msIP");
const duplexer3 = __webpack_require__("U064");
const requestAsEventEmitter = __webpack_require__("y/nk");
const {HTTPError, ReadError} = __webpack_require__("9Fi5");

module.exports = options => {
	const input = new PassThrough();
	const output = new PassThrough();
	const proxy = duplexer3(input, output);
	const piped = new Set();
	let isFinished = false;

	options.retry.retries = () => 0;

	if (options.body) {
		proxy.write = () => {
			throw new Error('Got\'s stream is not writable when the `body` option is used');
		};
	}

	const emitter = requestAsEventEmitter(options, input);

	// Cancels the request
	proxy._destroy = emitter.abort;

	emitter.on('response', response => {
		const {statusCode} = response;

		response.on('error', error => {
			proxy.emit('error', new ReadError(error, options));
		});

		if (options.throwHttpErrors && statusCode !== 304 && (statusCode < 200 || statusCode > 299)) {
			proxy.emit('error', new HTTPError(response, options), null, response);
			return;
		}

		isFinished = true;

		response.pipe(output);

		for (const destination of piped) {
			if (destination.headersSent) {
				continue;
			}

			for (const [key, value] of Object.entries(response.headers)) {
				// Got gives *decompressed* data. Overriding `content-encoding` header would result in an error.
				// It's not possible to decompress already decompressed data, is it?
				const allowed = options.decompress ? key !== 'content-encoding' : true;
				if (allowed) {
					destination.setHeader(key, value);
				}
			}

			destination.statusCode = response.statusCode;
		}

		proxy.emit('response', response);
	});

	[
		'error',
		'request',
		'redirect',
		'uploadProgress',
		'downloadProgress'
	].forEach(event => emitter.on(event, (...args) => proxy.emit(event, ...args)));

	const pipe = proxy.pipe.bind(proxy);
	const unpipe = proxy.unpipe.bind(proxy);
	proxy.pipe = (destination, options) => {
		if (isFinished) {
			throw new Error('Failed to pipe. The response has been emitted already.');
		}

		const result = pipe(destination, options);

		if (Reflect.has(destination, 'setHeader')) {
			piped.add(destination);
		}

		return result;
	};

	proxy.unpipe = stream => {
		piped.delete(stream);
		return unpipe(stream);
	};

	return proxy;
};


/***/ }),

/***/ "kuaU":
/***/ (function(module, exports, __webpack_require__) {

const { timingSafeEqual: TSE } = __webpack_require__("PJMN")

const paddedBuffer = (input, length) => {
  if (input.length === length) {
    return input
  }

  const buffer = Buffer.alloc(length)
  input.copy(buffer)
  return buffer
}

const timingSafeEqual = (a, b) => {
  const length = Math.max(a.length, b.length)
  return TSE(paddedBuffer(a, length), paddedBuffer(b, length))
}

module.exports = timingSafeEqual


/***/ }),

/***/ "l3Iq":
/***/ (function(module, exports, __webpack_require__) {

const base64url = __webpack_require__("Xab3")
const isDisjoint = __webpack_require__("KQbz")
const isObject = __webpack_require__("kF1/")
const deepClone = __webpack_require__("O9d4")
const { JWSInvalid } = __webpack_require__("yt7c")
const { sign } = __webpack_require__("FUB/")
const getKey = __webpack_require__("oGTz")

const serializers = __webpack_require__("SwXk")

const PROCESS_RECIPIENT = Symbol('PROCESS_RECIPIENT')

class Sign {
  constructor (payload) {
    if (typeof payload === 'string') {
      payload = base64url.encode(payload)
    } else if (Buffer.isBuffer(payload)) {
      payload = base64url.encodeBuffer(payload)
      this._binary = true
    } else if (isObject(payload)) {
      payload = base64url.JSON.encode(payload)
    } else {
      throw new TypeError('payload argument must be a Buffer, string or an object')
    }

    this._payload = payload
    this._recipients = []
  }

  /*
   * @public
   */
  recipient (key, protectedHeader, unprotectedHeader) {
    key = getKey(key)

    if (protectedHeader !== undefined && !isObject(protectedHeader)) {
      throw new TypeError('protectedHeader argument must be a plain object when provided')
    }

    if (unprotectedHeader !== undefined && !isObject(unprotectedHeader)) {
      throw new TypeError('unprotectedHeader argument must be a plain object when provided')
    }

    if (!isDisjoint(protectedHeader, unprotectedHeader)) {
      throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint')
    }

    this._recipients.push({
      key,
      protectedHeader: protectedHeader ? deepClone(protectedHeader) : undefined,
      unprotectedHeader: unprotectedHeader ? deepClone(unprotectedHeader) : undefined
    })

    return this
  }

  /*
   * @private
   */
  [PROCESS_RECIPIENT] (recipient, first) {
    const { key, protectedHeader, unprotectedHeader } = recipient

    if (key.use === 'enc') {
      throw new TypeError('a key with "use":"enc" is not usable for signing')
    }

    const joseHeader = {
      protected: protectedHeader || {},
      unprotected: unprotectedHeader || {}
    }

    let alg = joseHeader.protected.alg || joseHeader.unprotected.alg

    if (!alg) {
      alg = key.alg || [...key.algorithms('sign')][0]
      if (recipient.protectedHeader) {
        joseHeader.protected.alg = recipient.protectedHeader.alg = alg
      } else {
        joseHeader.protected = recipient.protectedHeader = { alg }
      }
    }

    if (!alg) {
      throw new JWSInvalid('could not resolve a usable "alg" for a recipient')
    }

    recipient.header = unprotectedHeader
    recipient.protected = Object.keys(joseHeader.protected).length ? base64url.JSON.encode(joseHeader.protected) : ''

    if (first && joseHeader.protected.crit && joseHeader.protected.crit.includes('b64') && joseHeader.protected.b64 === false) {
      if (this._binary) {
        this._payload = base64url.decodeToBuffer(this._payload)
      } else {
        this._payload = base64url.decode(this._payload)
      }
    }

    const data = Buffer.concat([
      Buffer.from(recipient.protected || ''),
      Buffer.from('.'),
      Buffer.from(this._payload)
    ])

    recipient.signature = base64url.encodeBuffer(sign(alg, key, data))
  }

  /*
   * @public
   */
  sign (serialization) {
    const serializer = serializers[serialization]
    if (!serializer) {
      throw new TypeError('serialization must be one of "compact", "flattened", "general"')
    }

    if (!this._recipients.length) {
      throw new JWSInvalid('missing recipients')
    }

    serializer.validate(this, this._recipients)

    this._recipients.forEach((recipient, i) => {
      this[PROCESS_RECIPIENT](recipient, i === 0)
    })

    return serializer(this._payload, this._recipients)
  }
}

module.exports = Sign


/***/ }),

/***/ "lA9T":
/***/ (function(module, exports, __webpack_require__) {

const Key = __webpack_require__("//Cd")
const None = __webpack_require__("qSBP")
const EmbeddedJWK = __webpack_require__("eEdi")
const EmbeddedX5C = __webpack_require__("IhwK")
const importKey = __webpack_require__("GhER")
const generate = __webpack_require__("LDEB")

module.exports = {
  ...generate,
  asKey: importKey,
  isKey: input => input instanceof Key,
  None,
  EmbeddedJWK,
  EmbeddedX5C
}

/* deprecated */
Object.defineProperty(module.exports, 'importKey', {
  value: importKey.deprecated,
  enumerable: false
})


/***/ }),

/***/ "lERV":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// rfc7231 6.1
const statusCodeCacheableByDefault = new Set([
    200,
    203,
    204,
    206,
    300,
    301,
    404,
    405,
    410,
    414,
    501,
]);

// This implementation does not understand partial responses (206)
const understoodStatuses = new Set([
    200,
    203,
    204,
    300,
    301,
    302,
    303,
    307,
    308,
    404,
    405,
    410,
    414,
    501,
]);

const errorStatusCodes = new Set([
    500,
    502,
    503, 
    504,
]);

const hopByHopHeaders = {
    date: true, // included, because we add Age update Date
    connection: true,
    'keep-alive': true,
    'proxy-authenticate': true,
    'proxy-authorization': true,
    te: true,
    trailer: true,
    'transfer-encoding': true,
    upgrade: true,
};

const excludedFromRevalidationUpdate = {
    // Since the old body is reused, it doesn't make sense to change properties of the body
    'content-length': true,
    'content-encoding': true,
    'transfer-encoding': true,
    'content-range': true,
};

function toNumberOrZero(s) {
    const n = parseInt(s, 10);
    return isFinite(n) ? n : 0;
}

// RFC 5861
function isErrorResponse(response) {
    // consider undefined response as faulty
    if(!response) {
        return true
    }
    return errorStatusCodes.has(response.status);
}

function parseCacheControl(header) {
    const cc = {};
    if (!header) return cc;

    // TODO: When there is more than one value present for a given directive (e.g., two Expires header fields, multiple Cache-Control: max-age directives),
    // the directive's value is considered invalid. Caches are encouraged to consider responses that have invalid freshness information to be stale
    const parts = header.trim().split(/\s*,\s*/); // TODO: lame parsing
    for (const part of parts) {
        const [k, v] = part.split(/\s*=\s*/, 2);
        cc[k] = v === undefined ? true : v.replace(/^"|"$/g, ''); // TODO: lame unquoting
    }

    return cc;
}

function formatCacheControl(cc) {
    let parts = [];
    for (const k in cc) {
        const v = cc[k];
        parts.push(v === true ? k : k + '=' + v);
    }
    if (!parts.length) {
        return undefined;
    }
    return parts.join(', ');
}

module.exports = class CachePolicy {
    constructor(
        req,
        res,
        {
            shared,
            cacheHeuristic,
            immutableMinTimeToLive,
            ignoreCargoCult,
            _fromObject,
        } = {}
    ) {
        if (_fromObject) {
            this._fromObject(_fromObject);
            return;
        }

        if (!res || !res.headers) {
            throw Error('Response headers missing');
        }
        this._assertRequestHasHeaders(req);

        this._responseTime = this.now();
        this._isShared = shared !== false;
        this._cacheHeuristic =
            undefined !== cacheHeuristic ? cacheHeuristic : 0.1; // 10% matches IE
        this._immutableMinTtl =
            undefined !== immutableMinTimeToLive
                ? immutableMinTimeToLive
                : 24 * 3600 * 1000;

        this._status = 'status' in res ? res.status : 200;
        this._resHeaders = res.headers;
        this._rescc = parseCacheControl(res.headers['cache-control']);
        this._method = 'method' in req ? req.method : 'GET';
        this._url = req.url;
        this._host = req.headers.host;
        this._noAuthorization = !req.headers.authorization;
        this._reqHeaders = res.headers.vary ? req.headers : null; // Don't keep all request headers if they won't be used
        this._reqcc = parseCacheControl(req.headers['cache-control']);

        // Assume that if someone uses legacy, non-standard uncecessary options they don't understand caching,
        // so there's no point stricly adhering to the blindly copy&pasted directives.
        if (
            ignoreCargoCult &&
            'pre-check' in this._rescc &&
            'post-check' in this._rescc
        ) {
            delete this._rescc['pre-check'];
            delete this._rescc['post-check'];
            delete this._rescc['no-cache'];
            delete this._rescc['no-store'];
            delete this._rescc['must-revalidate'];
            this._resHeaders = Object.assign({}, this._resHeaders, {
                'cache-control': formatCacheControl(this._rescc),
            });
            delete this._resHeaders.expires;
            delete this._resHeaders.pragma;
        }

        // When the Cache-Control header field is not present in a request, caches MUST consider the no-cache request pragma-directive
        // as having the same effect as if "Cache-Control: no-cache" were present (see Section 5.2.1).
        if (
            res.headers['cache-control'] == null &&
            /no-cache/.test(res.headers.pragma)
        ) {
            this._rescc['no-cache'] = true;
        }
    }

    now() {
        return Date.now();
    }

    storable() {
        // The "no-store" request directive indicates that a cache MUST NOT store any part of either this request or any response to it.
        return !!(
            !this._reqcc['no-store'] &&
            // A cache MUST NOT store a response to any request, unless:
            // The request method is understood by the cache and defined as being cacheable, and
            ('GET' === this._method ||
                'HEAD' === this._method ||
                ('POST' === this._method && this._hasExplicitExpiration())) &&
            // the response status code is understood by the cache, and
            understoodStatuses.has(this._status) &&
            // the "no-store" cache directive does not appear in request or response header fields, and
            !this._rescc['no-store'] &&
            // the "private" response directive does not appear in the response, if the cache is shared, and
            (!this._isShared || !this._rescc.private) &&
            // the Authorization header field does not appear in the request, if the cache is shared,
            (!this._isShared ||
                this._noAuthorization ||
                this._allowsStoringAuthenticated()) &&
            // the response either:
            // contains an Expires header field, or
            (this._resHeaders.expires ||
                // contains a max-age response directive, or
                // contains a s-maxage response directive and the cache is shared, or
                // contains a public response directive.
                this._rescc['max-age'] ||
                (this._isShared && this._rescc['s-maxage']) ||
                this._rescc.public ||
                // has a status code that is defined as cacheable by default
                statusCodeCacheableByDefault.has(this._status))
        );
    }

    _hasExplicitExpiration() {
        // 4.2.1 Calculating Freshness Lifetime
        return (
            (this._isShared && this._rescc['s-maxage']) ||
            this._rescc['max-age'] ||
            this._resHeaders.expires
        );
    }

    _assertRequestHasHeaders(req) {
        if (!req || !req.headers) {
            throw Error('Request headers missing');
        }
    }

    satisfiesWithoutRevalidation(req) {
        this._assertRequestHasHeaders(req);

        // When presented with a request, a cache MUST NOT reuse a stored response, unless:
        // the presented request does not contain the no-cache pragma (Section 5.4), nor the no-cache cache directive,
        // unless the stored response is successfully validated (Section 4.3), and
        const requestCC = parseCacheControl(req.headers['cache-control']);
        if (requestCC['no-cache'] || /no-cache/.test(req.headers.pragma)) {
            return false;
        }

        if (requestCC['max-age'] && this.age() > requestCC['max-age']) {
            return false;
        }

        if (
            requestCC['min-fresh'] &&
            this.timeToLive() < 1000 * requestCC['min-fresh']
        ) {
            return false;
        }

        // the stored response is either:
        // fresh, or allowed to be served stale
        if (this.stale()) {
            const allowsStale =
                requestCC['max-stale'] &&
                !this._rescc['must-revalidate'] &&
                (true === requestCC['max-stale'] ||
                    requestCC['max-stale'] > this.age() - this.maxAge());
            if (!allowsStale) {
                return false;
            }
        }

        return this._requestMatches(req, false);
    }

    _requestMatches(req, allowHeadMethod) {
        // The presented effective request URI and that of the stored response match, and
        return (
            (!this._url || this._url === req.url) &&
            this._host === req.headers.host &&
            // the request method associated with the stored response allows it to be used for the presented request, and
            (!req.method ||
                this._method === req.method ||
                (allowHeadMethod && 'HEAD' === req.method)) &&
            // selecting header fields nominated by the stored response (if any) match those presented, and
            this._varyMatches(req)
        );
    }

    _allowsStoringAuthenticated() {
        //  following Cache-Control response directives (Section 5.2.2) have such an effect: must-revalidate, public, and s-maxage.
        return (
            this._rescc['must-revalidate'] ||
            this._rescc.public ||
            this._rescc['s-maxage']
        );
    }

    _varyMatches(req) {
        if (!this._resHeaders.vary) {
            return true;
        }

        // A Vary header field-value of "*" always fails to match
        if (this._resHeaders.vary === '*') {
            return false;
        }

        const fields = this._resHeaders.vary
            .trim()
            .toLowerCase()
            .split(/\s*,\s*/);
        for (const name of fields) {
            if (req.headers[name] !== this._reqHeaders[name]) return false;
        }
        return true;
    }

    _copyWithoutHopByHopHeaders(inHeaders) {
        const headers = {};
        for (const name in inHeaders) {
            if (hopByHopHeaders[name]) continue;
            headers[name] = inHeaders[name];
        }
        // 9.1.  Connection
        if (inHeaders.connection) {
            const tokens = inHeaders.connection.trim().split(/\s*,\s*/);
            for (const name of tokens) {
                delete headers[name];
            }
        }
        if (headers.warning) {
            const warnings = headers.warning.split(/,/).filter(warning => {
                return !/^\s*1[0-9][0-9]/.test(warning);
            });
            if (!warnings.length) {
                delete headers.warning;
            } else {
                headers.warning = warnings.join(',').trim();
            }
        }
        return headers;
    }

    responseHeaders() {
        const headers = this._copyWithoutHopByHopHeaders(this._resHeaders);
        const age = this.age();

        // A cache SHOULD generate 113 warning if it heuristically chose a freshness
        // lifetime greater than 24 hours and the response's age is greater than 24 hours.
        if (
            age > 3600 * 24 &&
            !this._hasExplicitExpiration() &&
            this.maxAge() > 3600 * 24
        ) {
            headers.warning =
                (headers.warning ? `${headers.warning}, ` : '') +
                '113 - "rfc7234 5.5.4"';
        }
        headers.age = `${Math.round(age)}`;
        headers.date = new Date(this.now()).toUTCString();
        return headers;
    }

    /**
     * Value of the Date response header or current time if Date was invalid
     * @return timestamp
     */
    date() {
        const serverDate = Date.parse(this._resHeaders.date);
        if (isFinite(serverDate)) {
            return serverDate;
        }
        return this._responseTime;
    }

    /**
     * Value of the Age header, in seconds, updated for the current time.
     * May be fractional.
     *
     * @return Number
     */
    age() {
        let age = this._ageValue();

        const residentTime = (this.now() - this._responseTime) / 1000;
        return age + residentTime;
    }

    _ageValue() {
        return toNumberOrZero(this._resHeaders.age);
    }

    /**
     * Value of applicable max-age (or heuristic equivalent) in seconds. This counts since response's `Date`.
     *
     * For an up-to-date value, see `timeToLive()`.
     *
     * @return Number
     */
    maxAge() {
        if (!this.storable() || this._rescc['no-cache']) {
            return 0;
        }

        // Shared responses with cookies are cacheable according to the RFC, but IMHO it'd be unwise to do so by default
        // so this implementation requires explicit opt-in via public header
        if (
            this._isShared &&
            (this._resHeaders['set-cookie'] &&
                !this._rescc.public &&
                !this._rescc.immutable)
        ) {
            return 0;
        }

        if (this._resHeaders.vary === '*') {
            return 0;
        }

        if (this._isShared) {
            if (this._rescc['proxy-revalidate']) {
                return 0;
            }
            // if a response includes the s-maxage directive, a shared cache recipient MUST ignore the Expires field.
            if (this._rescc['s-maxage']) {
                return toNumberOrZero(this._rescc['s-maxage']);
            }
        }

        // If a response includes a Cache-Control field with the max-age directive, a recipient MUST ignore the Expires field.
        if (this._rescc['max-age']) {
            return toNumberOrZero(this._rescc['max-age']);
        }

        const defaultMinTtl = this._rescc.immutable ? this._immutableMinTtl : 0;

        const serverDate = this.date();
        if (this._resHeaders.expires) {
            const expires = Date.parse(this._resHeaders.expires);
            // A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired").
            if (Number.isNaN(expires) || expires < serverDate) {
                return 0;
            }
            return Math.max(defaultMinTtl, (expires - serverDate) / 1000);
        }

        if (this._resHeaders['last-modified']) {
            const lastModified = Date.parse(this._resHeaders['last-modified']);
            if (isFinite(lastModified) && serverDate > lastModified) {
                return Math.max(
                    defaultMinTtl,
                    ((serverDate - lastModified) / 1000) * this._cacheHeuristic
                );
            }
        }

        return defaultMinTtl;
    }

    timeToLive() {
        const age = this.maxAge() - this.age();
        const staleIfErrorAge = age + toNumberOrZero(this._rescc['stale-if-error']);
        const staleWhileRevalidateAge = age + toNumberOrZero(this._rescc['stale-while-revalidate']);
        return Math.max(0, age, staleIfErrorAge, staleWhileRevalidateAge) * 1000;
    }

    stale() {
        return this.maxAge() <= this.age();
    }

    _useStaleIfError() {
        return this.maxAge() + toNumberOrZero(this._rescc['stale-if-error']) > this.age();
    }

    useStaleWhileRevalidate() {
        return this.maxAge() + toNumberOrZero(this._rescc['stale-while-revalidate']) > this.age();
    }

    static fromObject(obj) {
        return new this(undefined, undefined, { _fromObject: obj });
    }

    _fromObject(obj) {
        if (this._responseTime) throw Error('Reinitialized');
        if (!obj || obj.v !== 1) throw Error('Invalid serialization');

        this._responseTime = obj.t;
        this._isShared = obj.sh;
        this._cacheHeuristic = obj.ch;
        this._immutableMinTtl =
            obj.imm !== undefined ? obj.imm : 24 * 3600 * 1000;
        this._status = obj.st;
        this._resHeaders = obj.resh;
        this._rescc = obj.rescc;
        this._method = obj.m;
        this._url = obj.u;
        this._host = obj.h;
        this._noAuthorization = obj.a;
        this._reqHeaders = obj.reqh;
        this._reqcc = obj.reqcc;
    }

    toObject() {
        return {
            v: 1,
            t: this._responseTime,
            sh: this._isShared,
            ch: this._cacheHeuristic,
            imm: this._immutableMinTtl,
            st: this._status,
            resh: this._resHeaders,
            rescc: this._rescc,
            m: this._method,
            u: this._url,
            h: this._host,
            a: this._noAuthorization,
            reqh: this._reqHeaders,
            reqcc: this._reqcc,
        };
    }

    /**
     * Headers for sending to the origin server to revalidate stale response.
     * Allows server to return 304 to allow reuse of the previous response.
     *
     * Hop by hop headers are always stripped.
     * Revalidation headers may be added or removed, depending on request.
     */
    revalidationHeaders(incomingReq) {
        this._assertRequestHasHeaders(incomingReq);
        const headers = this._copyWithoutHopByHopHeaders(incomingReq.headers);

        // This implementation does not understand range requests
        delete headers['if-range'];

        if (!this._requestMatches(incomingReq, true) || !this.storable()) {
            // revalidation allowed via HEAD
            // not for the same resource, or wasn't allowed to be cached anyway
            delete headers['if-none-match'];
            delete headers['if-modified-since'];
            return headers;
        }

        /* MUST send that entity-tag in any cache validation request (using If-Match or If-None-Match) if an entity-tag has been provided by the origin server. */
        if (this._resHeaders.etag) {
            headers['if-none-match'] = headers['if-none-match']
                ? `${headers['if-none-match']}, ${this._resHeaders.etag}`
                : this._resHeaders.etag;
        }

        // Clients MAY issue simple (non-subrange) GET requests with either weak validators or strong validators. Clients MUST NOT use weak validators in other forms of request.
        const forbidsWeakValidators =
            headers['accept-ranges'] ||
            headers['if-match'] ||
            headers['if-unmodified-since'] ||
            (this._method && this._method != 'GET');

        /* SHOULD send the Last-Modified value in non-subrange cache validation requests (using If-Modified-Since) if only a Last-Modified value has been provided by the origin server.
        Note: This implementation does not understand partial responses (206) */
        if (forbidsWeakValidators) {
            delete headers['if-modified-since'];

            if (headers['if-none-match']) {
                const etags = headers['if-none-match']
                    .split(/,/)
                    .filter(etag => {
                        return !/^\s*W\//.test(etag);
                    });
                if (!etags.length) {
                    delete headers['if-none-match'];
                } else {
                    headers['if-none-match'] = etags.join(',').trim();
                }
            }
        } else if (
            this._resHeaders['last-modified'] &&
            !headers['if-modified-since']
        ) {
            headers['if-modified-since'] = this._resHeaders['last-modified'];
        }

        return headers;
    }

    /**
     * Creates new CachePolicy with information combined from the previews response,
     * and the new revalidation response.
     *
     * Returns {policy, modified} where modified is a boolean indicating
     * whether the response body has been modified, and old cached body can't be used.
     *
     * @return {Object} {policy: CachePolicy, modified: Boolean}
     */
    revalidatedPolicy(request, response) {
        this._assertRequestHasHeaders(request);
        if(this._useStaleIfError() && isErrorResponse(response)) {  // I consider the revalidation request unsuccessful
          return {
            modified: false,
            matches: false,
            policy: this,
          };
        }
        if (!response || !response.headers) {
            throw Error('Response headers missing');
        }

        // These aren't going to be supported exactly, since one CachePolicy object
        // doesn't know about all the other cached objects.
        let matches = false;
        if (response.status !== undefined && response.status != 304) {
            matches = false;
        } else if (
            response.headers.etag &&
            !/^\s*W\//.test(response.headers.etag)
        ) {
            // "All of the stored responses with the same strong validator are selected.
            // If none of the stored responses contain the same strong validator,
            // then the cache MUST NOT use the new response to update any stored responses."
            matches =
                this._resHeaders.etag &&
                this._resHeaders.etag.replace(/^\s*W\//, '') ===
                    response.headers.etag;
        } else if (this._resHeaders.etag && response.headers.etag) {
            // "If the new response contains a weak validator and that validator corresponds
            // to one of the cache's stored responses,
            // then the most recent of those matching stored responses is selected for update."
            matches =
                this._resHeaders.etag.replace(/^\s*W\//, '') ===
                response.headers.etag.replace(/^\s*W\//, '');
        } else if (this._resHeaders['last-modified']) {
            matches =
                this._resHeaders['last-modified'] ===
                response.headers['last-modified'];
        } else {
            // If the new response does not include any form of validator (such as in the case where
            // a client generates an If-Modified-Since request from a source other than the Last-Modified
            // response header field), and there is only one stored response, and that stored response also
            // lacks a validator, then that stored response is selected for update.
            if (
                !this._resHeaders.etag &&
                !this._resHeaders['last-modified'] &&
                !response.headers.etag &&
                !response.headers['last-modified']
            ) {
                matches = true;
            }
        }

        if (!matches) {
            return {
                policy: new this.constructor(request, response),
                // Client receiving 304 without body, even if it's invalid/mismatched has no option
                // but to reuse a cached body. We don't have a good way to tell clients to do
                // error recovery in such case.
                modified: response.status != 304,
                matches: false,
            };
        }

        // use other header fields provided in the 304 (Not Modified) response to replace all instances
        // of the corresponding header fields in the stored response.
        const headers = {};
        for (const k in this._resHeaders) {
            headers[k] =
                k in response.headers && !excludedFromRevalidationUpdate[k]
                    ? response.headers[k]
                    : this._resHeaders[k];
        }

        const newResponse = Object.assign({}, response, {
            status: this._status,
            method: this._method,
            headers,
        });
        return {
            policy: new this.constructor(request, newResponse, {
                shared: this._isShared,
                cacheHeuristic: this._cacheHeuristic,
                immutableMinTimeToLive: this._immutableMinTtl,
            }),
            modified: false,
            matches: true,
        };
    }
};


/***/ }),

/***/ "lN8I":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const pSome = __webpack_require__("htIY");
const PCancelable = __webpack_require__("Alr0");

module.exports = (iterable, options) => {
	const anyCancelable = pSome(iterable, {...options, count: 1});

	return PCancelable.fn(async onCancel => {
		onCancel(() => {
			anyCancelable.cancel();
		});

		const [value] = await anyCancelable;
		return value;
	})();
};

module.exports.AggregateError = pSome.AggregateError;


/***/ }),

/***/ "m2VO":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const cookies_1 = __webpack_require__("gKi1");
function createLogoutUrl(settings, returnToUrl) {
    return `https://${settings.domain}/v2/logout?client_id=${settings.clientId}&returnTo=${encodeURIComponent(returnToUrl)}`;
}
function logoutHandler(settings, sessionSettings, clientProvider, store) {
    return (req, res, options) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        const session = yield store.read(req);
        let endSessionUrl;
        const returnToUrl = (options === null || options === void 0 ? void 0 : options.returnTo) || settings.postLogoutRedirectUri;
        try {
            const client = yield clientProvider();
            endSessionUrl = client.endSessionUrl({
                id_token_hint: session ? session.idToken : undefined,
                post_logout_redirect_uri: returnToUrl
            });
        }
        catch (err) {
            if (/end_session_endpoint must be configured/.exec(err)) {
                // Use default url if end_session_endpoint is not configured
                endSessionUrl = createLogoutUrl(settings, returnToUrl);
            }
            else {
                throw err;
            }
        }
        // Remove the cookies
        cookies_1.setCookies(req, res, [
            {
                name: 'a0:state',
                value: '',
                maxAge: -1
            },
            {
                name: sessionSettings.cookieName,
                value: '',
                maxAge: -1,
                path: sessionSettings.cookiePath,
                domain: sessionSettings.cookieDomain
            }
        ]);
        // Redirect to the logout endpoint.
        res.writeHead(302, {
            Location: endSessionUrl
        });
        res.end();
    });
}
exports.default = logoutHandler;
//# sourceMappingURL=logout.js.map

/***/ }),

/***/ "mRrf":
/***/ (function(module, exports) {

const isNotString = val => typeof val !== 'string' || val.length === 0

module.exports.isNotString = isNotString
module.exports.isString = function isString (Err, value, label, claim, required = false) {
  if (required && value === undefined) {
    throw new Err(`${label} is missing`, claim, 'missing')
  }

  if (value !== undefined && isNotString(value)) {
    throw new Err(`${label} must be a string`, claim, 'invalid')
  }
}


/***/ }),

/***/ "mXTs":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

module.exports = (url, opts) => {
	if (typeof url !== 'string') {
		throw new TypeError(`Expected \`url\` to be of type \`string\`, got \`${typeof url}\``);
	}

	url = url.trim();
	opts = Object.assign({https: false}, opts);

	if (/^\.*\/|^(?!localhost)\w+:/.test(url)) {
		return url;
	}

	return url.replace(/^(?!(?:\w+:)?\/\/)/, opts.https ? 'https://' : 'http://');
};


/***/ }),

/***/ "msIP":
/***/ (function(module, exports) {

module.exports = require("stream");

/***/ }),

/***/ "mw/K":
/***/ (function(module, exports) {

module.exports = require("fs");

/***/ }),

/***/ "mxNO":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const EventEmitter = __webpack_require__("/0p4");
const JSONB = __webpack_require__("F/5w");

const loadStore = opts => {
	const adapters = {
		redis: '@keyv/redis',
		mongodb: '@keyv/mongo',
		mongo: '@keyv/mongo',
		sqlite: '@keyv/sqlite',
		postgresql: '@keyv/postgres',
		postgres: '@keyv/postgres',
		mysql: '@keyv/mysql'
	};
	if (opts.adapter || opts.uri) {
		const adapter = opts.adapter || /^[^:]*/.exec(opts.uri)[0];
		return new (__webpack_require__("qIYm")(adapters[adapter]))(opts);
	}
	return new Map();
};

class Keyv extends EventEmitter {
	constructor(uri, opts) {
		super();
		this.opts = Object.assign(
			{
				namespace: 'keyv',
				serialize: JSONB.stringify,
				deserialize: JSONB.parse
			},
			(typeof uri === 'string') ? { uri } : uri,
			opts
		);

		if (!this.opts.store) {
			const adapterOpts = Object.assign({}, this.opts);
			this.opts.store = loadStore(adapterOpts);
		}

		if (typeof this.opts.store.on === 'function') {
			this.opts.store.on('error', err => this.emit('error', err));
		}

		this.opts.store.namespace = this.opts.namespace;
	}

	_getKeyPrefix(key) {
		return `${this.opts.namespace}:${key}`;
	}

	get(key) {
		key = this._getKeyPrefix(key);
		const store = this.opts.store;
		return Promise.resolve()
			.then(() => store.get(key))
			.then(data => {
				data = (typeof data === 'string') ? this.opts.deserialize(data) : data;
				if (data === undefined) {
					return undefined;
				}
				if (typeof data.expires === 'number' && Date.now() > data.expires) {
					this.delete(key);
					return undefined;
				}
				return data.value;
			});
	}

	set(key, value, ttl) {
		key = this._getKeyPrefix(key);
		if (typeof ttl === 'undefined') {
			ttl = this.opts.ttl;
		}
		if (ttl === 0) {
			ttl = undefined;
		}
		const store = this.opts.store;

		return Promise.resolve()
			.then(() => {
				const expires = (typeof ttl === 'number') ? (Date.now() + ttl) : null;
				value = { value, expires };
				return store.set(key, this.opts.serialize(value), ttl);
			})
			.then(() => true);
	}

	delete(key) {
		key = this._getKeyPrefix(key);
		const store = this.opts.store;
		return Promise.resolve()
			.then(() => store.delete(key));
	}

	clear() {
		const store = this.opts.store;
		return Promise.resolve()
			.then(() => store.clear());
	}
}

module.exports = Keyv;


/***/ }),

/***/ "n8pu":
/***/ (function(module, exports, __webpack_require__) {

const { improvedDH } = __webpack_require__("pDDt")
const { KEYOBJECT } = __webpack_require__("ehsS")
const { generateSync } = __webpack_require__("LDEB")
const { name: secp256k1 } = __webpack_require__("F/JS")
const { ECDH_DERIVE_LENGTHS } = __webpack_require__("N+nT")

const derive = __webpack_require__("kZLX")

const wrapKey = (wrap, derive, key, payload) => {
  const epk = generateSync(key.kty, key.crv)

  const derivedKey = derive(epk, key, payload)

  const result = wrap({ [KEYOBJECT]: derivedKey }, payload)
  result.header = result.header || {}
  Object.assign(result.header, { epk: { kty: key.kty, crv: key.crv, x: epk.x, y: epk.y } })

  return result
}

const unwrapKey = (unwrap, derive, key, payload, header) => {
  const { epk } = header
  const derivedKey = derive(key, epk, header)

  return unwrap({ [KEYOBJECT]: derivedKey }, payload, header)
}

module.exports = (JWA, JWK) => {
  ['ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'].forEach((jwaAlg) => {
    const kw = jwaAlg.substr(-6)
    const kwWrap = JWA.keyManagementEncrypt.get(kw)
    const kwUnwrap = JWA.keyManagementDecrypt.get(kw)
    const keylen = parseInt(jwaAlg.substr(9, 3), 10)
    ECDH_DERIVE_LENGTHS.set(jwaAlg, keylen)

    if (kwWrap && kwUnwrap) {
      JWA.keyManagementEncrypt.set(jwaAlg, wrapKey.bind(undefined, kwWrap, derive.bind(undefined, jwaAlg, keylen)))
      JWA.keyManagementDecrypt.set(jwaAlg, unwrapKey.bind(undefined, kwUnwrap, derive.bind(undefined, jwaAlg, keylen)))
      JWK.EC.deriveKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.crv !== secp256k1

      if (improvedDH) {
        JWK.OKP.deriveKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.keyObject.asymmetricKeyType.startsWith('x')
      }
    }
  })
}
module.exports.wrapKey = wrapKey
module.exports.unwrapKey = unwrapKey


/***/ }),

/***/ "nK8a":
/***/ (function(module) {

module.exports = JSON.parse("{\"_from\":\"openid-client@^3.15.0\",\"_id\":\"openid-client@3.15.10\",\"_inBundle\":false,\"_integrity\":\"sha512-C9r6/iVzNQ7aGp0krS5mFIY5nY8AH6ajYCH0Njns6AXy2fM3Khw/dY97QlaFJWW2QLhec6xfEk23LZw9EeX66Q==\",\"_location\":\"/openid-client\",\"_phantomChildren\":{},\"_requested\":{\"type\":\"range\",\"registry\":true,\"raw\":\"openid-client@^3.15.0\",\"name\":\"openid-client\",\"escapedName\":\"openid-client\",\"rawSpec\":\"^3.15.0\",\"saveSpec\":null,\"fetchSpec\":\"^3.15.0\"},\"_requiredBy\":[\"/@auth0/nextjs-auth0\"],\"_resolved\":\"https://registry.npmjs.org/openid-client/-/openid-client-3.15.10.tgz\",\"_shasum\":\"35978f629bb95fdeeb0ab7365aa4800ca0b6558e\",\"_spec\":\"openid-client@^3.15.0\",\"_where\":\"/Users/jonah/code/resumate/node_modules/@auth0/nextjs-auth0\",\"author\":{\"name\":\"Filip Skokan\",\"email\":\"panva.ip@gmail.com\"},\"bugs\":{\"url\":\"https://github.com/panva/node-openid-client/issues\"},\"bundleDependencies\":false,\"commitlint\":{\"extends\":[\"@commitlint/config-conventional\"]},\"dependencies\":{\"@types/got\":\"^9.6.9\",\"base64url\":\"^3.0.1\",\"got\":\"^9.6.0\",\"jose\":\"^1.27.1\",\"lru-cache\":\"^6.0.0\",\"make-error\":\"^1.3.6\",\"object-hash\":\"^2.0.1\",\"oidc-token-hash\":\"^5.0.0\",\"p-any\":\"^3.0.0\"},\"deprecated\":false,\"description\":\"OpenID Connect Relying Party (RP, Client) implementation for Node.js runtime, supports passportjs\",\"devDependencies\":{\"@commitlint/cli\":\"^9.1.1\",\"@commitlint/config-conventional\":\"^9.1.1\",\"@types/passport\":\"^1.0.4\",\"chai\":\"^4.2.0\",\"eslint\":\"^7.4.0\",\"eslint-config-airbnb-base\":\"^14.2.0\",\"eslint-plugin-import\":\"^2.21.2\",\"husky\":\"^4.0.0\",\"mocha\":\"^8.0.1\",\"nock\":\"^13.0.2\",\"nyc\":\"^15.1.0\",\"readable-mock-req\":\"^0.2.2\",\"sinon\":\"^9.0.0\",\"timekeeper\":\"^2.2.0\"},\"engines\":{\"node\":\"^10.13.0 || >=12.0.0\"},\"files\":[\"lib\",\"types/index.d.ts\"],\"funding\":{\"url\":\"https://github.com/sponsors/panva\"},\"homepage\":\"https://github.com/panva/node-openid-client\",\"husky\":{\"hooks\":{\"commit-msg\":\"commitlint -E HUSKY_GIT_PARAMS\"}},\"keywords\":[\"auth\",\"authentication\",\"basic\",\"certified\",\"client\",\"connect\",\"dynamic\",\"electron\",\"hybrid\",\"identity\",\"implicit\",\"oauth\",\"oauth2\",\"oidc\",\"openid\",\"passport\",\"relying party\",\"strategy\"],\"license\":\"MIT\",\"main\":\"lib/index.js\",\"name\":\"openid-client\",\"nyc\":{\"reporter\":[\"lcov\",\"text-summary\"]},\"repository\":{\"type\":\"git\",\"url\":\"git+https://github.com/panva/node-openid-client.git\"},\"scripts\":{\"coverage\":\"nyc mocha test/**/*.test.js\",\"lint\":\"eslint lib test\",\"lint-fix\":\"eslint lib test --fix\",\"lint-ts\":\"npx typescript@~3.6.0 --build types\",\"test\":\"mocha test/**/*.test.js\"},\"standard-version\":{\"scripts\":{\"postchangelog\":\"sed -i '' -e 's/### \\\\[/## [/g' CHANGELOG.md\"}},\"types\":\"types/index.d.ts\",\"version\":\"3.15.10\"}");

/***/ }),

/***/ "ngYE":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("q4ve");
const DeepEqual = __webpack_require__("1VP5");
const EscapeRegex = __webpack_require__("Ug5E");
const Utils = __webpack_require__("jvMF");


const internals = {};


module.exports = function (ref, values, options = {}) {        // options: { deep, once, only, part, symbols }

    /*
        string -> string(s)
        array -> item(s)
        object -> key(s)
        object -> object (key:value)
    */

    if (typeof values !== 'object') {
        values = [values];
    }

    Assert(!Array.isArray(values) || values.length, 'Values array cannot be empty');

    // String

    if (typeof ref === 'string') {
        return internals.string(ref, values, options);
    }

    // Array

    if (Array.isArray(ref)) {
        return internals.array(ref, values, options);
    }

    // Object

    Assert(typeof ref === 'object', 'Reference must be string or an object');
    return internals.object(ref, values, options);
};


internals.array = function (ref, values, options) {

    if (!Array.isArray(values)) {
        values = [values];
    }

    if (!ref.length) {
        return false;
    }

    if (options.only &&
        options.once &&
        ref.length !== values.length) {

        return false;
    }

    let compare;

    // Map values

    const map = new Map();
    for (const value of values) {
        if (!options.deep ||
            !value ||
            typeof value !== 'object') {

            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
        else {
            compare = compare || internals.compare(options);

            let found = false;
            for (const [key, existing] of map.entries()) {
                if (compare(key, value)) {
                    ++existing.allowed;
                    found = true;
                    break;
                }
            }

            if (!found) {
                map.set(value, { allowed: 1, hits: 0 });
            }
        }
    }

    // Lookup values

    let hits = 0;
    for (const item of ref) {
        let match;
        if (!options.deep ||
            !item ||
            typeof item !== 'object') {

            match = map.get(item);
        }
        else {
            for (const [key, existing] of map.entries()) {
                if (compare(key, item)) {
                    match = existing;
                    break;
                }
            }
        }

        if (match) {
            ++match.hits;
            ++hits;

            if (options.once &&
                match.hits > match.allowed) {

                return false;
            }
        }
    }

    // Validate results

    if (options.only &&
        hits !== ref.length) {

        return false;
    }

    for (const match of map.values()) {
        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }
    }

    return !!hits;
};


internals.object = function (ref, values, options) {

    Assert(options.once === undefined, 'Cannot use option once with object');

    const keys = Utils.keys(ref, options);
    if (!keys.length) {
        return false;
    }

    // Keys list

    if (Array.isArray(values)) {
        return internals.array(keys, values, options);
    }

    // Key value pairs

    const symbols = Object.getOwnPropertySymbols(values).filter((sym) => values.propertyIsEnumerable(sym));
    const targets = [...Object.keys(values), ...symbols];

    const compare = internals.compare(options);
    const set = new Set(targets);

    for (const key of keys) {
        if (!set.has(key)) {
            if (options.only) {
                return false;
            }

            continue;
        }

        if (!compare(values[key], ref[key])) {
            return false;
        }

        set.delete(key);
    }

    if (set.size) {
        return options.part ? set.size < targets.length : false;
    }

    return true;
};


internals.string = function (ref, values, options) {

    // Empty string

    if (ref === '') {
        return values.length === 1 && values[0] === '' ||               // '' contains ''
            !options.once && !values.some((v) => v !== '');             // '' contains multiple '' if !once
    }

    // Map values

    const map = new Map();
    const patterns = [];

    for (const value of values) {
        Assert(typeof value === 'string', 'Cannot compare string reference to non-string value');

        if (value) {
            const existing = map.get(value);
            if (existing) {
                ++existing.allowed;
            }
            else {
                map.set(value, { allowed: 1, hits: 0 });
                patterns.push(EscapeRegex(value));
            }
        }
        else if (options.once ||
            options.only) {

            return false;
        }
    }

    if (!patterns.length) {                     // Non-empty string contains unlimited empty string
        return true;
    }

    // Match patterns

    const regex = new RegExp(`(${patterns.join('|')})`, 'g');
    const leftovers = ref.replace(regex, ($0, $1) => {

        ++map.get($1).hits;
        return '';                              // Remove from string
    });

    // Validate results

    if (options.only &&
        leftovers) {

        return false;
    }

    let any = false;
    for (const match of map.values()) {
        if (match.hits) {
            any = true;
        }

        if (match.hits === match.allowed) {
            continue;
        }

        if (match.hits < match.allowed &&
            !options.part) {

            return false;
        }

        // match.hits > match.allowed

        if (options.once) {
            return false;
        }
    }

    return !!any;
};


internals.compare = function (options) {

    if (!options.deep) {
        return internals.shallow;
    }

    const hasOnly = options.only !== undefined;
    const hasPart = options.part !== undefined;

    const flags = {
        prototype: hasOnly ? options.only : hasPart ? !options.part : false,
        part: hasOnly ? !options.only : hasPart ? options.part : false
    };

    return (a, b) => DeepEqual(a, b, flags);
};


internals.shallow = function (a, b) {

    return a === b;
};


/***/ }),

/***/ "nqRS":
/***/ (function(module, exports) {

module.exports = (obj) => JSON.parse(JSON.stringify(obj));


/***/ }),

/***/ "o/Eg":
/***/ (function(module, exports) {

module.exports = (AlgorithmIdentifier, PrivateKey) => function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').use(PrivateKey)
  )
}


/***/ }),

/***/ "o156":
/***/ (function(module, exports) {

const minute = 60
const hour = minute * 60
const day = hour * 24
const week = day * 7
const year = day * 365.25

const REGEX = /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i

module.exports = (str) => {
  const matched = REGEX.exec(str)

  if (!matched) {
    throw new TypeError(`invalid time period format ("${str}")`)
  }

  const value = parseFloat(matched[1])
  const unit = matched[2].toLowerCase()

  switch (unit) {
    case 'sec':
    case 'secs':
    case 'second':
    case 'seconds':
    case 's':
      return Math.round(value)
    case 'minute':
    case 'minutes':
    case 'min':
    case 'mins':
    case 'm':
      return Math.round(value * minute)
    case 'hour':
    case 'hours':
    case 'hr':
    case 'hrs':
    case 'h':
      return Math.round(value * hour)
    case 'day':
    case 'days':
    case 'd':
      return Math.round(value * day)
    case 'week':
    case 'weeks':
    case 'w':
      return Math.round(value * week)
    case 'year':
    case 'years':
    case 'yr':
    case 'yrs':
    case 'y':
      return Math.round(value * year)
  }
}


/***/ }),

/***/ "oGTz":
/***/ (function(module, exports, __webpack_require__) {

const errors = __webpack_require__("yt7c")
const Key = __webpack_require__("//Cd")
const importKey = __webpack_require__("GhER")
const { KeyStore } = __webpack_require__("aIoy")

module.exports = (input, keyStoreAllowed = false) => {
  if (input instanceof Key) {
    return input
  }

  if (input instanceof KeyStore) {
    if (!keyStoreAllowed) {
      throw new TypeError('key argument for this operation must not be a JWKS.KeyStore instance')
    }

    return input
  }

  try {
    return importKey(input)
  } catch (err) {
    if (err instanceof errors.JOSEError && !(err instanceof errors.JWKImportFailed)) {
      throw err
    }

    let msg
    if (keyStoreAllowed) {
      msg = 'key must be an instance of a key instantiated by JWK.asKey, a valid JWK.asKey input, or a JWKS.KeyStore instance'
    } else {
      msg = 'key must be an instance of a key instantiated by JWK.asKey, or a valid JWK.asKey input'
    }

    throw new TypeError(msg)
  }
}


/***/ }),

/***/ "otTC":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Hoek = __webpack_require__("XZo7");


const internals = {
    codes: new Map([
        [100, 'Continue'],
        [101, 'Switching Protocols'],
        [102, 'Processing'],
        [200, 'OK'],
        [201, 'Created'],
        [202, 'Accepted'],
        [203, 'Non-Authoritative Information'],
        [204, 'No Content'],
        [205, 'Reset Content'],
        [206, 'Partial Content'],
        [207, 'Multi-Status'],
        [300, 'Multiple Choices'],
        [301, 'Moved Permanently'],
        [302, 'Moved Temporarily'],
        [303, 'See Other'],
        [304, 'Not Modified'],
        [305, 'Use Proxy'],
        [307, 'Temporary Redirect'],
        [400, 'Bad Request'],
        [401, 'Unauthorized'],
        [402, 'Payment Required'],
        [403, 'Forbidden'],
        [404, 'Not Found'],
        [405, 'Method Not Allowed'],
        [406, 'Not Acceptable'],
        [407, 'Proxy Authentication Required'],
        [408, 'Request Time-out'],
        [409, 'Conflict'],
        [410, 'Gone'],
        [411, 'Length Required'],
        [412, 'Precondition Failed'],
        [413, 'Request Entity Too Large'],
        [414, 'Request-URI Too Large'],
        [415, 'Unsupported Media Type'],
        [416, 'Requested Range Not Satisfiable'],
        [417, 'Expectation Failed'],
        [418, 'I\'m a teapot'],
        [422, 'Unprocessable Entity'],
        [423, 'Locked'],
        [424, 'Failed Dependency'],
        [425, 'Unordered Collection'],
        [426, 'Upgrade Required'],
        [428, 'Precondition Required'],
        [429, 'Too Many Requests'],
        [431, 'Request Header Fields Too Large'],
        [451, 'Unavailable For Legal Reasons'],
        [500, 'Internal Server Error'],
        [501, 'Not Implemented'],
        [502, 'Bad Gateway'],
        [503, 'Service Unavailable'],
        [504, 'Gateway Time-out'],
        [505, 'HTTP Version Not Supported'],
        [506, 'Variant Also Negotiates'],
        [507, 'Insufficient Storage'],
        [509, 'Bandwidth Limit Exceeded'],
        [510, 'Not Extended'],
        [511, 'Network Authentication Required']
    ])
};


module.exports = internals.Boom = class extends Error {

    constructor(message, options = {}) {

        if (message instanceof Error) {
            return internals.Boom.boomify(Hoek.clone(message), options);
        }

        const { statusCode = 500, data = null, ctor = internals.Boom } = options;
        const error = new Error(message ? message : undefined);         // Avoids settings null message
        Error.captureStackTrace(error, ctor);                           // Filter the stack to our external API
        error.data = data;
        const boom = internals.initialize(error, statusCode);

        Object.defineProperty(boom, 'typeof', { value: ctor });

        if (options.decorate) {
            Object.assign(boom, options.decorate);
        }

        return boom;
    }

    static [Symbol.hasInstance](instance) {

        return internals.Boom.isBoom(instance);
    }

    static isBoom(err) {

        return err instanceof Error && !!err.isBoom;
    }

    static boomify(err, options) {

        Hoek.assert(err instanceof Error, 'Cannot wrap non-Error object');

        options = options || {};

        if (options.data !== undefined) {
            err.data = options.data;
        }

        if (options.decorate) {
            Object.assign(err, options.decorate);
        }

        if (!err.isBoom) {
            return internals.initialize(err, options.statusCode || 500, options.message);
        }

        if (options.override === false ||                           // Defaults to true
            !options.statusCode && !options.message) {

            return err;
        }

        return internals.initialize(err, options.statusCode || err.output.statusCode, options.message);
    }

    // 4xx Client Errors

    static badRequest(message, data) {

        return new internals.Boom(message, { statusCode: 400, data, ctor: internals.Boom.badRequest });
    }

    static unauthorized(message, scheme, attributes) {          // Or (message, wwwAuthenticate[])

        const err = new internals.Boom(message, { statusCode: 401, ctor: internals.Boom.unauthorized });

        // function (message)

        if (!scheme) {
            return err;
        }

        // function (message, wwwAuthenticate[])

        if (typeof scheme !== 'string') {
            err.output.headers['WWW-Authenticate'] = scheme.join(', ');
            return err;
        }

        // function (message, scheme, attributes)

        let wwwAuthenticate = `${scheme} `;

        if (attributes ||
            message) {

            err.output.payload.attributes = {};
        }

        if (attributes) {
            if (typeof attributes === 'string') {
                wwwAuthenticate += Hoek.escapeHeaderAttribute(attributes);
                err.output.payload.attributes = attributes;
            }
            else {
                wwwAuthenticate += Object.keys(attributes).map((name) => {

                    let value = attributes[name];
                    if (value === null ||
                        value === undefined) {

                        value = '';
                    }

                    err.output.payload.attributes[name] = value;
                    return `${name}="${Hoek.escapeHeaderAttribute(value.toString())}"`;
                })
                    .join(', ');
            }
        }

        if (message) {
            if (attributes) {
                wwwAuthenticate += ', ';
            }

            wwwAuthenticate += `error="${Hoek.escapeHeaderAttribute(message)}"`;
            err.output.payload.attributes.error = message;
        }
        else {
            err.isMissing = true;
        }

        err.output.headers['WWW-Authenticate'] = wwwAuthenticate;
        return err;
    }

    static paymentRequired(message, data) {

        return new internals.Boom(message, { statusCode: 402, data, ctor: internals.Boom.paymentRequired });
    }

    static forbidden(message, data) {

        return new internals.Boom(message, { statusCode: 403, data, ctor: internals.Boom.forbidden });
    }

    static notFound(message, data) {

        return new internals.Boom(message, { statusCode: 404, data, ctor: internals.Boom.notFound });
    }

    static methodNotAllowed(message, data, allow) {

        const err = new internals.Boom(message, { statusCode: 405, data, ctor: internals.Boom.methodNotAllowed });

        if (typeof allow === 'string') {
            allow = [allow];
        }

        if (Array.isArray(allow)) {
            err.output.headers.Allow = allow.join(', ');
        }

        return err;
    }

    static notAcceptable(message, data) {

        return new internals.Boom(message, { statusCode: 406, data, ctor: internals.Boom.notAcceptable });
    }

    static proxyAuthRequired(message, data) {

        return new internals.Boom(message, { statusCode: 407, data, ctor: internals.Boom.proxyAuthRequired });
    }

    static clientTimeout(message, data) {

        return new internals.Boom(message, { statusCode: 408, data, ctor: internals.Boom.clientTimeout });
    }

    static conflict(message, data) {

        return new internals.Boom(message, { statusCode: 409, data, ctor: internals.Boom.conflict });
    }

    static resourceGone(message, data) {

        return new internals.Boom(message, { statusCode: 410, data, ctor: internals.Boom.resourceGone });
    }

    static lengthRequired(message, data) {

        return new internals.Boom(message, { statusCode: 411, data, ctor: internals.Boom.lengthRequired });
    }

    static preconditionFailed(message, data) {

        return new internals.Boom(message, { statusCode: 412, data, ctor: internals.Boom.preconditionFailed });
    }

    static entityTooLarge(message, data) {

        return new internals.Boom(message, { statusCode: 413, data, ctor: internals.Boom.entityTooLarge });
    }

    static uriTooLong(message, data) {

        return new internals.Boom(message, { statusCode: 414, data, ctor: internals.Boom.uriTooLong });
    }

    static unsupportedMediaType(message, data) {

        return new internals.Boom(message, { statusCode: 415, data, ctor: internals.Boom.unsupportedMediaType });
    }

    static rangeNotSatisfiable(message, data) {

        return new internals.Boom(message, { statusCode: 416, data, ctor: internals.Boom.rangeNotSatisfiable });
    }

    static expectationFailed(message, data) {

        return new internals.Boom(message, { statusCode: 417, data, ctor: internals.Boom.expectationFailed });
    }

    static teapot(message, data) {

        return new internals.Boom(message, { statusCode: 418, data, ctor: internals.Boom.teapot });
    }

    static badData(message, data) {

        return new internals.Boom(message, { statusCode: 422, data, ctor: internals.Boom.badData });
    }

    static locked(message, data) {

        return new internals.Boom(message, { statusCode: 423, data, ctor: internals.Boom.locked });
    }

    static failedDependency(message, data) {

        return new internals.Boom(message, { statusCode: 424, data, ctor: internals.Boom.failedDependency });
    }

    static preconditionRequired(message, data) {

        return new internals.Boom(message, { statusCode: 428, data, ctor: internals.Boom.preconditionRequired });
    }

    static tooManyRequests(message, data) {

        return new internals.Boom(message, { statusCode: 429, data, ctor: internals.Boom.tooManyRequests });
    }

    static illegal(message, data) {

        return new internals.Boom(message, { statusCode: 451, data, ctor: internals.Boom.illegal });
    }

    // 5xx Server Errors

    static internal(message, data, statusCode = 500) {

        return internals.serverError(message, data, statusCode, internals.Boom.internal);
    }

    static notImplemented(message, data) {

        return internals.serverError(message, data, 501, internals.Boom.notImplemented);
    }

    static badGateway(message, data) {

        return internals.serverError(message, data, 502, internals.Boom.badGateway);
    }

    static serverUnavailable(message, data) {

        return internals.serverError(message, data, 503, internals.Boom.serverUnavailable);
    }

    static gatewayTimeout(message, data) {

        return internals.serverError(message, data, 504, internals.Boom.gatewayTimeout);
    }

    static badImplementation(message, data) {

        const err = internals.serverError(message, data, 500, internals.Boom.badImplementation);
        err.isDeveloperError = true;
        return err;
    }
};


internals.Boom.default = internals.Boom;        // Support ES6 module import


internals.initialize = function (err, statusCode, message) {

    const numberCode = parseInt(statusCode, 10);
    Hoek.assert(!isNaN(numberCode) && numberCode >= 400, 'First argument must be a number (400+):', statusCode);

    err.isBoom = true;
    err.isServer = numberCode >= 500;

    if (!err.hasOwnProperty('data')) {
        err.data = null;
    }

    err.output = {
        statusCode: numberCode,
        payload: {},
        headers: {}
    };

    Object.defineProperty(err, 'reformat', { value: internals.reformat });

    if (!message &&
        !err.message) {

        err.reformat();
        message = err.output.payload.error;
    }

    if (message) {
        const props = Object.getOwnPropertyDescriptor(err, 'message') || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(err), 'message');
        Hoek.assert(props.configurable && !props.get, 'The error is not compatible with boom');

        err.message = message + (err.message ? ': ' + err.message : '');
        err.output.payload.message = err.message;
    }

    err.reformat();
    return err;
};


internals.reformat = function (debug = false) {

    this.output.payload.statusCode = this.output.statusCode;
    this.output.payload.error = internals.codes.get(this.output.statusCode) || 'Unknown';

    if (this.output.statusCode === 500 && debug !== true) {
        this.output.payload.message = 'An internal server error occurred';              // Hide actual error from user
    }
    else if (this.message) {
        this.output.payload.message = this.message;
    }
};


internals.serverError = function (message, data, statusCode, ctor) {

    if (data instanceof Error &&
        !data.isBoom) {

        return internals.Boom.boomify(data, { statusCode, message });
    }

    return new internals.Boom(message, { statusCode, data, ctor });
};


/***/ }),

/***/ "oyvS":
/***/ (function(module, exports) {

module.exports = require("path");

/***/ }),

/***/ "p9XZ":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Stringify = __webpack_require__("PX5Q");


const internals = {};


module.exports = class extends Error {

    constructor(args) {

        const msgs = args
            .filter((arg) => arg !== '')
            .map((arg) => {

                return typeof arg === 'string' ? arg : arg instanceof Error ? arg.message : Stringify(arg);
            });

        super(msgs.join(' ') || 'Unknown error');

        if (typeof Error.captureStackTrace === 'function') {            // $lab:coverage:ignore$
            Error.captureStackTrace(this, exports.assert);
        }
    }
};


/***/ }),

/***/ "pBmY":
/***/ (function(module, exports) {

module.exports = AlgorithmIdentifier => function () {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('publicKey').bitstr()
  )
}


/***/ }),

/***/ "pDDt":
/***/ (function(module, exports, __webpack_require__) {

const { diffieHellman, KeyObject, sign, verify } = __webpack_require__("PJMN")

const [major, minor] = process.version.substr(1).split('.').map(x => parseInt(x, 10))

module.exports = {
  oaepHashSupported: major > 12 || (major === 12 && minor >= 9),
  keyObjectSupported: !!KeyObject && major >= 12,
  edDSASupported: !!sign && !!verify,
  dsaEncodingSupported: major > 13 || (major === 13 && minor >= 2) || (major === 12 && minor >= 16),
  improvedDH: !!diffieHellman
}


/***/ }),

/***/ "q1Jy":
/***/ (function(module, exports, __webpack_require__) {

var once = __webpack_require__("VmuJ");

var noop = function() {};

var isRequest = function(stream) {
	return stream.setHeader && typeof stream.abort === 'function';
};

var isChildProcess = function(stream) {
	return stream.stdio && Array.isArray(stream.stdio) && stream.stdio.length === 3
};

var eos = function(stream, opts, callback) {
	if (typeof opts === 'function') return eos(stream, null, opts);
	if (!opts) opts = {};

	callback = once(callback || noop);

	var ws = stream._writableState;
	var rs = stream._readableState;
	var readable = opts.readable || (opts.readable !== false && stream.readable);
	var writable = opts.writable || (opts.writable !== false && stream.writable);
	var cancelled = false;

	var onlegacyfinish = function() {
		if (!stream.writable) onfinish();
	};

	var onfinish = function() {
		writable = false;
		if (!readable) callback.call(stream);
	};

	var onend = function() {
		readable = false;
		if (!writable) callback.call(stream);
	};

	var onexit = function(exitCode) {
		callback.call(stream, exitCode ? new Error('exited with error code: ' + exitCode) : null);
	};

	var onerror = function(err) {
		callback.call(stream, err);
	};

	var onclose = function() {
		process.nextTick(onclosenexttick);
	};

	var onclosenexttick = function() {
		if (cancelled) return;
		if (readable && !(rs && (rs.ended && !rs.destroyed))) return callback.call(stream, new Error('premature close'));
		if (writable && !(ws && (ws.ended && !ws.destroyed))) return callback.call(stream, new Error('premature close'));
	};

	var onrequest = function() {
		stream.req.on('finish', onfinish);
	};

	if (isRequest(stream)) {
		stream.on('complete', onfinish);
		stream.on('abort', onclose);
		if (stream.req) onrequest();
		else stream.on('request', onrequest);
	} else if (writable && !ws) { // legacy streams
		stream.on('end', onlegacyfinish);
		stream.on('close', onlegacyfinish);
	}

	if (isChildProcess(stream)) stream.on('exit', onexit);

	stream.on('end', onend);
	stream.on('finish', onfinish);
	if (opts.error !== false) stream.on('error', onerror);
	stream.on('close', onclose);

	return function() {
		cancelled = true;
		stream.removeListener('complete', onfinish);
		stream.removeListener('abort', onclose);
		stream.removeListener('request', onrequest);
		if (stream.req) stream.req.removeListener('finish', onfinish);
		stream.removeListener('end', onlegacyfinish);
		stream.removeListener('close', onlegacyfinish);
		stream.removeListener('finish', onfinish);
		stream.removeListener('exit', onexit);
		stream.removeListener('end', onend);
		stream.removeListener('error', onerror);
		stream.removeListener('close', onclose);
	};
};

module.exports = eos;


/***/ }),

/***/ "q2Us":
/***/ (function(module, exports, __webpack_require__) {

const { pbkdf2Sync: pbkdf2, randomBytes } = __webpack_require__("PJMN")

const { KEYOBJECT } = __webpack_require__("ehsS")
const base64url = __webpack_require__("Xab3")

const SALT_LENGTH = 16
const NULL_BUFFER = Buffer.alloc(1, 0)

const concatSalt = (alg, p2s) => {
  return Buffer.concat([
    Buffer.from(alg, 'utf8'),
    NULL_BUFFER,
    p2s
  ])
}

const wrapKey = (keylen, sha, concat, wrap, { [KEYOBJECT]: keyObject }, payload) => {
  // Note that if password-based encryption is used for multiple
  // recipients, it is expected that each recipient use different values
  // for the PBES2 parameters "p2s" and "p2c".
  // here we generate p2c between 2048 and 4096 and random p2s
  const p2c = Math.floor((Math.random() * 2049) + 2048)
  const p2s = randomBytes(SALT_LENGTH)
  const salt = concat(p2s)

  const derivedKey = pbkdf2(keyObject.export(), salt, p2c, keylen, sha)

  const result = wrap({ [KEYOBJECT]: derivedKey }, payload)
  result.header = result.header || {}
  Object.assign(result.header, { p2c, p2s: base64url.encodeBuffer(p2s) })

  return result
}

const unwrapKey = (keylen, sha, concat, unwrap, { [KEYOBJECT]: keyObject }, payload, header) => {
  const { p2s, p2c } = header
  const salt = concat(p2s)
  const derivedKey = pbkdf2(keyObject.export(), salt, p2c, keylen, sha)
  return unwrap({ [KEYOBJECT]: derivedKey }, payload, header)
}

module.exports = (JWA, JWK) => {
  ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'].forEach((jwaAlg) => {
    const kw = jwaAlg.substr(-6)
    const kwWrap = JWA.keyManagementEncrypt.get(kw)
    const kwUnwrap = JWA.keyManagementDecrypt.get(kw)
    const keylen = parseInt(jwaAlg.substr(13, 3), 10) / 8
    const sha = `sha${jwaAlg.substr(8, 3)}`

    if (kwWrap && kwUnwrap) {
      JWA.keyManagementEncrypt.set(jwaAlg, wrapKey.bind(undefined, keylen, sha, concatSalt.bind(undefined, jwaAlg), kwWrap))
      JWA.keyManagementDecrypt.set(jwaAlg, unwrapKey.bind(undefined, keylen, sha, concatSalt.bind(undefined, jwaAlg), kwUnwrap))
      JWK.oct.deriveKey[jwaAlg] = key => key.use === 'enc' || key.use === undefined
    }
  })
}


/***/ }),

/***/ "q4ve":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const AssertError = __webpack_require__("FURP");

const internals = {};


module.exports = function (condition, ...args) {

    if (condition) {
        return;
    }

    if (args.length === 1 &&
        args[0] instanceof Error) {

        throw args[0];
    }

    throw new AssertError(args);
};


/***/ }),

/***/ "qI4P":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Ignore = __webpack_require__("gJmk");


const internals = {};


module.exports = function () {

    return new Promise(Ignore);         // $lab:coverage:ignore$
};


/***/ }),

/***/ "qIYm":
/***/ (function(module, exports) {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = function() { return []; };
webpackEmptyContext.resolve = webpackEmptyContext;
module.exports = webpackEmptyContext;
webpackEmptyContext.id = "qIYm";

/***/ }),

/***/ "qQzh":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const iron_1 = tslib_1.__importDefault(__webpack_require__("ClL1"));
const session_1 = tslib_1.__importDefault(__webpack_require__("gt9x"));
const cookies_1 = __webpack_require__("gKi1");
class CookieSessionStore {
    constructor(settings) {
        this.settings = settings;
    }
    /**
     * Read the session from the cookie.
     * @param req HTTP request
     */
    read(req) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!req) {
                throw new Error('Request is not available');
            }
            const { cookieSecret, cookieName } = this.settings;
            const cookies = cookies_1.parseCookies(req);
            const cookie = cookies[cookieName];
            if (!cookie || cookie.length === 0) {
                return null;
            }
            const unsealed = yield iron_1.default.unseal(cookies[cookieName], cookieSecret, iron_1.default.defaults);
            if (!unsealed) {
                return null;
            }
            return unsealed;
        });
    }
    /**
     * Write the session to the cookie.
     * @param req HTTP request
     */
    save(req, res, session) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!res) {
                throw new Error('Response is not available');
            }
            if (!req) {
                throw new Error('Request is not available');
            }
            const { cookieSecret, cookieName, cookiePath, cookieLifetime, cookieDomain, cookieSameSite } = this.settings;
            const { idToken, accessToken, accessTokenExpiresAt, accessTokenScope, refreshToken, user, createdAt } = session;
            const persistedSession = new session_1.default(user, createdAt);
            if (this.settings.storeIdToken && idToken) {
                persistedSession.idToken = idToken;
            }
            if (this.settings.storeAccessToken && accessToken) {
                persistedSession.accessToken = accessToken;
                persistedSession.accessTokenScope = accessTokenScope;
                persistedSession.accessTokenExpiresAt = accessTokenExpiresAt;
            }
            if (this.settings.storeRefreshToken && refreshToken) {
                persistedSession.refreshToken = refreshToken;
            }
            const encryptedSession = yield iron_1.default.seal(persistedSession, cookieSecret, iron_1.default.defaults);
            cookies_1.setCookie(req, res, {
                name: cookieName,
                value: encryptedSession,
                path: cookiePath,
                maxAge: cookieLifetime,
                domain: cookieDomain,
                sameSite: cookieSameSite
            });
            return persistedSession;
        });
    }
}
exports.default = CookieSessionStore;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "qRSN":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("q4ve");
const Clone = __webpack_require__("W5Ll");
const Merge = __webpack_require__("Fssn");
const Utils = __webpack_require__("jvMF");


const internals = {};


module.exports = function (defaults, source, options = {}) {

    Assert(defaults && typeof defaults === 'object', 'Invalid defaults value: must be an object');
    Assert(!source || source === true || typeof source === 'object', 'Invalid source value: must be true, falsy or an object');
    Assert(typeof options === 'object', 'Invalid options: must be an object');

    if (!source) {                                                  // If no source, return null
        return null;
    }

    if (options.shallow) {
        return internals.applyToDefaultsWithShallow(defaults, source, options);
    }

    const copy = Clone(defaults);

    if (source === true) {                                          // If source is set to true, use defaults
        return copy;
    }

    const nullOverride = options.nullOverride !== undefined ? options.nullOverride : false;
    return Merge(copy, source, { nullOverride, mergeArrays: false });
};


internals.applyToDefaultsWithShallow = function (defaults, source, options) {

    const keys = options.shallow;
    Assert(Array.isArray(keys), 'Invalid keys');

    options = Object.assign({}, options);
    options.shallow = false;

    const copy = Clone(defaults, { shallow: keys });

    if (source === true) {                                                      // If source is set to true, use defaults
        return copy;
    }

    const storage = Utils.store(source, keys);                              // Move shallow copy items to storage
    Merge(copy, source, { mergeArrays: false, nullOverride: false });   // Deep copy the rest
    Utils.restore(copy, source, storage);                                   // Shallow copy the stored items and restore
    return copy;
};


/***/ }),

/***/ "qSBP":
/***/ (function(module, exports, __webpack_require__) {

const { inspect } = __webpack_require__("jK02")

const Key = __webpack_require__("//Cd")

class NoneKey extends Key {
  constructor () {
    super({ type: 'unsecured' }, { alg: 'none' })
    Object.defineProperties(this, {
      kid: { value: undefined },
      kty: { value: undefined },
      thumbprint: { value: undefined },
      toJWK: { value: undefined },
      toPEM: { value: undefined }
    })
  }

  /* c8 ignore next 3 */
  [inspect.custom] () {
    return 'None {}'
  }

  algorithms (operation) {
    switch (operation) {
      case 'sign':
      case 'verify':
      case undefined:
        return new Set(['none'])
      default:
        return new Set()
    }
  }
}

module.exports = new NoneKey()


/***/ }),

/***/ "qXE0":
/***/ (function(module, exports, __webpack_require__) {

const verify = __webpack_require__("BOd6")

module.exports = {
  IdToken: { verify: (token, key, options) => verify(token, key, { ...options, profile: 'id_token' }) },
  LogoutToken: { verify: (token, key, options) => verify(token, key, { ...options, profile: 'logout_token' }) },
  AccessToken: { verify: (token, key, options) => verify(token, key, { ...options, profile: 'at+JWT' }) }
}


/***/ }),

/***/ "qsvm":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// We define these manually to ensure they're always copied
// even if they would move up the prototype chain
// https://nodejs.org/api/http.html#http_class_http_incomingmessage
const knownProps = [
	'destroy',
	'setTimeout',
	'socket',
	'headers',
	'trailers',
	'rawHeaders',
	'statusCode',
	'httpVersion',
	'httpVersionMinor',
	'httpVersionMajor',
	'rawTrailers',
	'statusMessage'
];

module.exports = (fromStream, toStream) => {
	const fromProps = new Set(Object.keys(fromStream).concat(knownProps));

	for (const prop of fromProps) {
		// Don't overwrite existing properties
		if (prop in toStream) {
			continue;
		}

		toStream[prop] = typeof fromStream[prop] === 'function' ? fromStream[prop].bind(fromStream) : fromStream[prop];
	}
};


/***/ }),

/***/ "qwdb":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function initAuth0(settings) {
    const isBrowser = typeof window !== 'undefined' || false;
    if (isBrowser) {
        return __webpack_require__("6gLP").default(settings);
    }
    return __webpack_require__("+du+").default(settings);
}
exports.initAuth0 = initAuth0;
/**
 * @deprecated useAuth0 has been deprecated in favor of initAuth0
 */
exports.useAuth0 = initAuth0;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "sJmi":
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(__dirname) {module.exports=function(e,r){"use strict";var t={};function __webpack_require__(r){if(t[r]){return t[r].exports}var n=t[r]={i:r,l:false,exports:{}};e[r].call(n.exports,n,n.exports,__webpack_require__);n.l=true;return n.exports}__webpack_require__.ab=__dirname+"/";function startup(){return __webpack_require__(197)}return startup()}({14:function(e,r,t){var n=t(704).Buffer;var i=t(413);var a=t(669);function DataStream(e){this.buffer=null;this.writable=true;this.readable=true;if(!e){this.buffer=n.alloc(0);return this}if(typeof e.pipe==="function"){this.buffer=n.alloc(0);e.pipe(this);return this}if(e.length||typeof e==="object"){this.buffer=e;this.writable=false;process.nextTick(function(){this.emit("end",e);this.readable=false;this.emit("close")}.bind(this));return this}throw new TypeError("Unexpected data type ("+typeof e+")")}a.inherits(DataStream,i);DataStream.prototype.write=function write(e){this.buffer=n.concat([this.buffer,n.from(e)]);this.emit("data",e)};DataStream.prototype.end=function end(e){if(e)this.write(e);this.emit("end",e);this.emit("close");this.writable=false;this.readable=false};e.exports=DataStream},24:function(e,r,t){var n=t(704).Buffer;var i=t(14);var a=t(572);var o=t(413);var s=t(586);var u=t(669);var f=/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;function isObject(e){return Object.prototype.toString.call(e)==="[object Object]"}function safeJsonParse(e){if(isObject(e))return e;try{return JSON.parse(e)}catch(e){return undefined}}function headerFromJWS(e){var r=e.split(".",1)[0];return safeJsonParse(n.from(r,"base64").toString("binary"))}function securedInputFromJWS(e){return e.split(".",2).join(".")}function signatureFromJWS(e){return e.split(".")[2]}function payloadFromJWS(e,r){r=r||"utf8";var t=e.split(".")[1];return n.from(t,"base64").toString(r)}function isValidJws(e){return f.test(e)&&!!headerFromJWS(e)}function jwsVerify(e,r,t){if(!r){var n=new Error("Missing algorithm parameter for jws.verify");n.code="MISSING_ALGORITHM";throw n}e=s(e);var i=signatureFromJWS(e);var o=securedInputFromJWS(e);var u=a(r);return u.verify(o,i,t)}function jwsDecode(e,r){r=r||{};e=s(e);if(!isValidJws(e))return null;var t=headerFromJWS(e);if(!t)return null;var n=payloadFromJWS(e);if(t.typ==="JWT"||r.json)n=JSON.parse(n,r.encoding);return{header:t,payload:n,signature:signatureFromJWS(e)}}function VerifyStream(e){e=e||{};var r=e.secret||e.publicKey||e.key;var t=new i(r);this.readable=true;this.algorithm=e.algorithm;this.encoding=e.encoding;this.secret=this.publicKey=this.key=t;this.signature=new i(e.signature);this.secret.once("close",function(){if(!this.signature.writable&&this.readable)this.verify()}.bind(this));this.signature.once("close",function(){if(!this.secret.writable&&this.readable)this.verify()}.bind(this))}u.inherits(VerifyStream,o);VerifyStream.prototype.verify=function verify(){try{var e=jwsVerify(this.signature.buffer,this.algorithm,this.key.buffer);var r=jwsDecode(this.signature.buffer,this.encoding);this.emit("done",e,r);this.emit("data",e);this.emit("end");this.readable=false;return e}catch(e){this.readable=false;this.emit("error",e);this.emit("close")}};VerifyStream.decode=jwsDecode;VerifyStream.isValid=isValidJws;VerifyStream.verify=jwsVerify;e.exports=VerifyStream},51:function(e,r,t){var n=t(105);e.exports=function(e,r){r=r||{};var t=n.decode(e,r);if(!t){return null}var i=t.payload;if(typeof i==="string"){try{var a=JSON.parse(i);if(a!==null&&typeof a==="object"){i=a}}catch(e){}}if(r.complete===true){return{header:t.header,payload:i,signature:t.signature}}return i}},91:function(e,r,t){var n=t(821);var i=function(e,r){n.call(this,e);this.name="TokenExpiredError";this.expiredAt=r};i.prototype=Object.create(n.prototype);i.prototype.constructor=i;e.exports=i},105:function(e,r,t){var n=t(717);var i=t(24);var a=["HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"];r.ALGORITHMS=a;r.sign=n.sign;r.verify=i.verify;r.decode=i.decode;r.isValid=i.isValid;r.createSign=function createSign(e){return new n(e)};r.createVerify=function createVerify(e){return new i(e)}},110:function(e,r,t){var n=t(821);var i=t(487);var a=t(91);var o=t(51);var s=t(686);var u=t(284);var f=t(105);var c=["RS256","RS384","RS512","ES256","ES384","ES512"];var p=["RS256","RS384","RS512"];var l=["HS256","HS384","HS512"];if(u){c.splice(3,0,"PS256","PS384","PS512");p.splice(3,0,"PS256","PS384","PS512")}e.exports=function(e,r,t,u){if(typeof t==="function"&&!u){u=t;t={}}if(!t){t={}}t=Object.assign({},t);var v;if(u){v=u}else{v=function(e,r){if(e)throw e;return r}}if(t.clockTimestamp&&typeof t.clockTimestamp!=="number"){return v(new n("clockTimestamp must be a number"))}if(t.nonce!==undefined&&(typeof t.nonce!=="string"||t.nonce.trim()==="")){return v(new n("nonce must be a non-empty string"))}var y=t.clockTimestamp||Math.floor(Date.now()/1e3);if(!e){return v(new n("jwt must be provided"))}if(typeof e!=="string"){return v(new n("jwt must be a string"))}var d=e.split(".");if(d.length!==3){return v(new n("jwt malformed"))}var b;try{b=o(e,{complete:true})}catch(e){return v(e)}if(!b){return v(new n("invalid token"))}var h=b.header;var g;if(typeof r==="function"){if(!u){return v(new n("verify must be called asynchronous if secret or public key is provided as a callback"))}g=r}else{g=function(e,t){return t(null,r)}}return g(h,function(r,o){if(r){return v(new n("error in secret or public key callback: "+r.message))}var u=d[2].trim()!=="";if(!u&&o){return v(new n("jwt signature is required"))}if(u&&!o){return v(new n("secret or public key must be provided"))}if(!u&&!t.algorithms){t.algorithms=["none"]}if(!t.algorithms){t.algorithms=~o.toString().indexOf("BEGIN CERTIFICATE")||~o.toString().indexOf("BEGIN PUBLIC KEY")?c:~o.toString().indexOf("BEGIN RSA PUBLIC KEY")?p:l}if(!~t.algorithms.indexOf(b.header.alg)){return v(new n("invalid algorithm"))}var g;try{g=f.verify(e,b.header.alg,o)}catch(e){return v(e)}if(!g){return v(new n("invalid signature"))}var m=b.payload;if(typeof m.nbf!=="undefined"&&!t.ignoreNotBefore){if(typeof m.nbf!=="number"){return v(new n("invalid nbf value"))}if(m.nbf>y+(t.clockTolerance||0)){return v(new i("jwt not active",new Date(m.nbf*1e3)))}}if(typeof m.exp!=="undefined"&&!t.ignoreExpiration){if(typeof m.exp!=="number"){return v(new n("invalid exp value"))}if(y>=m.exp+(t.clockTolerance||0)){return v(new a("jwt expired",new Date(m.exp*1e3)))}}if(t.audience){var S=Array.isArray(t.audience)?t.audience:[t.audience];var w=Array.isArray(m.aud)?m.aud:[m.aud];var j=w.some(function(e){return S.some(function(r){return r instanceof RegExp?r.test(e):r===e})});if(!j){return v(new n("jwt audience invalid. expected: "+S.join(" or ")))}}if(t.issuer){var x=typeof t.issuer==="string"&&m.iss!==t.issuer||Array.isArray(t.issuer)&&t.issuer.indexOf(m.iss)===-1;if(x){return v(new n("jwt issuer invalid. expected: "+t.issuer))}}if(t.subject){if(m.sub!==t.subject){return v(new n("jwt subject invalid. expected: "+t.subject))}}if(t.jwtid){if(m.jti!==t.jwtid){return v(new n("jwt jwtid invalid. expected: "+t.jwtid))}}if(t.nonce){if(m.nonce!==t.nonce){return v(new n("jwt nonce invalid. expected: "+t.nonce))}}if(t.maxAge){if(typeof m.iat!=="number"){return v(new n("iat required when maxAge is specified"))}var E=s(t.maxAge,m.iat);if(typeof E==="undefined"){return v(new n('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'))}if(y>=E+(t.clockTolerance||0)){return v(new a("maxAge exceeded",new Date(E*1e3)))}}if(t.complete===true){var O=b.signature;return v(null,{header:h,payload:m,signature:O})}return v(null,m)})}},138:function(e){var r="[object Object]";function isHostObject(e){var r=false;if(e!=null&&typeof e.toString!="function"){try{r=!!(e+"")}catch(e){}}return r}function overArg(e,r){return function(t){return e(r(t))}}var t=Function.prototype,n=Object.prototype;var i=t.toString;var a=n.hasOwnProperty;var o=i.call(Object);var s=n.toString;var u=overArg(Object.getPrototypeOf,Object);function isObjectLike(e){return!!e&&typeof e=="object"}function isPlainObject(e){if(!isObjectLike(e)||s.call(e)!=r||isHostObject(e)){return false}var t=u(e);if(t===null){return true}var n=a.call(t,"constructor")&&t.constructor;return typeof n=="function"&&n instanceof n&&i.call(n)==o}e.exports=isPlainObject},197:function(e,r,t){e.exports={decode:t(51),verify:t(110),sign:t(428),JsonWebTokenError:t(821),NotBeforeError:t(487),TokenExpiredError:t(91)}},284:function(e,r,t){var n=t(519);e.exports=n.satisfies(process.version,"^6.12.0 || >=8.0.0")},293:function(e){e.exports=__webpack_require__("NkYg")},337:function(e){var r="Expected a function";var t=1/0,n=1.7976931348623157e308,i=0/0;var a="[object Symbol]";var o=/^\s+|\s+$/g;var s=/^[-+]0x[0-9a-f]+$/i;var u=/^0b[01]+$/i;var f=/^0o[0-7]+$/i;var c=parseInt;var p=Object.prototype;var l=p.toString;function before(e,t){var n;if(typeof t!="function"){throw new TypeError(r)}e=toInteger(e);return function(){if(--e>0){n=t.apply(this,arguments)}if(e<=1){t=undefined}return n}}function once(e){return before(2,e)}function isObject(e){var r=typeof e;return!!e&&(r=="object"||r=="function")}function isObjectLike(e){return!!e&&typeof e=="object"}function isSymbol(e){return typeof e=="symbol"||isObjectLike(e)&&l.call(e)==a}function toFinite(e){if(!e){return e===0?e:0}e=toNumber(e);if(e===t||e===-t){var r=e<0?-1:1;return r*n}return e===e?e:0}function toInteger(e){var r=toFinite(e),t=r%1;return r===r?t?r-t:r:0}function toNumber(e){if(typeof e=="number"){return e}if(isSymbol(e)){return i}if(isObject(e)){var r=typeof e.valueOf=="function"?e.valueOf():e;e=isObject(r)?r+"":r}if(typeof e!="string"){return e===0?e:+e}e=e.replace(o,"");var t=u.test(e);return t||f.test(e)?c(e.slice(2),t?2:8):s.test(e)?i:+e}e.exports=once},339:function(e){var r=1/0,t=1.7976931348623157e308,n=0/0;var i="[object Symbol]";var a=/^\s+|\s+$/g;var o=/^[-+]0x[0-9a-f]+$/i;var s=/^0b[01]+$/i;var u=/^0o[0-7]+$/i;var f=parseInt;var c=Object.prototype;var p=c.toString;function isInteger(e){return typeof e=="number"&&e==toInteger(e)}function isObject(e){var r=typeof e;return!!e&&(r=="object"||r=="function")}function isObjectLike(e){return!!e&&typeof e=="object"}function isSymbol(e){return typeof e=="symbol"||isObjectLike(e)&&p.call(e)==i}function toFinite(e){if(!e){return e===0?e:0}e=toNumber(e);if(e===r||e===-r){var n=e<0?-1:1;return n*t}return e===e?e:0}function toInteger(e){var r=toFinite(e),t=r%1;return r===r?t?r-t:r:0}function toNumber(e){if(typeof e=="number"){return e}if(isSymbol(e)){return n}if(isObject(e)){var r=typeof e.valueOf=="function"?e.valueOf():e;e=isObject(r)?r+"":r}if(typeof e!="string"){return e===0?e:+e}e=e.replace(a,"");var t=s.test(e);return t||u.test(e)?f(e.slice(2),t?2:8):o.test(e)?n:+e}e.exports=isInteger},358:function(e){"use strict";function getParamSize(e){var r=(e/8|0)+(e%8===0?0:1);return r}var r={ES256:getParamSize(256),ES384:getParamSize(384),ES512:getParamSize(521)};function getParamBytesForAlg(e){var t=r[e];if(t){return t}throw new Error('Unknown algorithm "'+e+'"')}e.exports=getParamBytesForAlg},413:function(e){e.exports=__webpack_require__("msIP")},417:function(e){e.exports=__webpack_require__("PJMN")},428:function(e,r,t){var n=t(686);var i=t(284);var a=t(105);var o=t(473);var s=t(449);var u=t(339);var f=t(958);var c=t(138);var p=t(665);var l=t(337);var v=["RS256","RS384","RS512","ES256","ES384","ES512","HS256","HS384","HS512","none"];if(i){v.splice(3,0,"PS256","PS384","PS512")}var y={expiresIn:{isValid:function(e){return u(e)||p(e)&&e},message:'"expiresIn" should be a number of seconds or string representing a timespan'},notBefore:{isValid:function(e){return u(e)||p(e)&&e},message:'"notBefore" should be a number of seconds or string representing a timespan'},audience:{isValid:function(e){return p(e)||Array.isArray(e)},message:'"audience" must be a string or array'},algorithm:{isValid:o.bind(null,v),message:'"algorithm" must be a valid string enum value'},header:{isValid:c,message:'"header" must be an object'},encoding:{isValid:p,message:'"encoding" must be a string'},issuer:{isValid:p,message:'"issuer" must be a string'},subject:{isValid:p,message:'"subject" must be a string'},jwtid:{isValid:p,message:'"jwtid" must be a string'},noTimestamp:{isValid:s,message:'"noTimestamp" must be a boolean'},keyid:{isValid:p,message:'"keyid" must be a string'},mutatePayload:{isValid:s,message:'"mutatePayload" must be a boolean'}};var d={iat:{isValid:f,message:'"iat" should be a number of seconds'},exp:{isValid:f,message:'"exp" should be a number of seconds'},nbf:{isValid:f,message:'"nbf" should be a number of seconds'}};function validate(e,r,t,n){if(!c(t)){throw new Error('Expected "'+n+'" to be a plain object.')}Object.keys(t).forEach(function(i){var a=e[i];if(!a){if(!r){throw new Error('"'+i+'" is not allowed in "'+n+'"')}return}if(!a.isValid(t[i])){throw new Error(a.message)}})}function validateOptions(e){return validate(y,false,e,"options")}function validatePayload(e){return validate(d,true,e,"payload")}var b={audience:"aud",issuer:"iss",subject:"sub",jwtid:"jti"};var h=["expiresIn","notBefore","noTimestamp","audience","issuer","subject","jwtid"];e.exports=function(e,r,t,i){if(typeof t==="function"){i=t;t={}}else{t=t||{}}var o=typeof e==="object"&&!Buffer.isBuffer(e);var s=Object.assign({alg:t.algorithm||"HS256",typ:o?"JWT":undefined,kid:t.keyid},t.header);function failure(e){if(i){return i(e)}throw e}if(!r&&t.algorithm!=="none"){return failure(new Error("secretOrPrivateKey must have a value"))}if(typeof e==="undefined"){return failure(new Error("payload is required"))}else if(o){try{validatePayload(e)}catch(e){return failure(e)}if(!t.mutatePayload){e=Object.assign({},e)}}else{var u=h.filter(function(e){return typeof t[e]!=="undefined"});if(u.length>0){return failure(new Error("invalid "+u.join(",")+" option for "+typeof e+" payload"))}}if(typeof e.exp!=="undefined"&&typeof t.expiresIn!=="undefined"){return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'))}if(typeof e.nbf!=="undefined"&&typeof t.notBefore!=="undefined"){return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'))}try{validateOptions(t)}catch(e){return failure(e)}var f=e.iat||Math.floor(Date.now()/1e3);if(t.noTimestamp){delete e.iat}else if(o){e.iat=f}if(typeof t.notBefore!=="undefined"){try{e.nbf=n(t.notBefore,f)}catch(e){return failure(e)}if(typeof e.nbf==="undefined"){return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'))}}if(typeof t.expiresIn!=="undefined"&&typeof e==="object"){try{e.exp=n(t.expiresIn,f)}catch(e){return failure(e)}if(typeof e.exp==="undefined"){return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'))}}Object.keys(b).forEach(function(r){var n=b[r];if(typeof t[r]!=="undefined"){if(typeof e[n]!=="undefined"){return failure(new Error('Bad "options.'+r+'" option. The payload already has an "'+n+'" property.'))}e[n]=t[r]}});var c=t.encoding||"utf8";if(typeof i==="function"){i=i&&l(i);a.createSign({header:s,privateKey:r,payload:e,encoding:c}).once("error",i).once("done",function(e){i(null,e)})}else{return a.sign({header:s,payload:e,secret:r,encoding:c})}}},449:function(e){var r="[object Boolean]";var t=Object.prototype;var n=t.toString;function isBoolean(e){return e===true||e===false||isObjectLike(e)&&n.call(e)==r}function isObjectLike(e){return!!e&&typeof e=="object"}e.exports=isBoolean},473:function(e){var r=1/0,t=9007199254740991,n=1.7976931348623157e308,i=0/0;var a="[object Arguments]",o="[object Function]",s="[object GeneratorFunction]",u="[object String]",f="[object Symbol]";var c=/^\s+|\s+$/g;var p=/^[-+]0x[0-9a-f]+$/i;var l=/^0b[01]+$/i;var v=/^0o[0-7]+$/i;var y=/^(?:0|[1-9]\d*)$/;var d=parseInt;function arrayMap(e,r){var t=-1,n=e?e.length:0,i=Array(n);while(++t<n){i[t]=r(e[t],t,e)}return i}function baseFindIndex(e,r,t,n){var i=e.length,a=t+(n?1:-1);while(n?a--:++a<i){if(r(e[a],a,e)){return a}}return-1}function baseIndexOf(e,r,t){if(r!==r){return baseFindIndex(e,baseIsNaN,t)}var n=t-1,i=e.length;while(++n<i){if(e[n]===r){return n}}return-1}function baseIsNaN(e){return e!==e}function baseTimes(e,r){var t=-1,n=Array(e);while(++t<e){n[t]=r(t)}return n}function baseValues(e,r){return arrayMap(r,function(r){return e[r]})}function overArg(e,r){return function(t){return e(r(t))}}var b=Object.prototype;var h=b.hasOwnProperty;var g=b.toString;var m=b.propertyIsEnumerable;var S=overArg(Object.keys,Object),w=Math.max;function arrayLikeKeys(e,r){var t=j(e)||isArguments(e)?baseTimes(e.length,String):[];var n=t.length,i=!!n;for(var a in e){if((r||h.call(e,a))&&!(i&&(a=="length"||isIndex(a,n)))){t.push(a)}}return t}function baseKeys(e){if(!isPrototype(e)){return S(e)}var r=[];for(var t in Object(e)){if(h.call(e,t)&&t!="constructor"){r.push(t)}}return r}function isIndex(e,r){r=r==null?t:r;return!!r&&(typeof e=="number"||y.test(e))&&(e>-1&&e%1==0&&e<r)}function isPrototype(e){var r=e&&e.constructor,t=typeof r=="function"&&r.prototype||b;return e===t}function includes(e,r,t,n){e=isArrayLike(e)?e:values(e);t=t&&!n?toInteger(t):0;var i=e.length;if(t<0){t=w(i+t,0)}return isString(e)?t<=i&&e.indexOf(r,t)>-1:!!i&&baseIndexOf(e,r,t)>-1}function isArguments(e){return isArrayLikeObject(e)&&h.call(e,"callee")&&(!m.call(e,"callee")||g.call(e)==a)}var j=Array.isArray;function isArrayLike(e){return e!=null&&isLength(e.length)&&!isFunction(e)}function isArrayLikeObject(e){return isObjectLike(e)&&isArrayLike(e)}function isFunction(e){var r=isObject(e)?g.call(e):"";return r==o||r==s}function isLength(e){return typeof e=="number"&&e>-1&&e%1==0&&e<=t}function isObject(e){var r=typeof e;return!!e&&(r=="object"||r=="function")}function isObjectLike(e){return!!e&&typeof e=="object"}function isString(e){return typeof e=="string"||!j(e)&&isObjectLike(e)&&g.call(e)==u}function isSymbol(e){return typeof e=="symbol"||isObjectLike(e)&&g.call(e)==f}function toFinite(e){if(!e){return e===0?e:0}e=toNumber(e);if(e===r||e===-r){var t=e<0?-1:1;return t*n}return e===e?e:0}function toInteger(e){var r=toFinite(e),t=r%1;return r===r?t?r-t:r:0}function toNumber(e){if(typeof e=="number"){return e}if(isSymbol(e)){return i}if(isObject(e)){var r=typeof e.valueOf=="function"?e.valueOf():e;e=isObject(r)?r+"":r}if(typeof e!="string"){return e===0?e:+e}e=e.replace(c,"");var t=l.test(e);return t||v.test(e)?d(e.slice(2),t?2:8):p.test(e)?i:+e}function keys(e){return isArrayLike(e)?arrayLikeKeys(e):baseKeys(e)}function values(e){return e?baseValues(e,keys(e)):[]}e.exports=includes},487:function(e,r,t){var n=t(821);var i=function(e,r){n.call(this,e);this.name="NotBeforeError";this.date=r};i.prototype=Object.create(n.prototype);i.prototype.constructor=i;e.exports=i},505:function(e,r,t){"use strict";var n=t(293).Buffer;var i=t(293).SlowBuffer;e.exports=bufferEq;function bufferEq(e,r){if(!n.isBuffer(e)||!n.isBuffer(r)){return false}if(e.length!==r.length){return false}var t=0;for(var i=0;i<e.length;i++){t|=e[i]^r[i]}return t===0}bufferEq.install=function(){n.prototype.equal=i.prototype.equal=function equal(e){return bufferEq(this,e)}};var a=n.prototype.equal;var o=i.prototype.equal;bufferEq.restore=function(){n.prototype.equal=a;i.prototype.equal=o}},519:function(e){e.exports=__webpack_require__("4Hvf")},572:function(e,r,t){var n=t(505);var i=t(704).Buffer;var a=t(417);var o=t(731);var s=t(669);var u='"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';var f="secret must be a string or buffer";var c="key must be a string or a buffer";var p="key must be a string, a buffer or an object";var l=typeof a.createPublicKey==="function";if(l){c+=" or a KeyObject";f+="or a KeyObject"}function checkIsPublicKey(e){if(i.isBuffer(e)){return}if(typeof e==="string"){return}if(!l){throw typeError(c)}if(typeof e!=="object"){throw typeError(c)}if(typeof e.type!=="string"){throw typeError(c)}if(typeof e.asymmetricKeyType!=="string"){throw typeError(c)}if(typeof e.export!=="function"){throw typeError(c)}}function checkIsPrivateKey(e){if(i.isBuffer(e)){return}if(typeof e==="string"){return}if(typeof e==="object"){return}throw typeError(p)}function checkIsSecretKey(e){if(i.isBuffer(e)){return}if(typeof e==="string"){return e}if(!l){throw typeError(f)}if(typeof e!=="object"){throw typeError(f)}if(e.type!=="secret"){throw typeError(f)}if(typeof e.export!=="function"){throw typeError(f)}}function fromBase64(e){return e.replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")}function toBase64(e){e=e.toString();var r=4-e.length%4;if(r!==4){for(var t=0;t<r;++t){e+="="}}return e.replace(/\-/g,"+").replace(/_/g,"/")}function typeError(e){var r=[].slice.call(arguments,1);var t=s.format.bind(s,e).apply(null,r);return new TypeError(t)}function bufferOrString(e){return i.isBuffer(e)||typeof e==="string"}function normalizeInput(e){if(!bufferOrString(e))e=JSON.stringify(e);return e}function createHmacSigner(e){return function sign(r,t){checkIsSecretKey(t);r=normalizeInput(r);var n=a.createHmac("sha"+e,t);var i=(n.update(r),n.digest("base64"));return fromBase64(i)}}function createHmacVerifier(e){return function verify(r,t,a){var o=createHmacSigner(e)(r,a);return n(i.from(t),i.from(o))}}function createKeySigner(e){return function sign(r,t){checkIsPrivateKey(t);r=normalizeInput(r);var n=a.createSign("RSA-SHA"+e);var i=(n.update(r),n.sign(t,"base64"));return fromBase64(i)}}function createKeyVerifier(e){return function verify(r,t,n){checkIsPublicKey(n);r=normalizeInput(r);t=toBase64(t);var i=a.createVerify("RSA-SHA"+e);i.update(r);return i.verify(n,t,"base64")}}function createPSSKeySigner(e){return function sign(r,t){checkIsPrivateKey(t);r=normalizeInput(r);var n=a.createSign("RSA-SHA"+e);var i=(n.update(r),n.sign({key:t,padding:a.constants.RSA_PKCS1_PSS_PADDING,saltLength:a.constants.RSA_PSS_SALTLEN_DIGEST},"base64"));return fromBase64(i)}}function createPSSKeyVerifier(e){return function verify(r,t,n){checkIsPublicKey(n);r=normalizeInput(r);t=toBase64(t);var i=a.createVerify("RSA-SHA"+e);i.update(r);return i.verify({key:n,padding:a.constants.RSA_PKCS1_PSS_PADDING,saltLength:a.constants.RSA_PSS_SALTLEN_DIGEST},t,"base64")}}function createECDSASigner(e){var r=createKeySigner(e);return function sign(){var t=r.apply(null,arguments);t=o.derToJose(t,"ES"+e);return t}}function createECDSAVerifer(e){var r=createKeyVerifier(e);return function verify(t,n,i){n=o.joseToDer(n,"ES"+e).toString("base64");var a=r(t,n,i);return a}}function createNoneSigner(){return function sign(){return""}}function createNoneVerifier(){return function verify(e,r){return r===""}}e.exports=function jwa(e){var r={hs:createHmacSigner,rs:createKeySigner,ps:createPSSKeySigner,es:createECDSASigner,none:createNoneSigner};var t={hs:createHmacVerifier,rs:createKeyVerifier,ps:createPSSKeyVerifier,es:createECDSAVerifer,none:createNoneVerifier};var n=e.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i);if(!n)throw typeError(u,e);var i=(n[1]||n[3]).toLowerCase();var a=n[2];return{sign:r[i](a),verify:t[i](a)}}},586:function(e,r,t){var n=t(293).Buffer;e.exports=function toString(e){if(typeof e==="string")return e;if(typeof e==="number"||n.isBuffer(e))return e.toString();return JSON.stringify(e)}},665:function(e){var r="[object String]";var t=Object.prototype;var n=t.toString;var i=Array.isArray;function isObjectLike(e){return!!e&&typeof e=="object"}function isString(e){return typeof e=="string"||!i(e)&&isObjectLike(e)&&n.call(e)==r}e.exports=isString},669:function(e){e.exports=__webpack_require__("jK02")},686:function(e,r,t){var n=t(998);e.exports=function(e,r){var t=r||Math.floor(Date.now()/1e3);if(typeof e==="string"){var i=n(e);if(typeof i==="undefined"){return}return Math.floor(t+i/1e3)}else if(typeof e==="number"){return t+e}else{return}}},704:function(e,r,t){var n=t(293);var i=n.Buffer;function copyProps(e,r){for(var t in e){r[t]=e[t]}}if(i.from&&i.alloc&&i.allocUnsafe&&i.allocUnsafeSlow){e.exports=n}else{copyProps(n,r);r.Buffer=SafeBuffer}function SafeBuffer(e,r,t){return i(e,r,t)}SafeBuffer.prototype=Object.create(i.prototype);copyProps(i,SafeBuffer);SafeBuffer.from=function(e,r,t){if(typeof e==="number"){throw new TypeError("Argument must not be a number")}return i(e,r,t)};SafeBuffer.alloc=function(e,r,t){if(typeof e!=="number"){throw new TypeError("Argument must be a number")}var n=i(e);if(r!==undefined){if(typeof t==="string"){n.fill(r,t)}else{n.fill(r)}}else{n.fill(0)}return n};SafeBuffer.allocUnsafe=function(e){if(typeof e!=="number"){throw new TypeError("Argument must be a number")}return i(e)};SafeBuffer.allocUnsafeSlow=function(e){if(typeof e!=="number"){throw new TypeError("Argument must be a number")}return n.SlowBuffer(e)}},717:function(e,r,t){var n=t(704).Buffer;var i=t(14);var a=t(572);var o=t(413);var s=t(586);var u=t(669);function base64url(e,r){return n.from(e,r).toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")}function jwsSecuredInput(e,r,t){t=t||"utf8";var n=base64url(s(e),"binary");var i=base64url(s(r),t);return u.format("%s.%s",n,i)}function jwsSign(e){var r=e.header;var t=e.payload;var n=e.secret||e.privateKey;var i=e.encoding;var o=a(r.alg);var s=jwsSecuredInput(r,t,i);var f=o.sign(s,n);return u.format("%s.%s",s,f)}function SignStream(e){var r=e.secret||e.privateKey||e.key;var t=new i(r);this.readable=true;this.header=e.header;this.encoding=e.encoding;this.secret=this.privateKey=this.key=t;this.payload=new i(e.payload);this.secret.once("close",function(){if(!this.payload.writable&&this.readable)this.sign()}.bind(this));this.payload.once("close",function(){if(!this.secret.writable&&this.readable)this.sign()}.bind(this))}u.inherits(SignStream,o);SignStream.prototype.sign=function sign(){try{var e=jwsSign({header:this.header,payload:this.payload.buffer,secret:this.secret.buffer,encoding:this.encoding});this.emit("done",e);this.emit("data",e);this.emit("end");this.readable=false;return e}catch(e){this.readable=false;this.emit("error",e);this.emit("close")}};SignStream.sign=jwsSign;e.exports=SignStream},731:function(e,r,t){"use strict";var n=t(704).Buffer;var i=t(358);var a=128,o=0,s=32,u=16,f=2,c=u|s|o<<6,p=f|o<<6;function base64Url(e){return e.replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")}function signatureAsBuffer(e){if(n.isBuffer(e)){return e}else if("string"===typeof e){return n.from(e,"base64")}throw new TypeError("ECDSA signature must be a Base64 string or a Buffer")}function derToJose(e,r){e=signatureAsBuffer(e);var t=i(r);var o=t+1;var s=e.length;var u=0;if(e[u++]!==c){throw new Error('Could not find expected "seq"')}var f=e[u++];if(f===(a|1)){f=e[u++]}if(s-u<f){throw new Error('"seq" specified length of "'+f+'", only "'+(s-u)+'" remaining')}if(e[u++]!==p){throw new Error('Could not find expected "int" for "r"')}var l=e[u++];if(s-u-2<l){throw new Error('"r" specified length of "'+l+'", only "'+(s-u-2)+'" available')}if(o<l){throw new Error('"r" specified length of "'+l+'", max of "'+o+'" is acceptable')}var v=u;u+=l;if(e[u++]!==p){throw new Error('Could not find expected "int" for "s"')}var y=e[u++];if(s-u!==y){throw new Error('"s" specified length of "'+y+'", expected "'+(s-u)+'"')}if(o<y){throw new Error('"s" specified length of "'+y+'", max of "'+o+'" is acceptable')}var d=u;u+=y;if(u!==s){throw new Error('Expected to consume entire buffer, but "'+(s-u)+'" bytes remain')}var b=t-l,h=t-y;var g=n.allocUnsafe(b+l+h+y);for(u=0;u<b;++u){g[u]=0}e.copy(g,u,v+Math.max(-b,0),v+l);u=t;for(var m=u;u<m+h;++u){g[u]=0}e.copy(g,u,d+Math.max(-h,0),d+y);g=g.toString("base64");g=base64Url(g);return g}function countPadding(e,r,t){var n=0;while(r+n<t&&e[r+n]===0){++n}var i=e[r+n]>=a;if(i){--n}return n}function joseToDer(e,r){e=signatureAsBuffer(e);var t=i(r);var o=e.length;if(o!==t*2){throw new TypeError('"'+r+'" signatures must be "'+t*2+'" bytes, saw "'+o+'"')}var s=countPadding(e,0,t);var u=countPadding(e,t,e.length);var f=t-s;var l=t-u;var v=1+1+f+1+1+l;var y=v<a;var d=n.allocUnsafe((y?2:3)+v);var b=0;d[b++]=c;if(y){d[b++]=v}else{d[b++]=a|1;d[b++]=v&255}d[b++]=p;d[b++]=f;if(s<0){d[b++]=0;b+=e.copy(d,b,0,t)}else{b+=e.copy(d,b,s,t)}d[b++]=p;d[b++]=l;if(u<0){d[b++]=0;e.copy(d,b,t)}else{e.copy(d,b,t+u)}return d}e.exports={derToJose:derToJose,joseToDer:joseToDer}},821:function(e){var r=function(e,r){Error.call(this,e);if(Error.captureStackTrace){Error.captureStackTrace(this,this.constructor)}this.name="JsonWebTokenError";this.message=e;if(r)this.inner=r};r.prototype=Object.create(Error.prototype);r.prototype.constructor=r;e.exports=r},958:function(e){var r="[object Number]";var t=Object.prototype;var n=t.toString;function isObjectLike(e){return!!e&&typeof e=="object"}function isNumber(e){return typeof e=="number"||isObjectLike(e)&&n.call(e)==r}e.exports=isNumber},998:function(e){var r=1e3;var t=r*60;var n=t*60;var i=n*24;var a=i*7;var o=i*365.25;e.exports=function(e,r){r=r||{};var t=typeof e;if(t==="string"&&e.length>0){return parse(e)}else if(t==="number"&&isFinite(e)){return r.long?fmtLong(e):fmtShort(e)}throw new Error("val is not a non-empty string or a valid number. val="+JSON.stringify(e))};function parse(e){e=String(e);if(e.length>100){return}var s=/^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(e);if(!s){return}var u=parseFloat(s[1]);var f=(s[2]||"ms").toLowerCase();switch(f){case"years":case"year":case"yrs":case"yr":case"y":return u*o;case"weeks":case"week":case"w":return u*a;case"days":case"day":case"d":return u*i;case"hours":case"hour":case"hrs":case"hr":case"h":return u*n;case"minutes":case"minute":case"mins":case"min":case"m":return u*t;case"seconds":case"second":case"secs":case"sec":case"s":return u*r;case"milliseconds":case"millisecond":case"msecs":case"msec":case"ms":return u;default:return undefined}}function fmtShort(e){var a=Math.abs(e);if(a>=i){return Math.round(e/i)+"d"}if(a>=n){return Math.round(e/n)+"h"}if(a>=t){return Math.round(e/t)+"m"}if(a>=r){return Math.round(e/r)+"s"}return e+"ms"}function fmtLong(e){var a=Math.abs(e);if(a>=i){return plural(e,a,i,"day")}if(a>=n){return plural(e,a,n,"hour")}if(a>=t){return plural(e,a,t,"minute")}if(a>=r){return plural(e,a,r,"second")}return e+" ms"}function plural(e,r,t,n){var i=r>=t*1.5;return Math.round(e/t)+" "+n+(i?"s":"")}}});
/* WEBPACK VAR INJECTION */}.call(this, "/"))

/***/ }),

/***/ "sR+5":
/***/ (function(module, exports, __webpack_require__) {

const Sign = __webpack_require__("l3Iq")
const { verify } = __webpack_require__("ZXG7")

const single = (serialization, payload, key, protectedHeader, unprotectedHeader) => {
  return new Sign(payload)
    .recipient(key, protectedHeader, unprotectedHeader)
    .sign(serialization)
}

module.exports.Sign = Sign
module.exports.sign = single.bind(undefined, 'compact')
module.exports.sign.flattened = single.bind(undefined, 'flattened')
module.exports.sign.general = single.bind(undefined, 'general')

module.exports.verify = verify


/***/ }),

/***/ "sesp":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (method) {

    if (method._hoekOnce) {
        return method;
    }

    let once = false;
    const wrapped = function (...args) {

        if (!once) {
            once = true;
            method(...args);
        }
    };

    wrapped._hoekOnce = true;
    return wrapped;
};


/***/ }),

/***/ "tCGZ":
/***/ (function(module) {

module.exports = JSON.parse("{\"_from\":\"got@^9.6.0\",\"_id\":\"got@9.6.0\",\"_inBundle\":false,\"_integrity\":\"sha512-R7eWptXuGYxwijs0eV+v3o6+XH1IqVK8dJOEecQfTmkncw9AV4dcw/Dhxi8MdlqPthxxpZyizMzyg8RTmEsG+Q==\",\"_location\":\"/got\",\"_phantomChildren\":{},\"_requested\":{\"type\":\"range\",\"registry\":true,\"raw\":\"got@^9.6.0\",\"name\":\"got\",\"escapedName\":\"got\",\"rawSpec\":\"^9.6.0\",\"saveSpec\":null,\"fetchSpec\":\"^9.6.0\"},\"_requiredBy\":[\"/openid-client\"],\"_resolved\":\"https://registry.npmjs.org/got/-/got-9.6.0.tgz\",\"_shasum\":\"edf45e7d67f99545705de1f7bbeeeb121765ed85\",\"_spec\":\"got@^9.6.0\",\"_where\":\"/Users/jonah/code/resumate/node_modules/openid-client\",\"ava\":{\"concurrency\":4},\"browser\":{\"decompress-response\":false,\"electron\":false},\"bugs\":{\"url\":\"https://github.com/sindresorhus/got/issues\"},\"bundleDependencies\":false,\"dependencies\":{\"@sindresorhus/is\":\"^0.14.0\",\"@szmarczak/http-timer\":\"^1.1.2\",\"cacheable-request\":\"^6.0.0\",\"decompress-response\":\"^3.3.0\",\"duplexer3\":\"^0.1.4\",\"get-stream\":\"^4.1.0\",\"lowercase-keys\":\"^1.0.1\",\"mimic-response\":\"^1.0.1\",\"p-cancelable\":\"^1.0.0\",\"to-readable-stream\":\"^1.0.0\",\"url-parse-lax\":\"^3.0.0\"},\"deprecated\":false,\"description\":\"Simplified HTTP requests\",\"devDependencies\":{\"ava\":\"^1.1.0\",\"coveralls\":\"^3.0.0\",\"delay\":\"^4.1.0\",\"form-data\":\"^2.3.3\",\"get-port\":\"^4.0.0\",\"np\":\"^3.1.0\",\"nyc\":\"^13.1.0\",\"p-event\":\"^2.1.0\",\"pem\":\"^1.13.2\",\"proxyquire\":\"^2.0.1\",\"sinon\":\"^7.2.2\",\"slow-stream\":\"0.0.4\",\"tempfile\":\"^2.0.0\",\"tempy\":\"^0.2.1\",\"tough-cookie\":\"^3.0.0\",\"xo\":\"^0.24.0\"},\"engines\":{\"node\":\">=8.6\"},\"files\":[\"source\"],\"homepage\":\"https://github.com/sindresorhus/got#readme\",\"keywords\":[\"http\",\"https\",\"get\",\"got\",\"url\",\"uri\",\"request\",\"util\",\"utility\",\"simple\",\"curl\",\"wget\",\"fetch\",\"net\",\"network\",\"electron\"],\"license\":\"MIT\",\"main\":\"source\",\"name\":\"got\",\"repository\":{\"type\":\"git\",\"url\":\"git+https://github.com/sindresorhus/got.git\"},\"scripts\":{\"release\":\"np\",\"test\":\"xo && nyc ava\"},\"version\":\"9.6.0\"}");

/***/ }),

/***/ "tIIU":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = function (timeout) {

    return new Promise((resolve) => setTimeout(resolve, timeout));
};


/***/ }),

/***/ "tlh6":
/***/ (function(module, exports) {

module.exports = require("string_decoder");

/***/ }),

/***/ "tuF3":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Helper which tests if a URL can safely be redirected to. Requires the URL to be relative.
 * @param url
 */
function isSafeRedirect(url) {
    if (typeof url !== 'string') {
        throw new TypeError(`Invalid url: ${url}`);
    }
    // Prevent open redirects using the //foo.com format (double forward slash).
    if (/\/\//.test(url)) {
        return false;
    }
    return !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(url);
}
exports.default = isSafeRedirect;
//# sourceMappingURL=url-helpers.js.map

/***/ }),

/***/ "u88T":
/***/ (function(module, exports, __webpack_require__) {

const asn1 = __webpack_require__("9ny7")

const types = new Map()

const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', __webpack_require__("yAVD"))
types.set('AlgorithmIdentifier', AlgorithmIdentifier)

const ECPrivateKey = asn1.define('ECPrivateKey', __webpack_require__("HKOu"))
types.set('ECPrivateKey', ECPrivateKey)

const PrivateKeyInfo = asn1.define('PrivateKeyInfo', __webpack_require__("wEzw")(AlgorithmIdentifier))
types.set('PrivateKeyInfo', PrivateKeyInfo)

const PublicKeyInfo = asn1.define('PublicKeyInfo', __webpack_require__("pBmY")(AlgorithmIdentifier))
types.set('PublicKeyInfo', PublicKeyInfo)

const PrivateKey = asn1.define('PrivateKey', __webpack_require__("YFSu"))
types.set('PrivateKey', PrivateKey)

const OneAsymmetricKey = asn1.define('OneAsymmetricKey', __webpack_require__("o/Eg")(AlgorithmIdentifier, PrivateKey))
types.set('OneAsymmetricKey', OneAsymmetricKey)

const RSAPrivateKey = asn1.define('RSAPrivateKey', __webpack_require__("Ra3S"))
types.set('RSAPrivateKey', RSAPrivateKey)

const RSAPublicKey = asn1.define('RSAPublicKey', __webpack_require__("k9s9"))
types.set('RSAPublicKey', RSAPublicKey)

module.exports = types


/***/ }),

/***/ "uGJc":
/***/ (function(module, exports) {

module.exports = alg => `sha${alg.substr(2, 3)}`


/***/ }),

/***/ "uJ/c":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


module.exports = internals.flatten = function (array, target) {

    const result = target || [];

    for (let i = 0; i < array.length; ++i) {
        if (Array.isArray(array[i])) {
            internals.flatten(array[i], result);
        }
        else {
            result.push(array[i]);
        }
    }

    return result;
};


/***/ }),

/***/ "ugmf":
/***/ (function(module, exports) {

module.exports = require("tls");

/***/ }),

/***/ "uk5n":
/***/ (function(module, exports, __webpack_require__) {

const { createHash } = __webpack_require__("PJMN")

const base64url = __webpack_require__("Xab3")

const x5t = (hash, cert) => base64url.encodeBuffer(createHash(hash).update(Buffer.from(cert, 'base64')).digest())

module.exports.kid = components => base64url.encodeBuffer(createHash('sha256').update(JSON.stringify(components)).digest())
module.exports.x5t = x5t.bind(undefined, 'sha1')
module.exports['x5t#S256'] = x5t.bind(undefined, 'sha256')


/***/ }),

/***/ "urXW":
/***/ (function(module, exports, __webpack_require__) {

const { JOSECritNotUnderstood, JWSInvalid } = __webpack_require__("yt7c")

const DEFINED = new Set([
  'alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'typ', 'cty',
  'crit', 'enc', 'zip', 'epk', 'apu', 'apv', 'iv', 'tag', 'p2s', 'p2c'
])

module.exports = function validateCrit (Err, protectedHeader, unprotectedHeader, understood) {
  if (protectedHeader && 'crit' in protectedHeader) {
    if (
      !Array.isArray(protectedHeader.crit) ||
      protectedHeader.crit.length === 0 ||
      protectedHeader.crit.some(s => typeof s !== 'string' || !s)
    ) {
      throw new Err('"crit" Header Parameter MUST be an array of non-empty strings when present')
    }
    const whitelisted = new Set(understood)
    const combined = { ...protectedHeader, ...unprotectedHeader }
    protectedHeader.crit.forEach((parameter) => {
      if (DEFINED.has(parameter)) {
        throw new Err(`The critical list contains a non-extension Header Parameter ${parameter}`)
      }
      if (!whitelisted.has(parameter)) {
        throw new JOSECritNotUnderstood(`critical "${parameter}" is not understood`)
      }
      if (parameter === 'b64') {
        if (!('b64' in protectedHeader)) {
          throw new JWSInvalid('"b64" critical parameter must be integrity protected')
        }
        if (typeof protectedHeader.b64 !== 'boolean') {
          throw new JWSInvalid('"b64" critical parameter must be a boolean')
        }
      } else if (!(parameter in combined)) {
        throw new Err(`critical parameter "${parameter}" is missing`)
      }
    })
  }
  if (unprotectedHeader && 'crit' in unprotectedHeader) {
    throw new Err('"crit" Header Parameter MUST be integrity protected when present')
  }
}


/***/ }),

/***/ "vC2k":
/***/ (function(module, exports, __webpack_require__) {

const { generateKeyPairSync, generateKeyPair: async } = __webpack_require__("PJMN")
const { promisify } = __webpack_require__("jK02")

const {
  THUMBPRINT_MATERIAL, JWK_MEMBERS, PUBLIC_MEMBERS,
  PRIVATE_MEMBERS, KEY_MANAGEMENT_DECRYPT, KEY_MANAGEMENT_ENCRYPT
} = __webpack_require__("ehsS")
const { OKP_CURVES } = __webpack_require__("N+nT")
const { edDSASupported } = __webpack_require__("pDDt")
const errors = __webpack_require__("yt7c")

const Key = __webpack_require__("//Cd")

const generateKeyPair = promisify(async)

const OKP_PUBLIC = new Set(['crv', 'x'])
Object.freeze(OKP_PUBLIC)
const OKP_PRIVATE = new Set([...OKP_PUBLIC, 'd'])
Object.freeze(OKP_PRIVATE)

// Octet string key pairs Key Type
class OKPKey extends Key {
  constructor (...args) {
    super(...args)
    this[JWK_MEMBERS]()
    Object.defineProperty(this, 'kty', { value: 'OKP', enumerable: true })
    if (!OKP_CURVES.has(this.crv)) {
      throw new errors.JOSENotSupported('unsupported OKP key curve')
    }
  }

  static get [PUBLIC_MEMBERS] () {
    return OKP_PUBLIC
  }

  static get [PRIVATE_MEMBERS] () {
    return OKP_PRIVATE
  }

  // https://tc39.github.io/ecma262/#sec-ordinaryownpropertykeys no need for any special
  // JSON.stringify handling in V8
  [THUMBPRINT_MATERIAL] () {
    return { crv: this.crv, kty: 'OKP', x: this.x }
  }

  [KEY_MANAGEMENT_ENCRYPT] () {
    return this.algorithms('deriveKey')
  }

  [KEY_MANAGEMENT_DECRYPT] () {
    if (this.public) {
      return new Set()
    }
    return this.algorithms('deriveKey')
  }

  static async generate (crv = 'Ed25519', privat = true) {
    if (!edDSASupported) {
      throw new errors.JOSENotSupported('OKP keys are not supported in your Node.js runtime version')
    }

    if (!OKP_CURVES.has(crv)) {
      throw new errors.JOSENotSupported(`unsupported OKP key curve: ${crv}`)
    }

    const { privateKey, publicKey } = await generateKeyPair(crv.toLowerCase())

    return privat ? privateKey : publicKey
  }

  static generateSync (crv = 'Ed25519', privat = true) {
    if (!edDSASupported) {
      throw new errors.JOSENotSupported('OKP keys are not supported in your Node.js runtime version')
    }

    if (!OKP_CURVES.has(crv)) {
      throw new errors.JOSENotSupported(`unsupported OKP key curve: ${crv}`)
    }

    const { privateKey, publicKey } = generateKeyPairSync(crv.toLowerCase())

    return privat ? privateKey : publicKey
  }
}

module.exports = OKPKey


/***/ }),

/***/ "vUsp":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
function padString(input) {
    var segmentLength = 4;
    var stringLength = input.length;
    var diff = stringLength % segmentLength;
    if (!diff) {
        return input;
    }
    var position = stringLength;
    var padLength = segmentLength - diff;
    var paddedStringLength = stringLength + padLength;
    var buffer = Buffer.alloc(paddedStringLength);
    buffer.write(input);
    while (padLength--) {
        buffer.write("=", position++);
    }
    return buffer.toString();
}
exports.default = padString;


/***/ }),

/***/ "vbc4":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const internals = {};


exports = module.exports = {
    array: Array.prototype,
    buffer: Buffer && Buffer.prototype,             // $lab:coverage:ignore$
    date: Date.prototype,
    error: Error.prototype,
    generic: Object.prototype,
    map: Map.prototype,
    promise: Promise.prototype,
    regex: RegExp.prototype,
    set: Set.prototype,
    weakMap: WeakMap.prototype,
    weakSet: WeakSet.prototype
};


internals.typeMap = new Map([
    ['[object Error]', exports.error],
    ['[object Map]', exports.map],
    ['[object Promise]', exports.promise],
    ['[object Set]', exports.set],
    ['[object WeakMap]', exports.weakMap],
    ['[object WeakSet]', exports.weakSet]
]);


exports.getInternalProto = function (obj) {

    if (Array.isArray(obj)) {
        return exports.array;
    }

    if (Buffer && obj instanceof Buffer) {          // $lab:coverage:ignore$
        return exports.buffer;
    }

    if (obj instanceof Date) {
        return exports.date;
    }

    if (obj instanceof RegExp) {
        return exports.regex;
    }

    if (obj instanceof Error) {
        return exports.error;
    }

    const objName = Object.prototype.toString.call(obj);
    return internals.typeMap.get(objName) || exports.generic;
};


/***/ }),

/***/ "vv4h":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.pageNotFoundError=pageNotFoundError;exports.getPagePath=getPagePath;exports.requirePage=requirePage;exports.requireFontManifest=requireFontManifest;var _fs=__webpack_require__("mw/K");var _path=__webpack_require__("oyvS");var _constants=__webpack_require__("w7wo");var _normalizePagePath=__webpack_require__("w0zM");function pageNotFoundError(page){const err=new Error(`Cannot find module for page: ${page}`);err.code='ENOENT';return err;}function getPagePath(page,distDir,serverless,dev){const serverBuildPath=(0,_path.join)(distDir,serverless&&!dev?_constants.SERVERLESS_DIRECTORY:_constants.SERVER_DIRECTORY);const pagesManifest=__webpack_require__("PJv+")((0,_path.join)(serverBuildPath,_constants.PAGES_MANIFEST));try{page=(0,_normalizePagePath.denormalizePagePath)((0,_normalizePagePath.normalizePagePath)(page));}catch(err){console.error(err);throw pageNotFoundError(page);}if(!pagesManifest[page]){throw pageNotFoundError(page);}return(0,_path.join)(serverBuildPath,pagesManifest[page]);}function requirePage(page,distDir,serverless){const pagePath=getPagePath(page,distDir,serverless);if(pagePath.endsWith('.html')){return _fs.promises.readFile(pagePath,'utf8');}return __webpack_require__("PJv+")(pagePath);}function requireFontManifest(distDir,serverless){const serverBuildPath=(0,_path.join)(distDir,serverless?_constants.SERVERLESS_DIRECTORY:_constants.SERVER_DIRECTORY);const fontManifest=__webpack_require__("PJv+")((0,_path.join)(serverBuildPath,_constants.FONT_MANIFEST));return fontManifest;}
//# sourceMappingURL=require.js.map

/***/ }),

/***/ "w0zM":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.normalizePagePath=normalizePagePath;exports.denormalizePagePath=exports.normalizePathSep=void 0;var _path=__webpack_require__("oyvS");var _denormalizePagePath=__webpack_require__("wkBG");exports.normalizePathSep=_denormalizePagePath.normalizePathSep;exports.denormalizePagePath=_denormalizePagePath.denormalizePagePath;function normalizePagePath(page){// If the page is `/` we need to append `/index`, otherwise the returned directory root will be bundles instead of pages
if(page==='/'){page='/index';}else if(/^\/index(\/|$)/.test(page)){page=`/index${page}`;}// Resolve on anything that doesn't start with `/`
if(!page.startsWith('/')){page=`/${page}`;}// Throw when using ../ etc in the pathname
const resolvedPage=_path.posix.normalize(page);if(page!==resolvedPage){throw new Error(`Requested and resolved page mismatch: ${page} ${resolvedPage}`);}return page;}
//# sourceMappingURL=normalize-page-path.js.map

/***/ }),

/***/ "w7wo":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;
exports.OPTIMIZED_FONT_PROVIDERS = exports.SERVER_PROPS_ID = exports.STATIC_PROPS_ID = exports.PERMANENT_REDIRECT_STATUS = exports.TEMPORARY_REDIRECT_STATUS = exports.CLIENT_STATIC_FILES_RUNTIME_POLYFILLS = exports.CLIENT_STATIC_FILES_RUNTIME_WEBPACK = exports.CLIENT_STATIC_FILES_RUNTIME_AMP = exports.CLIENT_STATIC_FILES_RUNTIME_REACT_REFRESH = exports.CLIENT_STATIC_FILES_RUNTIME_MAIN = exports.STRING_LITERAL_DROP_BUNDLE = exports.AMP_RENDER_TARGET = exports.CLIENT_STATIC_FILES_RUNTIME = exports.CLIENT_STATIC_FILES_PATH = exports.CLIENT_PUBLIC_FILES_PATH = exports.BLOCKED_PAGES = exports.BUILD_ID_FILE = exports.CONFIG_FILE = exports.SERVERLESS_DIRECTORY = exports.SERVER_DIRECTORY = exports.FONT_MANIFEST = exports.REACT_LOADABLE_MANIFEST = exports.DEV_CLIENT_PAGES_MANIFEST = exports.ROUTES_MANIFEST = exports.PRERENDER_MANIFEST = exports.EXPORT_DETAIL = exports.EXPORT_MARKER = exports.BUILD_MANIFEST = exports.PAGES_MANIFEST = exports.PHASE_DEVELOPMENT_SERVER = exports.PHASE_PRODUCTION_SERVER = exports.PHASE_PRODUCTION_BUILD = exports.PHASE_EXPORT = void 0;
const PHASE_EXPORT = 'phase-export';
exports.PHASE_EXPORT = PHASE_EXPORT;
const PHASE_PRODUCTION_BUILD = 'phase-production-build';
exports.PHASE_PRODUCTION_BUILD = PHASE_PRODUCTION_BUILD;
const PHASE_PRODUCTION_SERVER = 'phase-production-server';
exports.PHASE_PRODUCTION_SERVER = PHASE_PRODUCTION_SERVER;
const PHASE_DEVELOPMENT_SERVER = 'phase-development-server';
exports.PHASE_DEVELOPMENT_SERVER = PHASE_DEVELOPMENT_SERVER;
const PAGES_MANIFEST = 'pages-manifest.json';
exports.PAGES_MANIFEST = PAGES_MANIFEST;
const BUILD_MANIFEST = 'build-manifest.json';
exports.BUILD_MANIFEST = BUILD_MANIFEST;
const EXPORT_MARKER = 'export-marker.json';
exports.EXPORT_MARKER = EXPORT_MARKER;
const EXPORT_DETAIL = 'export-detail.json';
exports.EXPORT_DETAIL = EXPORT_DETAIL;
const PRERENDER_MANIFEST = 'prerender-manifest.json';
exports.PRERENDER_MANIFEST = PRERENDER_MANIFEST;
const ROUTES_MANIFEST = 'routes-manifest.json';
exports.ROUTES_MANIFEST = ROUTES_MANIFEST;
const DEV_CLIENT_PAGES_MANIFEST = '_devPagesManifest.json';
exports.DEV_CLIENT_PAGES_MANIFEST = DEV_CLIENT_PAGES_MANIFEST;
const REACT_LOADABLE_MANIFEST = 'react-loadable-manifest.json';
exports.REACT_LOADABLE_MANIFEST = REACT_LOADABLE_MANIFEST;
const FONT_MANIFEST = 'font-manifest.json';
exports.FONT_MANIFEST = FONT_MANIFEST;
const SERVER_DIRECTORY = 'server';
exports.SERVER_DIRECTORY = SERVER_DIRECTORY;
const SERVERLESS_DIRECTORY = 'serverless';
exports.SERVERLESS_DIRECTORY = SERVERLESS_DIRECTORY;
const CONFIG_FILE = 'next.config.js';
exports.CONFIG_FILE = CONFIG_FILE;
const BUILD_ID_FILE = 'BUILD_ID';
exports.BUILD_ID_FILE = BUILD_ID_FILE;
const BLOCKED_PAGES = ['/_document', '/_app'];
exports.BLOCKED_PAGES = BLOCKED_PAGES;
const CLIENT_PUBLIC_FILES_PATH = 'public';
exports.CLIENT_PUBLIC_FILES_PATH = CLIENT_PUBLIC_FILES_PATH;
const CLIENT_STATIC_FILES_PATH = 'static';
exports.CLIENT_STATIC_FILES_PATH = CLIENT_STATIC_FILES_PATH;
const CLIENT_STATIC_FILES_RUNTIME = 'runtime';
exports.CLIENT_STATIC_FILES_RUNTIME = CLIENT_STATIC_FILES_RUNTIME;
const AMP_RENDER_TARGET = '__NEXT_AMP_RENDER_TARGET__';
exports.AMP_RENDER_TARGET = AMP_RENDER_TARGET;
const STRING_LITERAL_DROP_BUNDLE = '__NEXT_DROP_CLIENT_FILE__'; // static/runtime/main.js

exports.STRING_LITERAL_DROP_BUNDLE = STRING_LITERAL_DROP_BUNDLE;
const CLIENT_STATIC_FILES_RUNTIME_MAIN = `main`; // static/runtime/react-refresh.js

exports.CLIENT_STATIC_FILES_RUNTIME_MAIN = CLIENT_STATIC_FILES_RUNTIME_MAIN;
const CLIENT_STATIC_FILES_RUNTIME_REACT_REFRESH = `react-refresh`; // static/runtime/amp.js

exports.CLIENT_STATIC_FILES_RUNTIME_REACT_REFRESH = CLIENT_STATIC_FILES_RUNTIME_REACT_REFRESH;
const CLIENT_STATIC_FILES_RUNTIME_AMP = `amp`; // static/runtime/webpack.js

exports.CLIENT_STATIC_FILES_RUNTIME_AMP = CLIENT_STATIC_FILES_RUNTIME_AMP;
const CLIENT_STATIC_FILES_RUNTIME_WEBPACK = `webpack`; // static/runtime/polyfills.js

exports.CLIENT_STATIC_FILES_RUNTIME_WEBPACK = CLIENT_STATIC_FILES_RUNTIME_WEBPACK;
const CLIENT_STATIC_FILES_RUNTIME_POLYFILLS = `polyfills`;
exports.CLIENT_STATIC_FILES_RUNTIME_POLYFILLS = CLIENT_STATIC_FILES_RUNTIME_POLYFILLS;
const TEMPORARY_REDIRECT_STATUS = 307;
exports.TEMPORARY_REDIRECT_STATUS = TEMPORARY_REDIRECT_STATUS;
const PERMANENT_REDIRECT_STATUS = 308;
exports.PERMANENT_REDIRECT_STATUS = PERMANENT_REDIRECT_STATUS;
const STATIC_PROPS_ID = '__N_SSG';
exports.STATIC_PROPS_ID = STATIC_PROPS_ID;
const SERVER_PROPS_ID = '__N_SSP';
exports.SERVER_PROPS_ID = SERVER_PROPS_ID;
const OPTIMIZED_FONT_PROVIDERS = ['https://fonts.googleapis.com/css'];
exports.OPTIMIZED_FONT_PROVIDERS = OPTIMIZED_FONT_PROVIDERS;

/***/ }),

/***/ "w8yO":
/***/ (function(module, exports) {

const sign = () => Buffer.from('')
const verify = (key, payload, signature) => !signature.length

module.exports = (JWA, JWK) => {
  JWA.sign.set('none', sign)
  JWA.verify.set('none', verify)
}


/***/ }),

/***/ "wEzw":
/***/ (function(module, exports) {

module.exports = (AlgorithmIdentifier) => function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').octstr()
  )
}


/***/ }),

/***/ "whhB":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {URL, URLSearchParams} = __webpack_require__("bzos"); // TODO: Use the `URL` global when targeting Node.js 10
const urlLib = __webpack_require__("bzos");
const is = __webpack_require__("6mOv");
const urlParseLax = __webpack_require__("9l6Z");
const lowercaseKeys = __webpack_require__("y1+z");
const urlToOptions = __webpack_require__("NHoT");
const isFormData = __webpack_require__("faWz");
const merge = __webpack_require__("AW8e");
const knownHookEvents = __webpack_require__("JlL/");

const retryAfterStatusCodes = new Set([413, 429, 503]);

// `preNormalize` handles static options (e.g. headers).
// For example, when you create a custom instance and make a request
// with no static changes, they won't be normalized again.
//
// `normalize` operates on dynamic options - they cannot be saved.
// For example, `body` is everytime different per request.
// When it's done normalizing the new options, it performs merge()
// on the prenormalized options and the normalized ones.

const preNormalize = (options, defaults) => {
	if (is.nullOrUndefined(options.headers)) {
		options.headers = {};
	} else {
		options.headers = lowercaseKeys(options.headers);
	}

	if (options.baseUrl && !options.baseUrl.toString().endsWith('/')) {
		options.baseUrl += '/';
	}

	if (options.stream) {
		options.json = false;
	}

	if (is.nullOrUndefined(options.hooks)) {
		options.hooks = {};
	} else if (!is.object(options.hooks)) {
		throw new TypeError(`Parameter \`hooks\` must be an object, not ${is(options.hooks)}`);
	}

	for (const event of knownHookEvents) {
		if (is.nullOrUndefined(options.hooks[event])) {
			if (defaults) {
				options.hooks[event] = [...defaults.hooks[event]];
			} else {
				options.hooks[event] = [];
			}
		}
	}

	if (is.number(options.timeout)) {
		options.gotTimeout = {request: options.timeout};
	} else if (is.object(options.timeout)) {
		options.gotTimeout = options.timeout;
	}

	delete options.timeout;

	const {retry} = options;
	options.retry = {
		retries: 0,
		methods: [],
		statusCodes: [],
		errorCodes: []
	};

	if (is.nonEmptyObject(defaults) && retry !== false) {
		options.retry = {...defaults.retry};
	}

	if (retry !== false) {
		if (is.number(retry)) {
			options.retry.retries = retry;
		} else {
			options.retry = {...options.retry, ...retry};
		}
	}

	if (options.gotTimeout) {
		options.retry.maxRetryAfter = Math.min(...[options.gotTimeout.request, options.gotTimeout.connection].filter(n => !is.nullOrUndefined(n)));
	}

	if (is.array(options.retry.methods)) {
		options.retry.methods = new Set(options.retry.methods.map(method => method.toUpperCase()));
	}

	if (is.array(options.retry.statusCodes)) {
		options.retry.statusCodes = new Set(options.retry.statusCodes);
	}

	if (is.array(options.retry.errorCodes)) {
		options.retry.errorCodes = new Set(options.retry.errorCodes);
	}

	return options;
};

const normalize = (url, options, defaults) => {
	if (is.plainObject(url)) {
		options = {...url, ...options};
		url = options.url || {};
		delete options.url;
	}

	if (defaults) {
		options = merge({}, defaults.options, options ? preNormalize(options, defaults.options) : {});
	} else {
		options = merge({}, preNormalize(options));
	}

	if (!is.string(url) && !is.object(url)) {
		throw new TypeError(`Parameter \`url\` must be a string or object, not ${is(url)}`);
	}

	if (is.string(url)) {
		if (options.baseUrl) {
			if (url.toString().startsWith('/')) {
				url = url.toString().slice(1);
			}

			url = urlToOptions(new URL(url, options.baseUrl));
		} else {
			url = url.replace(/^unix:/, 'http://$&');
			url = urlParseLax(url);
		}
	} else if (is(url) === 'URL') {
		url = urlToOptions(url);
	}

	// Override both null/undefined with default protocol
	options = merge({path: ''}, url, {protocol: url.protocol || 'https:'}, options);

	for (const hook of options.hooks.init) {
		const called = hook(options);

		if (is.promise(called)) {
			throw new TypeError('The `init` hook must be a synchronous function');
		}
	}

	const {baseUrl} = options;
	Object.defineProperty(options, 'baseUrl', {
		set: () => {
			throw new Error('Failed to set baseUrl. Options are normalized already.');
		},
		get: () => baseUrl
	});

	const {query} = options;
	if (is.nonEmptyString(query) || is.nonEmptyObject(query) || query instanceof URLSearchParams) {
		if (!is.string(query)) {
			options.query = (new URLSearchParams(query)).toString();
		}

		options.path = `${options.path.split('?')[0]}?${options.query}`;
		delete options.query;
	}

	if (options.hostname === 'unix') {
		const matches = /(.+?):(.+)/.exec(options.path);

		if (matches) {
			const [, socketPath, path] = matches;
			options = {
				...options,
				socketPath,
				path,
				host: null
			};
		}
	}

	const {headers} = options;
	for (const [key, value] of Object.entries(headers)) {
		if (is.nullOrUndefined(value)) {
			delete headers[key];
		}
	}

	if (options.json && is.undefined(headers.accept)) {
		headers.accept = 'application/json';
	}

	if (options.decompress && is.undefined(headers['accept-encoding'])) {
		headers['accept-encoding'] = 'gzip, deflate';
	}

	const {body} = options;
	if (is.nullOrUndefined(body)) {
		options.method = options.method ? options.method.toUpperCase() : 'GET';
	} else {
		const isObject = is.object(body) && !is.buffer(body) && !is.nodeStream(body);
		if (!is.nodeStream(body) && !is.string(body) && !is.buffer(body) && !(options.form || options.json)) {
			throw new TypeError('The `body` option must be a stream.Readable, string or Buffer');
		}

		if (options.json && !(isObject || is.array(body))) {
			throw new TypeError('The `body` option must be an Object or Array when the `json` option is used');
		}

		if (options.form && !isObject) {
			throw new TypeError('The `body` option must be an Object when the `form` option is used');
		}

		if (isFormData(body)) {
			// Special case for https://github.com/form-data/form-data
			headers['content-type'] = headers['content-type'] || `multipart/form-data; boundary=${body.getBoundary()}`;
		} else if (options.form) {
			headers['content-type'] = headers['content-type'] || 'application/x-www-form-urlencoded';
			options.body = (new URLSearchParams(body)).toString();
		} else if (options.json) {
			headers['content-type'] = headers['content-type'] || 'application/json';
			options.body = JSON.stringify(body);
		}

		options.method = options.method ? options.method.toUpperCase() : 'POST';
	}

	if (!is.function(options.retry.retries)) {
		const {retries} = options.retry;

		options.retry.retries = (iteration, error) => {
			if (iteration > retries) {
				return 0;
			}

			if ((!error || !options.retry.errorCodes.has(error.code)) && (!options.retry.methods.has(error.method) || !options.retry.statusCodes.has(error.statusCode))) {
				return 0;
			}

			if (Reflect.has(error, 'headers') && Reflect.has(error.headers, 'retry-after') && retryAfterStatusCodes.has(error.statusCode)) {
				let after = Number(error.headers['retry-after']);
				if (is.nan(after)) {
					after = Date.parse(error.headers['retry-after']) - Date.now();
				} else {
					after *= 1000;
				}

				if (after > options.retry.maxRetryAfter) {
					return 0;
				}

				return after;
			}

			if (error.statusCode === 413) {
				return 0;
			}

			const noise = Math.random() * 100;
			return ((2 ** (iteration - 1)) * 1000) + noise;
		};
	}

	return options;
};

const reNormalize = options => normalize(urlLib.format(options), options);

module.exports = normalize;
module.exports.preNormalize = preNormalize;
module.exports.reNormalize = reNormalize;


/***/ }),

/***/ "wkBG":
/***/ (function(module, exports, __webpack_require__) {

"use strict";
exports.__esModule=true;exports.normalizePathSep=normalizePathSep;exports.denormalizePagePath=denormalizePagePath;function normalizePathSep(path){return path.replace(/\\/g,'/');}function denormalizePagePath(page){page=normalizePathSep(page);if(page.startsWith('/index/')){page=page.slice(6);}else if(page==='/index'){page='/';}return page;}
//# sourceMappingURL=denormalize-page-path.js.map

/***/ }),

/***/ "xG1e":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const AssertError = __webpack_require__("DWQ6");

const internals = {};


module.exports = function (condition, ...args) {

    if (condition) {
        return;
    }

    if (args.length === 1 &&
        args[0] instanceof Error) {

        throw args[0];
    }

    throw new AssertError(args);
};


/***/ }),

/***/ "xZ+y":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tls_1 = __webpack_require__("ugmf");
const deferToConnect = (socket, fn) => {
    let listeners;
    if (typeof fn === 'function') {
        const connect = fn;
        listeners = { connect };
    }
    else {
        listeners = fn;
    }
    const hasConnectListener = typeof listeners.connect === 'function';
    const hasSecureConnectListener = typeof listeners.secureConnect === 'function';
    const hasCloseListener = typeof listeners.close === 'function';
    const onConnect = () => {
        if (hasConnectListener) {
            listeners.connect();
        }
        if (socket instanceof tls_1.TLSSocket && hasSecureConnectListener) {
            if (socket.authorized) {
                listeners.secureConnect();
            }
            else if (!socket.authorizationError) {
                socket.once('secureConnect', listeners.secureConnect);
            }
        }
        if (hasCloseListener) {
            socket.once('close', listeners.close);
        }
    };
    if (socket.writable && !socket.connecting) {
        onConnect();
    }
    else if (socket.connecting) {
        socket.once('connect', onConnect);
    }
    else if (socket.destroyed && hasCloseListener) {
        listeners.close(socket._hadError);
    }
};
exports.default = deferToConnect;
// For CommonJS default export support
module.exports = deferToConnect;
module.exports.default = deferToConnect;


/***/ }),

/***/ "xZSz":
/***/ (function(module, exports, __webpack_require__) {

module.exports = {
  JWE: __webpack_require__("9AeD"),
  JWK: __webpack_require__("lA9T"),
  JWKS: __webpack_require__("WPgm"),
  JWS: __webpack_require__("sR+5"),
  JWT: __webpack_require__("zKJz"),
  errors: __webpack_require__("yt7c")
}


/***/ }),

/***/ "xfr8":
/***/ (function(module, exports, __webpack_require__) {

const generateIV = __webpack_require__("X3uD")
const base64url = __webpack_require__("Xab3")

module.exports = (JWA, JWK) => {
  ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'].forEach((jwaAlg) => {
    const encAlg = jwaAlg.substr(0, 7)
    const size = parseInt(jwaAlg.substr(1, 3), 10)
    const encrypt = JWA.encrypt.get(encAlg)
    const decrypt = JWA.decrypt.get(encAlg)

    if (encrypt && decrypt) {
      JWA.keyManagementEncrypt.set(jwaAlg, (key, payload) => {
        const iv = generateIV(jwaAlg)
        const { ciphertext, tag } = encrypt(key, payload, { iv })
        return {
          wrapped: ciphertext,
          header: { tag: base64url.encodeBuffer(tag), iv: base64url.encodeBuffer(iv) }
        }
      })
      JWA.keyManagementDecrypt.set(jwaAlg, decrypt)
      JWK.oct.wrapKey[jwaAlg] = JWK.oct.unwrapKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.length === size
    }
  })
}


/***/ }),

/***/ "xh2E":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const indentString = __webpack_require__("S6im");
const cleanStack = __webpack_require__("9rVn");

const cleanInternalStack = stack => stack.replace(/\s+at .*aggregate-error\/index.js:\d+:\d+\)?/g, '');

class AggregateError extends Error {
	constructor(errors) {
		if (!Array.isArray(errors)) {
			throw new TypeError(`Expected input to be an Array, got ${typeof errors}`);
		}

		errors = [...errors].map(error => {
			if (error instanceof Error) {
				return error;
			}

			if (error !== null && typeof error === 'object') {
				// Handle plain error objects with message property and/or possibly other metadata
				return Object.assign(new Error(error.message), error);
			}

			return new Error(error);
		});

		let message = errors
			.map(error => {
				// The `stack` property is not standardized, so we can't assume it exists
				return typeof error.stack === 'string' ? cleanInternalStack(cleanStack(error.stack)) : String(error);
			})
			.join('\n');
		message = '\n' + indentString(message, 4);
		super(message);

		this.name = 'AggregateError';

		Object.defineProperty(this, '_errors', {value: errors});
	}

	* [Symbol.iterator]() {
		for (const error of this._errors) {
			yield error;
		}
	}
}

module.exports = AggregateError;


/***/ }),

/***/ "xkC2":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("2BAz");
const Clone = __webpack_require__("JT7C");
const Merge = __webpack_require__("8AeH");
const Utils = __webpack_require__("3J/O");


const internals = {};


module.exports = function (defaults, source, options = {}) {

    Assert(defaults && typeof defaults === 'object', 'Invalid defaults value: must be an object');
    Assert(!source || source === true || typeof source === 'object', 'Invalid source value: must be true, falsy or an object');
    Assert(typeof options === 'object', 'Invalid options: must be an object');

    if (!source) {                                                  // If no source, return null
        return null;
    }

    if (options.shallow) {
        return internals.applyToDefaultsWithShallow(defaults, source, options);
    }

    const copy = Clone(defaults);

    if (source === true) {                                          // If source is set to true, use defaults
        return copy;
    }

    const nullOverride = options.nullOverride !== undefined ? options.nullOverride : false;
    return Merge(copy, source, { nullOverride, mergeArrays: false });
};


internals.applyToDefaultsWithShallow = function (defaults, source, options) {

    const keys = options.shallow;
    Assert(Array.isArray(keys), 'Invalid keys');

    options = Object.assign({}, options);
    options.shallow = false;

    const copy = Clone(defaults, { shallow: keys });

    if (source === true) {                                                      // If source is set to true, use defaults
        return copy;
    }

    const storage = Utils.store(source, keys);                              // Move shallow copy items to storage
    Merge(copy, source, { mergeArrays: false, nullOverride: false });   // Deep copy the rest
    Utils.restore(copy, source, storage);                                   // Shallow copy the stored items and restore
    return copy;
};


/***/ }),

/***/ "y/nk":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const {URL} = __webpack_require__("bzos"); // TODO: Use the `URL` global when targeting Node.js 10
const util = __webpack_require__("jK02");
const EventEmitter = __webpack_require__("/0p4");
const http = __webpack_require__("KEll");
const https = __webpack_require__("7WL4");
const urlLib = __webpack_require__("bzos");
const CacheableRequest = __webpack_require__("eC53");
const toReadableStream = __webpack_require__("MrQC");
const is = __webpack_require__("6mOv");
const timer = __webpack_require__("j0Yl");
const timedOut = __webpack_require__("2IvE");
const getBodySize = __webpack_require__("10GS");
const getResponse = __webpack_require__("zFNg");
const progress = __webpack_require__("K0QS");
const {CacheError, UnsupportedProtocolError, MaxRedirectsError, RequestError, TimeoutError} = __webpack_require__("9Fi5");
const urlToOptions = __webpack_require__("NHoT");

const getMethodRedirectCodes = new Set([300, 301, 302, 303, 304, 305, 307, 308]);
const allMethodRedirectCodes = new Set([300, 303, 307, 308]);

module.exports = (options, input) => {
	const emitter = new EventEmitter();
	const redirects = [];
	let currentRequest;
	let requestUrl;
	let redirectString;
	let uploadBodySize;
	let retryCount = 0;
	let shouldAbort = false;

	const setCookie = options.cookieJar ? util.promisify(options.cookieJar.setCookie.bind(options.cookieJar)) : null;
	const getCookieString = options.cookieJar ? util.promisify(options.cookieJar.getCookieString.bind(options.cookieJar)) : null;
	const agents = is.object(options.agent) ? options.agent : null;

	const emitError = async error => {
		try {
			for (const hook of options.hooks.beforeError) {
				// eslint-disable-next-line no-await-in-loop
				error = await hook(error);
			}

			emitter.emit('error', error);
		} catch (error2) {
			emitter.emit('error', error2);
		}
	};

	const get = async options => {
		const currentUrl = redirectString || requestUrl;

		if (options.protocol !== 'http:' && options.protocol !== 'https:') {
			throw new UnsupportedProtocolError(options);
		}

		decodeURI(currentUrl);

		let fn;
		if (is.function(options.request)) {
			fn = {request: options.request};
		} else {
			fn = options.protocol === 'https:' ? https : http;
		}

		if (agents) {
			const protocolName = options.protocol === 'https:' ? 'https' : 'http';
			options.agent = agents[protocolName] || options.agent;
		}

		/* istanbul ignore next: electron.net is broken */
		if (options.useElectronNet && process.versions.electron) {
			const r = ({x: __webpack_require__("/SMw")})['yx'.slice(1)]; // Trick webpack
			const electron = r('electron');
			fn = electron.net || electron.remote.net;
		}

		if (options.cookieJar) {
			const cookieString = await getCookieString(currentUrl, {});

			if (is.nonEmptyString(cookieString)) {
				options.headers.cookie = cookieString;
			}
		}

		let timings;
		const handleResponse = async response => {
			try {
				/* istanbul ignore next: fixes https://github.com/electron/electron/blob/cbb460d47628a7a146adf4419ed48550a98b2923/lib/browser/api/net.js#L59-L65 */
				if (options.useElectronNet) {
					response = new Proxy(response, {
						get: (target, name) => {
							if (name === 'trailers' || name === 'rawTrailers') {
								return [];
							}

							const value = target[name];
							return is.function(value) ? value.bind(target) : value;
						}
					});
				}

				const {statusCode} = response;
				response.url = currentUrl;
				response.requestUrl = requestUrl;
				response.retryCount = retryCount;
				response.timings = timings;
				response.redirectUrls = redirects;
				response.request = {
					gotOptions: options
				};

				const rawCookies = response.headers['set-cookie'];
				if (options.cookieJar && rawCookies) {
					await Promise.all(rawCookies.map(rawCookie => setCookie(rawCookie, response.url)));
				}

				if (options.followRedirect && 'location' in response.headers) {
					if (allMethodRedirectCodes.has(statusCode) || (getMethodRedirectCodes.has(statusCode) && (options.method === 'GET' || options.method === 'HEAD'))) {
						response.resume(); // We're being redirected, we don't care about the response.

						if (statusCode === 303) {
							// Server responded with "see other", indicating that the resource exists at another location,
							// and the client should request it from that location via GET or HEAD.
							options.method = 'GET';
						}

						if (redirects.length >= 10) {
							throw new MaxRedirectsError(statusCode, redirects, options);
						}

						// Handles invalid URLs. See https://github.com/sindresorhus/got/issues/604
						const redirectBuffer = Buffer.from(response.headers.location, 'binary').toString();
						const redirectURL = new URL(redirectBuffer, currentUrl);
						redirectString = redirectURL.toString();

						redirects.push(redirectString);

						const redirectOptions = {
							...options,
							...urlToOptions(redirectURL)
						};

						for (const hook of options.hooks.beforeRedirect) {
							// eslint-disable-next-line no-await-in-loop
							await hook(redirectOptions);
						}

						emitter.emit('redirect', response, redirectOptions);

						await get(redirectOptions);
						return;
					}
				}

				getResponse(response, options, emitter);
			} catch (error) {
				emitError(error);
			}
		};

		const handleRequest = request => {
			if (shouldAbort) {
				request.once('error', () => {});
				request.abort();
				return;
			}

			currentRequest = request;

			request.once('error', error => {
				if (request.aborted) {
					return;
				}

				if (error instanceof timedOut.TimeoutError) {
					error = new TimeoutError(error, options);
				} else {
					error = new RequestError(error, options);
				}

				if (emitter.retry(error) === false) {
					emitError(error);
				}
			});

			timings = timer(request);

			progress.upload(request, emitter, uploadBodySize);

			if (options.gotTimeout) {
				timedOut(request, options.gotTimeout, options);
			}

			emitter.emit('request', request);

			const uploadComplete = () => {
				request.emit('upload-complete');
			};

			try {
				if (is.nodeStream(options.body)) {
					options.body.once('end', uploadComplete);
					options.body.pipe(request);
					options.body = undefined;
				} else if (options.body) {
					request.end(options.body, uploadComplete);
				} else if (input && (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH')) {
					input.once('end', uploadComplete);
					input.pipe(request);
				} else {
					request.end(uploadComplete);
				}
			} catch (error) {
				emitError(new RequestError(error, options));
			}
		};

		if (options.cache) {
			const cacheableRequest = new CacheableRequest(fn.request, options.cache);
			const cacheRequest = cacheableRequest(options, handleResponse);

			cacheRequest.once('error', error => {
				if (error instanceof CacheableRequest.RequestError) {
					emitError(new RequestError(error, options));
				} else {
					emitError(new CacheError(error, options));
				}
			});

			cacheRequest.once('request', handleRequest);
		} else {
			// Catches errors thrown by calling fn.request(...)
			try {
				handleRequest(fn.request(options, handleResponse));
			} catch (error) {
				emitError(new RequestError(error, options));
			}
		}
	};

	emitter.retry = error => {
		let backoff;

		try {
			backoff = options.retry.retries(++retryCount, error);
		} catch (error2) {
			emitError(error2);
			return;
		}

		if (backoff) {
			const retry = async options => {
				try {
					for (const hook of options.hooks.beforeRetry) {
						// eslint-disable-next-line no-await-in-loop
						await hook(options, error, retryCount);
					}

					await get(options);
				} catch (error) {
					emitError(error);
				}
			};

			setTimeout(retry, backoff, {...options, forceRefresh: true});
			return true;
		}

		return false;
	};

	emitter.abort = () => {
		if (currentRequest) {
			currentRequest.once('error', () => {});
			currentRequest.abort();
		} else {
			shouldAbort = true;
		}
	};

	setImmediate(async () => {
		try {
			// Convert buffer to stream to receive upload progress events (#322)
			const {body} = options;
			if (is.buffer(body)) {
				options.body = toReadableStream(body);
				uploadBodySize = body.length;
			} else {
				uploadBodySize = await getBodySize(options);
			}

			if (is.undefined(options.headers['content-length']) && is.undefined(options.headers['transfer-encoding'])) {
				if ((uploadBodySize > 0 || options.method === 'PUT') && !is.null(uploadBodySize)) {
					options.headers['content-length'] = uploadBodySize;
				}
			}

			for (const hook of options.hooks.beforeRequest) {
				// eslint-disable-next-line no-await-in-loop
				await hook(options);
			}

			requestUrl = options.href || (new URL(options.path, urlLib.format(options))).toString();

			await get(options);
		} catch (error) {
			emitError(error);
		}
	});

	return emitter;
};


/***/ }),

/***/ "y1+z":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

module.exports = function (obj) {
	var ret = {};
	var keys = Object.keys(Object(obj));

	for (var i = 0; i < keys.length; i++) {
		ret[keys[i].toLowerCase()] = obj[keys[i]];
	}

	return ret;
};


/***/ }),

/***/ "yAVD":
/***/ (function(module, exports, __webpack_require__) {

const oids = __webpack_require__("ScBA")

module.exports = function () {
  this.seq().obj(
    this.key('algorithm').objid(oids),
    this.key('parameters').optional().choice({ namedCurve: this.objid(oids), null: this.null_() })
  )
}


/***/ }),

/***/ "yt7c":
/***/ (function(module, exports) {

const CODES = {
  JOSEAlgNotWhitelisted: 'ERR_JOSE_ALG_NOT_WHITELISTED',
  JOSECritNotUnderstood: 'ERR_JOSE_CRIT_NOT_UNDERSTOOD',
  JOSEInvalidEncoding: 'ERR_JOSE_INVALID_ENCODING',
  JOSEMultiError: 'ERR_JOSE_MULTIPLE_ERRORS',
  JOSENotSupported: 'ERR_JOSE_NOT_SUPPORTED',
  JWEDecryptionFailed: 'ERR_JWE_DECRYPTION_FAILED',
  JWEInvalid: 'ERR_JWE_INVALID',
  JWKImportFailed: 'ERR_JWK_IMPORT_FAILED',
  JWKInvalid: 'ERR_JWK_INVALID',
  JWKKeySupport: 'ERR_JWK_KEY_SUPPORT',
  JWKSNoMatchingKey: 'ERR_JWKS_NO_MATCHING_KEY',
  JWSInvalid: 'ERR_JWS_INVALID',
  JWSVerificationFailed: 'ERR_JWS_VERIFICATION_FAILED',
  JWTClaimInvalid: 'ERR_JWT_CLAIM_INVALID',
  JWTExpired: 'ERR_JWT_EXPIRED',
  JWTMalformed: 'ERR_JWT_MALFORMED'
}

const DEFAULT_MESSAGES = {
  JWEDecryptionFailed: 'decryption operation failed',
  JWEInvalid: 'JWE invalid',
  JWKSNoMatchingKey: 'no matching key found in the KeyStore',
  JWSInvalid: 'JWS invalid',
  JWSVerificationFailed: 'signature verification failed'
}

class JOSEError extends Error {
  constructor (message) {
    super(message)
    if (message === undefined) {
      this.message = DEFAULT_MESSAGES[this.constructor.name]
    }
    this.name = this.constructor.name
    this.code = CODES[this.constructor.name]
    Error.captureStackTrace(this, this.constructor)
  }
}

const isMulti = e => e instanceof JOSEMultiError
class JOSEMultiError extends JOSEError {
  constructor (errors) {
    super()
    let i
    while ((i = errors.findIndex(isMulti)) && i !== -1) {
      errors.splice(i, 1, ...errors[i])
    }
    Object.defineProperty(this, 'errors', { value: errors })
  }

  * [Symbol.iterator] () {
    for (const error of this.errors) {
      yield error
    }
  }
}
module.exports.JOSEError = JOSEError

module.exports.JOSEAlgNotWhitelisted = class JOSEAlgNotWhitelisted extends JOSEError {}
module.exports.JOSECritNotUnderstood = class JOSECritNotUnderstood extends JOSEError {}
module.exports.JOSEInvalidEncoding = class JOSEInvalidEncoding extends JOSEError {}
module.exports.JOSEMultiError = JOSEMultiError
module.exports.JOSENotSupported = class JOSENotSupported extends JOSEError {}

module.exports.JWEDecryptionFailed = class JWEDecryptionFailed extends JOSEError {}
module.exports.JWEInvalid = class JWEInvalid extends JOSEError {}

module.exports.JWKImportFailed = class JWKImportFailed extends JOSEError {}
module.exports.JWKInvalid = class JWKInvalid extends JOSEError {}
module.exports.JWKKeySupport = class JWKKeySupport extends JOSEError {}

module.exports.JWKSNoMatchingKey = class JWKSNoMatchingKey extends JOSEError {}

module.exports.JWSInvalid = class JWSInvalid extends JOSEError {}
module.exports.JWSVerificationFailed = class JWSVerificationFailed extends JOSEError {}

class JWTClaimInvalid extends JOSEError {
  constructor (message, claim = 'unspecified', reason = 'unspecified') {
    super(message)
    this.claim = claim
    this.reason = reason
  }
}
module.exports.JWTClaimInvalid = JWTClaimInvalid
module.exports.JWTExpired = class JWTExpired extends JWTClaimInvalid {}
module.exports.JWTMalformed = class JWTMalformed extends JOSEError {}


/***/ }),

/***/ "z/H/":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const is = __webpack_require__("6mOv");

module.exports = function deepFreeze(object) {
	for (const [key, value] of Object.entries(object)) {
		if (is.plainObject(value) || is.array(value)) {
			deepFreeze(object[key]);
		}
	}

	return Object.freeze(object);
};


/***/ }),

/***/ "zFNg":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

const decompressResponse = __webpack_require__("YNnK");
const is = __webpack_require__("6mOv");
const mimicResponse = __webpack_require__("qsvm");
const progress = __webpack_require__("K0QS");

module.exports = (response, options, emitter) => {
	const downloadBodySize = Number(response.headers['content-length']) || null;

	const progressStream = progress.download(response, emitter, downloadBodySize);

	mimicResponse(response, progressStream);

	const newResponse = options.decompress === true &&
		is.function(decompressResponse) &&
		options.method !== 'HEAD' ? decompressResponse(progressStream) : progressStream;

	if (!options.decompress && ['gzip', 'deflate'].includes(response.headers['content-encoding'])) {
		options.encoding = null;
	}

	emitter.emit('response', newResponse);

	emitter.emit('downloadProgress', {
		percent: 0,
		transferred: 0,
		total: downloadBodySize
	});

	response.pipe(progressStream);
};


/***/ }),

/***/ "zKJz":
/***/ (function(module, exports, __webpack_require__) {

const decode = __webpack_require__("7o4N")
const sign = __webpack_require__("6I+L")
const verify = __webpack_require__("BOd6")
const profiles = __webpack_require__("qXE0")

module.exports = {
  decode,
  sign,
  verify,
  ...profiles
}


/***/ }),

/***/ "zOht":
/***/ (function(module, exports, __webpack_require__) {

var __WEBPACK_AMD_DEFINE_ARRAY__, __WEBPACK_AMD_DEFINE_RESULT__;/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

/* global global, define, System, Reflect, Promise */
var __extends;
var __assign;
var __rest;
var __decorate;
var __param;
var __metadata;
var __awaiter;
var __generator;
var __exportStar;
var __values;
var __read;
var __spread;
var __spreadArrays;
var __await;
var __asyncGenerator;
var __asyncDelegator;
var __asyncValues;
var __makeTemplateObject;
var __importStar;
var __importDefault;
var __classPrivateFieldGet;
var __classPrivateFieldSet;
var __createBinding;
(function (factory) {
    var root = typeof global === "object" ? global : typeof self === "object" ? self : typeof this === "object" ? this : {};
    if (true) {
        !(__WEBPACK_AMD_DEFINE_ARRAY__ = [exports], __WEBPACK_AMD_DEFINE_RESULT__ = (function (exports) { factory(createExporter(root, createExporter(exports))); }).apply(exports, __WEBPACK_AMD_DEFINE_ARRAY__),
				__WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__));
    }
    else {}
    function createExporter(exports, previous) {
        if (exports !== root) {
            if (typeof Object.create === "function") {
                Object.defineProperty(exports, "__esModule", { value: true });
            }
            else {
                exports.__esModule = true;
            }
        }
        return function (id, v) { return exports[id] = previous ? previous(id, v) : v; };
    }
})
(function (exporter) {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };

    __extends = function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };

    __assign = Object.assign || function (t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };

    __rest = function (s, e) {
        var t = {};
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
            t[p] = s[p];
        if (s != null && typeof Object.getOwnPropertySymbols === "function")
            for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
                if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                    t[p[i]] = s[p[i]];
            }
        return t;
    };

    __decorate = function (decorators, target, key, desc) {
        var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
        if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
        else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
        return c > 3 && r && Object.defineProperty(target, key, r), r;
    };

    __param = function (paramIndex, decorator) {
        return function (target, key) { decorator(target, key, paramIndex); }
    };

    __metadata = function (metadataKey, metadataValue) {
        if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
    };

    __awaiter = function (thisArg, _arguments, P, generator) {
        function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
        return new (P || (P = Promise))(function (resolve, reject) {
            function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
            function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
            function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
            step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
    };

    __generator = function (thisArg, body) {
        var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
        function verb(n) { return function (v) { return step([n, v]); }; }
        function step(op) {
            if (f) throw new TypeError("Generator is already executing.");
            while (_) try {
                if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                if (y = 0, t) op = [op[0] & 2, t.value];
                switch (op[0]) {
                    case 0: case 1: t = op; break;
                    case 4: _.label++; return { value: op[1], done: false };
                    case 5: _.label++; y = op[1]; op = [0]; continue;
                    case 7: op = _.ops.pop(); _.trys.pop(); continue;
                    default:
                        if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                        if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                        if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                        if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                        if (t[2]) _.ops.pop();
                        _.trys.pop(); continue;
                }
                op = body.call(thisArg, _);
            } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
            if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
        }
    };

    __createBinding = function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
    };

    __exportStar = function (m, exports) {
        for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
    };

    __values = function (o) {
        var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
        if (m) return m.call(o);
        if (o && typeof o.length === "number") return {
            next: function () {
                if (o && i >= o.length) o = void 0;
                return { value: o && o[i++], done: !o };
            }
        };
        throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
    };

    __read = function (o, n) {
        var m = typeof Symbol === "function" && o[Symbol.iterator];
        if (!m) return o;
        var i = m.call(o), r, ar = [], e;
        try {
            while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
        }
        catch (error) { e = { error: error }; }
        finally {
            try {
                if (r && !r.done && (m = i["return"])) m.call(i);
            }
            finally { if (e) throw e.error; }
        }
        return ar;
    };

    __spread = function () {
        for (var ar = [], i = 0; i < arguments.length; i++)
            ar = ar.concat(__read(arguments[i]));
        return ar;
    };

    __spreadArrays = function () {
        for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
        for (var r = Array(s), k = 0, i = 0; i < il; i++)
            for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
                r[k] = a[j];
        return r;
    };

    __await = function (v) {
        return this instanceof __await ? (this.v = v, this) : new __await(v);
    };

    __asyncGenerator = function (thisArg, _arguments, generator) {
        if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
        var g = generator.apply(thisArg, _arguments || []), i, q = [];
        return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
        function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
        function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
        function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r);  }
        function fulfill(value) { resume("next", value); }
        function reject(value) { resume("throw", value); }
        function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
    };

    __asyncDelegator = function (o) {
        var i, p;
        return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
        function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
    };

    __asyncValues = function (o) {
        if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
        var m = o[Symbol.asyncIterator], i;
        return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
        function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
        function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
    };

    __makeTemplateObject = function (cooked, raw) {
        if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
        return cooked;
    };

    __importStar = function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
        result["default"] = mod;
        return result;
    };

    __importDefault = function (mod) {
        return (mod && mod.__esModule) ? mod : { "default": mod };
    };

    __classPrivateFieldGet = function (receiver, privateMap) {
        if (!privateMap.has(receiver)) {
            throw new TypeError("attempted to get private field on non-instance");
        }
        return privateMap.get(receiver);
    };

    __classPrivateFieldSet = function (receiver, privateMap, value) {
        if (!privateMap.has(receiver)) {
            throw new TypeError("attempted to set private field on non-instance");
        }
        privateMap.set(receiver, value);
        return value;
    };

    exporter("__extends", __extends);
    exporter("__assign", __assign);
    exporter("__rest", __rest);
    exporter("__decorate", __decorate);
    exporter("__param", __param);
    exporter("__metadata", __metadata);
    exporter("__awaiter", __awaiter);
    exporter("__generator", __generator);
    exporter("__exportStar", __exportStar);
    exporter("__createBinding", __createBinding);
    exporter("__values", __values);
    exporter("__read", __read);
    exporter("__spread", __spread);
    exporter("__spreadArrays", __spreadArrays);
    exporter("__await", __await);
    exporter("__asyncGenerator", __asyncGenerator);
    exporter("__asyncDelegator", __asyncDelegator);
    exporter("__asyncValues", __asyncValues);
    exporter("__makeTemplateObject", __makeTemplateObject);
    exporter("__importStar", __importStar);
    exporter("__importDefault", __importDefault);
    exporter("__classPrivateFieldGet", __classPrivateFieldGet);
    exporter("__classPrivateFieldSet", __classPrivateFieldSet);
});


/***/ }),

/***/ "zOyy":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Tokenize input string.
 */
function lexer(str) {
    var tokens = [];
    var i = 0;
    while (i < str.length) {
        var char = str[i];
        if (char === "*" || char === "+" || char === "?") {
            tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
            continue;
        }
        if (char === "\\") {
            tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
            continue;
        }
        if (char === "{") {
            tokens.push({ type: "OPEN", index: i, value: str[i++] });
            continue;
        }
        if (char === "}") {
            tokens.push({ type: "CLOSE", index: i, value: str[i++] });
            continue;
        }
        if (char === ":") {
            var name = "";
            var j = i + 1;
            while (j < str.length) {
                var code = str.charCodeAt(j);
                if (
                // `0-9`
                (code >= 48 && code <= 57) ||
                    // `A-Z`
                    (code >= 65 && code <= 90) ||
                    // `a-z`
                    (code >= 97 && code <= 122) ||
                    // `_`
                    code === 95) {
                    name += str[j++];
                    continue;
                }
                break;
            }
            if (!name)
                throw new TypeError("Missing parameter name at " + i);
            tokens.push({ type: "NAME", index: i, value: name });
            i = j;
            continue;
        }
        if (char === "(") {
            var count = 1;
            var pattern = "";
            var j = i + 1;
            if (str[j] === "?") {
                throw new TypeError("Pattern cannot start with \"?\" at " + j);
            }
            while (j < str.length) {
                if (str[j] === "\\") {
                    pattern += str[j++] + str[j++];
                    continue;
                }
                if (str[j] === ")") {
                    count--;
                    if (count === 0) {
                        j++;
                        break;
                    }
                }
                else if (str[j] === "(") {
                    count++;
                    if (str[j + 1] !== "?") {
                        throw new TypeError("Capturing groups are not allowed at " + j);
                    }
                }
                pattern += str[j++];
            }
            if (count)
                throw new TypeError("Unbalanced pattern at " + i);
            if (!pattern)
                throw new TypeError("Missing pattern at " + i);
            tokens.push({ type: "PATTERN", index: i, value: pattern });
            i = j;
            continue;
        }
        tokens.push({ type: "CHAR", index: i, value: str[i++] });
    }
    tokens.push({ type: "END", index: i, value: "" });
    return tokens;
}
/**
 * Parse a string for the raw tokens.
 */
function parse(str, options) {
    if (options === void 0) { options = {}; }
    var tokens = lexer(str);
    var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a;
    var defaultPattern = "[^" + escapeString(options.delimiter || "/#?") + "]+?";
    var result = [];
    var key = 0;
    var i = 0;
    var path = "";
    var tryConsume = function (type) {
        if (i < tokens.length && tokens[i].type === type)
            return tokens[i++].value;
    };
    var mustConsume = function (type) {
        var value = tryConsume(type);
        if (value !== undefined)
            return value;
        var _a = tokens[i], nextType = _a.type, index = _a.index;
        throw new TypeError("Unexpected " + nextType + " at " + index + ", expected " + type);
    };
    var consumeText = function () {
        var result = "";
        var value;
        // tslint:disable-next-line
        while ((value = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR"))) {
            result += value;
        }
        return result;
    };
    while (i < tokens.length) {
        var char = tryConsume("CHAR");
        var name = tryConsume("NAME");
        var pattern = tryConsume("PATTERN");
        if (name || pattern) {
            var prefix = char || "";
            if (prefixes.indexOf(prefix) === -1) {
                path += prefix;
                prefix = "";
            }
            if (path) {
                result.push(path);
                path = "";
            }
            result.push({
                name: name || key++,
                prefix: prefix,
                suffix: "",
                pattern: pattern || defaultPattern,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        var value = char || tryConsume("ESCAPED_CHAR");
        if (value) {
            path += value;
            continue;
        }
        if (path) {
            result.push(path);
            path = "";
        }
        var open = tryConsume("OPEN");
        if (open) {
            var prefix = consumeText();
            var name_1 = tryConsume("NAME") || "";
            var pattern_1 = tryConsume("PATTERN") || "";
            var suffix = consumeText();
            mustConsume("CLOSE");
            result.push({
                name: name_1 || (pattern_1 ? key++ : ""),
                pattern: name_1 && !pattern_1 ? defaultPattern : pattern_1,
                prefix: prefix,
                suffix: suffix,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        mustConsume("END");
    }
    return result;
}
exports.parse = parse;
/**
 * Compile a string to a template function for the path.
 */
function compile(str, options) {
    return tokensToFunction(parse(str, options), options);
}
exports.compile = compile;
/**
 * Expose a method for transforming tokens into the path function.
 */
function tokensToFunction(tokens, options) {
    if (options === void 0) { options = {}; }
    var reFlags = flags(options);
    var _a = options.encode, encode = _a === void 0 ? function (x) { return x; } : _a, _b = options.validate, validate = _b === void 0 ? true : _b;
    // Compile all the tokens into regexps.
    var matches = tokens.map(function (token) {
        if (typeof token === "object") {
            return new RegExp("^(?:" + token.pattern + ")$", reFlags);
        }
    });
    return function (data) {
        var path = "";
        for (var i = 0; i < tokens.length; i++) {
            var token = tokens[i];
            if (typeof token === "string") {
                path += token;
                continue;
            }
            var value = data ? data[token.name] : undefined;
            var optional = token.modifier === "?" || token.modifier === "*";
            var repeat = token.modifier === "*" || token.modifier === "+";
            if (Array.isArray(value)) {
                if (!repeat) {
                    throw new TypeError("Expected \"" + token.name + "\" to not repeat, but got an array");
                }
                if (value.length === 0) {
                    if (optional)
                        continue;
                    throw new TypeError("Expected \"" + token.name + "\" to not be empty");
                }
                for (var j = 0; j < value.length; j++) {
                    var segment = encode(value[j], token);
                    if (validate && !matches[i].test(segment)) {
                        throw new TypeError("Expected all \"" + token.name + "\" to match \"" + token.pattern + "\", but got \"" + segment + "\"");
                    }
                    path += token.prefix + segment + token.suffix;
                }
                continue;
            }
            if (typeof value === "string" || typeof value === "number") {
                var segment = encode(String(value), token);
                if (validate && !matches[i].test(segment)) {
                    throw new TypeError("Expected \"" + token.name + "\" to match \"" + token.pattern + "\", but got \"" + segment + "\"");
                }
                path += token.prefix + segment + token.suffix;
                continue;
            }
            if (optional)
                continue;
            var typeOfMessage = repeat ? "an array" : "a string";
            throw new TypeError("Expected \"" + token.name + "\" to be " + typeOfMessage);
        }
        return path;
    };
}
exports.tokensToFunction = tokensToFunction;
/**
 * Create path match function from `path-to-regexp` spec.
 */
function match(str, options) {
    var keys = [];
    var re = pathToRegexp(str, keys, options);
    return regexpToFunction(re, keys, options);
}
exports.match = match;
/**
 * Create a path match function from `path-to-regexp` output.
 */
function regexpToFunction(re, keys, options) {
    if (options === void 0) { options = {}; }
    var _a = options.decode, decode = _a === void 0 ? function (x) { return x; } : _a;
    return function (pathname) {
        var m = re.exec(pathname);
        if (!m)
            return false;
        var path = m[0], index = m.index;
        var params = Object.create(null);
        var _loop_1 = function (i) {
            // tslint:disable-next-line
            if (m[i] === undefined)
                return "continue";
            var key = keys[i - 1];
            if (key.modifier === "*" || key.modifier === "+") {
                params[key.name] = m[i].split(key.prefix + key.suffix).map(function (value) {
                    return decode(value, key);
                });
            }
            else {
                params[key.name] = decode(m[i], key);
            }
        };
        for (var i = 1; i < m.length; i++) {
            _loop_1(i);
        }
        return { path: path, index: index, params: params };
    };
}
exports.regexpToFunction = regexpToFunction;
/**
 * Escape a regular expression string.
 */
function escapeString(str) {
    return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
/**
 * Get the flags for a regexp from the options.
 */
function flags(options) {
    return options && options.sensitive ? "" : "i";
}
/**
 * Pull out keys from a regexp.
 */
function regexpToRegexp(path, keys) {
    if (!keys)
        return path;
    // Use a negative lookahead to match only capturing groups.
    var groups = path.source.match(/\((?!\?)/g);
    if (groups) {
        for (var i = 0; i < groups.length; i++) {
            keys.push({
                name: i,
                prefix: "",
                suffix: "",
                modifier: "",
                pattern: ""
            });
        }
    }
    return path;
}
/**
 * Transform an array into a regexp.
 */
function arrayToRegexp(paths, keys, options) {
    var parts = paths.map(function (path) { return pathToRegexp(path, keys, options).source; });
    return new RegExp("(?:" + parts.join("|") + ")", flags(options));
}
/**
 * Create a path regexp from string input.
 */
function stringToRegexp(path, keys, options) {
    return tokensToRegexp(parse(path, options), keys, options);
}
/**
 * Expose a function for taking tokens and returning a RegExp.
 */
function tokensToRegexp(tokens, keys, options) {
    if (options === void 0) { options = {}; }
    var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function (x) { return x; } : _d;
    var endsWith = "[" + escapeString(options.endsWith || "") + "]|$";
    var delimiter = "[" + escapeString(options.delimiter || "/#?") + "]";
    var route = start ? "^" : "";
    // Iterate over the tokens and create our regexp string.
    for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
        var token = tokens_1[_i];
        if (typeof token === "string") {
            route += escapeString(encode(token));
        }
        else {
            var prefix = escapeString(encode(token.prefix));
            var suffix = escapeString(encode(token.suffix));
            if (token.pattern) {
                if (keys)
                    keys.push(token);
                if (prefix || suffix) {
                    if (token.modifier === "+" || token.modifier === "*") {
                        var mod = token.modifier === "*" ? "?" : "";
                        route += "(?:" + prefix + "((?:" + token.pattern + ")(?:" + suffix + prefix + "(?:" + token.pattern + "))*)" + suffix + ")" + mod;
                    }
                    else {
                        route += "(?:" + prefix + "(" + token.pattern + ")" + suffix + ")" + token.modifier;
                    }
                }
                else {
                    route += "(" + token.pattern + ")" + token.modifier;
                }
            }
            else {
                route += "(?:" + prefix + suffix + ")" + token.modifier;
            }
        }
    }
    if (end) {
        if (!strict)
            route += delimiter + "?";
        route += !options.endsWith ? "$" : "(?=" + endsWith + ")";
    }
    else {
        var endToken = tokens[tokens.length - 1];
        var isEndDelimited = typeof endToken === "string"
            ? delimiter.indexOf(endToken[endToken.length - 1]) > -1
            : // tslint:disable-next-line
                endToken === undefined;
        if (!strict) {
            route += "(?:" + delimiter + "(?=" + endsWith + "))?";
        }
        if (!isEndDelimited) {
            route += "(?=" + delimiter + "|" + endsWith + ")";
        }
    }
    return new RegExp(route, flags(options));
}
exports.tokensToRegexp = tokensToRegexp;
/**
 * Normalize the given path string, returning a regular expression.
 *
 * An empty array can be passed in for the keys, which will hold the
 * placeholder key descriptions. For example, using `/user/:id`, `keys` will
 * contain `[{ name: 'id', delimiter: '/', optional: false, repeat: false }]`.
 */
function pathToRegexp(path, keys, options) {
    if (path instanceof RegExp)
        return regexpToRegexp(path, keys);
    if (Array.isArray(path))
        return arrayToRegexp(path, keys, options);
    return stringToRegexp(path, keys, options);
}
exports.pathToRegexp = pathToRegexp;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "zgCa":
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = __webpack_require__("zOht");
const access_token_error_1 = tslib_1.__importDefault(__webpack_require__("Ni7F"));
const session_1 = tslib_1.__importDefault(__webpack_require__("dKo8"));
const array_1 = __webpack_require__("PTLu");
class SessionTokenCache {
    constructor(store, clientProvider, req, res) {
        this.store = store;
        this.clientProvider = clientProvider;
        this.req = req;
        this.res = res;
    }
    getAccessToken(accessTokenRequest) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const session = yield this.store.read(this.req);
            if (!session) {
                throw new access_token_error_1.default('invalid_session', 'The user does not have a valid session.');
            }
            if (!session.accessToken && !session.refreshToken) {
                throw new access_token_error_1.default('invalid_session', 'The user does not have a valid access token.');
            }
            if (!session.accessTokenExpiresAt) {
                throw new access_token_error_1.default('access_token_expired', 'Expiration information for the access token is not available. The user will need to sign in again.');
            }
            if (accessTokenRequest && accessTokenRequest.scopes) {
                const persistedScopes = session.accessTokenScope;
                if (!persistedScopes || persistedScopes.length === 0) {
                    throw new access_token_error_1.default('insufficient_scope', 'An access token with the requested scopes could not be provided. The user will need to sign in again.');
                }
                const matchingScopes = array_1.intersect(accessTokenRequest.scopes, persistedScopes.split(' '));
                if (!array_1.match(accessTokenRequest.scopes, [...matchingScopes])) {
                    throw new access_token_error_1.default('insufficient_scope', `Could not retrieve an access token with scopes "${accessTokenRequest.scopes.join(' ')}". The user will need to sign in again.`);
                }
            }
            // Check if the token has expired.
            // There is an edge case where we might have some clock skew where our code assumes the token is still valid.
            // Adding a skew of 1 minute to compensate.
            if (!session.refreshToken && session.accessTokenExpiresAt * 1000 - 60000 < Date.now()) {
                throw new access_token_error_1.default('access_token_expired', 'The access token expired and a refresh token is not available. The user will need to sign in again.');
            }
            // Check if the token has expired.
            // There is an edge case where we might have some clock skew where our code assumes the token is still valid.
            // Adding a skew of 1 minute to compensate.
            if ((session.refreshToken && session.accessTokenExpiresAt * 1000 - 60000 < Date.now()) ||
                (session.refreshToken && accessTokenRequest && accessTokenRequest.refresh)) {
                const client = yield this.clientProvider();
                const tokenSet = yield client.refresh(session.refreshToken);
                // Update the session.
                const newSession = session_1.default(tokenSet);
                yield this.store.save(this.req, this.res, Object.assign(Object.assign({}, newSession), { refreshToken: newSession.refreshToken || session.refreshToken }));
                // Return the new access token.
                return {
                    accessToken: tokenSet.access_token
                };
            }
            // We don't have an access token.
            if (!session.accessToken) {
                throw new access_token_error_1.default('invalid_session', 'The user does not have a valid access token.');
            }
            // The access token is not expired and has sufficient scopes;
            return {
                accessToken: session.accessToken
            };
        });
    }
}
exports.default = SessionTokenCache;
//# sourceMappingURL=session-token-cache.js.map

/***/ }),

/***/ "zjbl":
/***/ (function(module, exports, __webpack_require__) {

"use strict";


const Assert = __webpack_require__("q4ve");


const internals = {};


module.exports = function (obj, chain, options) {

    if (chain === false ||
        chain === null ||
        chain === undefined) {

        return obj;
    }

    options = options || {};
    if (typeof options === 'string') {
        options = { separator: options };
    }

    const isChainArray = Array.isArray(chain);

    Assert(!isChainArray || !options.separator, 'Separator option no valid for array-based chain');

    const path = isChainArray ? chain : chain.split(options.separator || '.');
    let ref = obj;
    for (let i = 0; i < path.length; ++i) {
        let key = path[i];
        const type = options.iterables && internals.iterables(ref);

        if (Array.isArray(ref) ||
            type === 'set') {

            const number = Number(key);
            if (Number.isInteger(number)) {
                key = number < 0 ? ref.length + number : number;
            }
        }

        if (!ref ||
            typeof ref === 'function' && options.functions === false ||         // Defaults to true
            !type && ref[key] === undefined) {

            Assert(!options.strict || i + 1 === path.length, 'Missing segment', key, 'in reach path ', chain);
            Assert(typeof ref === 'object' || options.functions === true || typeof ref !== 'function', 'Invalid segment', key, 'in reach path ', chain);
            ref = options.default;
            break;
        }

        if (!type) {
            ref = ref[key];
        }
        else if (type === 'set') {
            ref = [...ref][key];
        }
        else {  // type === 'map'
            ref = ref.get(key);
        }
    }

    return ref;
};


internals.iterables = function (ref) {

    if (ref instanceof Set) {
        return 'set';
    }

    if (ref instanceof Map) {
        return 'map';
    }
};


/***/ }),

/***/ "zspo":
/***/ (function(module, exports, __webpack_require__) {

module.exports = {
  der: __webpack_require__("R7nf"),
  pem: __webpack_require__("QQHG")
}


/***/ })

/******/ });