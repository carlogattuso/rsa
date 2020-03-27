'use strict';

import * as crypto from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';

const _ONE = BigInt(1);
const _E = BigInt(65537);

/**
 * @typedef {Object} KeyPair
 * @property {PublicKey} publicKey - a RSA's public key
 * @property {PrivateKey} privateKey - the associated RSA's private key
 */

/**
 * @typedef {PublicKey} PublicKey
 */

/**
 * Generates a pair private, public key for the RSA cryptosystem.
 *
 * @param {number} [bitLength = 2048] - the bit length of the public modulo
 *
 * @returns {Promise} - a promise that resolves to a {@link KeyPair} of public, private keys
 */
export const generateRandomKeys = async function (bitLength=2048) {
    let p, q, n, phi, d;
    do {
        //We choose two random prime numbers
        p = await crypto.prime(Math.floor(bitLength / 2) + 1);
        q = await crypto.prime(Math.floor(bitLength / 2));

        n = p * q;

        phi = (p - _ONE) * (q - _ONE);

    } while (p === q ||
                crypto.bitLength(n) !== bitLength ||
                    !(crypto.gcd(phi,_E) === _ONE));

    d = crypto.modInv(_E,phi);

    const publicKey = new PublicKey(_E, n);
    const privateKey = new PrivateKey(d,p,q,phi,publicKey);
    return { publicKey: publicKey, privateKey: privateKey };
};

/**
 * Class for a RSA public key
 */
export const PublicKey = class PublicKey {
    /**
     * Creates an instance of class PublicKey
     * @param {bigint} e - the public exponent
     * @param {bigint} n - the public modulo
     */
    constructor(e,n){
        this.e = BigInt(e);
        this.n = BigInt(n);
    }

    /**
     * Get the bit length of the public modulo
     * @return {number} - bit length of the public modulo
     */
    get bitLength() {
        return crypto.bitLength(this.n);
    }

    /**
     * RSA public-key encryption
     *
     * @param {bigint} m - a cleartext number
     *
     * @returns {bigint} - the encryption of m with this public key
     */
    encrypt(m) {
        return crypto.modPow(m,this.e,this.n);
    }

    /**
     * RSA public-key verification
     *
     * @param {bigint} s - a bigint signed message
     *
     * @returns { bigint } - the cleartext of s with this public key
     */
    verify(s) {
        return crypto.modPow(s,this.e,this.n);
    }
};

/**
 * Class for a RSA private key
 */
export const PrivateKey = class PrivateKey {
    /**
     * Creates an instance of class PrivateKey
     * @param {bigint} d - the private exponent
     * @param {bigInt} p - random prime number
     * @param {bigInt} q - random prime number
     * @param {bigInt} phi - Euler's totient phi=(p-q)*(q-1)
     * @param {PublicKey} publicKey
     */
    constructor(d,p=null,q=null,phi=null,publicKey){
        this.d = BigInt(d);
        this._p = (p) ? BigInt(p) : null;
        this._q = (q) ? BigInt(q) : null;
        this._phi = (phi) ? BigInt(phi) : null;
        this.publicKey = publicKey;
    }

    /**
     * Get the bit length of the public modulo
     * @return { number } - bit length of the public modulo
     */
    get bitLength() {
        return crypto.bitLength(this.publicKey.n);
    }

    /**
     * Get the public modulo n=p·q
     * @returns {bigint} - the public modulo n=p·q
     */
    get n() {
        return this.publicKey.n;
    }

    /**
     * RSA private-key signature
     *
     * @param {bigint} m - a cleartext number
     *
     * @returns {bigint} - the signature of m with this private key
     */
    sign(m) {
        return crypto.modPow(m,this.d,this.publicKey.n);
    }

    /**
     * RSA private-key decryption
     *
     * @param {bigint} e - a bigint encrypted message
     *
     * @returns { bigint } - the cleartext number of e with this private key
     */
    decrypt(e) {
        return crypto.modPow(e,this.d,this.publicKey.n);
    }
};
