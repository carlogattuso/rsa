export function generateRandomKeys(bitLength?: number): Promise<any>;
export type PublicKey = any;
/**
 * Class for a RSA public key
 */
export const PublicKey: {
    new (e: bigint, n: bigint): {
        e: bigint;
        n: bigint;
        /**
         * Get the bit length of the public modulo
         * @return {number} - bit length of the public modulo
         */
        readonly bitLength: number;
        /**
         * RSA public-key encryption
         *
         * @param {bigint} m - a cleartext number
         *
         * @returns {bigint} - the encryption of m with this public key
         */
        encrypt(m: bigint): bigint;
        /**
         * RSA public-key verification
         *
         * @param {bigint} s - a bigint signed message
         *
         * @returns { bigint } - the cleartext of s with this public key
         */
        verify(s: bigint): bigint;
    };
};
/**
 * Class for a RSA private key
 */
export const PrivateKey: {
    new (d: bigint, p: any, q: any, phi: any, publicKey: any): {
        d: bigint;
        _p: bigint;
        _q: bigint;
        _phi: bigint;
        publicKey: any;
        /**
         * Get the bit length of the public modulo
         * @return { number } - bit length of the public modulo
         */
        readonly bitLength: number;
        /**
         * Get the public modulo n=p·q
         * @returns {bigint} - the public modulo n=p·q
         */
        readonly n: bigint;
        /**
         * RSA private-key signature
         *
         * @param {bigint} m - a cleartext number
         *
         * @returns {bigint} - the signature of m with this private key
         */
        sign(m: bigint): bigint;
        /**
         * RSA private-key decryption
         *
         * @param {bigint} e - a bigint encrypted message
         *
         * @returns { bigint } - the cleartext number of e with this private key
         */
        decrypt(e: bigint): bigint;
    };
};
export type KeyPair = {
    /**
     * - a RSA's public key
     */
    publicKey: any;
    /**
     * - the associated RSA's private key
     */
    privateKey: {
        d: bigint;
        _p: bigint;
        _q: bigint;
        _phi: bigint;
        publicKey: any;
        /**
         * Get the bit length of the public modulo
         * @return { number } - bit length of the public modulo
         */
        readonly bitLength: number;
        /**
         * Get the public modulo n=p·q
         * @returns {bigint} - the public modulo n=p·q
         */
        readonly n: bigint;
        /**
         * RSA private-key signature
         *
         * @param {bigint} m - a cleartext number
         *
         * @returns {bigint} - the signature of m with this private key
         */
        sign(m: bigint): bigint;
        /**
         * RSA private-key decryption
         *
         * @param {bigint} e - a bigint encrypted message
         *
         * @returns { bigint } - the cleartext number of e with this private key
         */
        decrypt(e: bigint): bigint;
    };
};
