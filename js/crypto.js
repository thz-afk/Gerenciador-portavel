'use strict';

/**
 * Crypto Module
 * Cryptographic operations using Web Crypto API
 */
const Crypto = {
    // Security settings
    PBKDF2_ITERATIONS: 300000,  // 300k iterations
    SALT_LENGTH: 32,
    IV_LENGTH: 16,
    TAG_LENGTH: 128,
    
    /**
     * Checks if Web Crypto is available
     */
    isSupported() {
        return typeof crypto !== 'undefined' && 
               crypto.subtle && 
               typeof crypto.subtle.encrypt === 'function';
    },
    
    /**
     * Generates a secure random salt
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    },
    
    /**
     * Derives a key from the password using PBKDF2
     * The password is immediately discarded after derivation
     */
    async deriveKey(password, salt) {
        // Input validations
        if (!password || typeof password !== 'string') {
            throw new Error('Password inválida');
        }
        if (!salt || salt.length < this.SALT_LENGTH) {
            throw new Error('Salt inválido');
        }
        
        const enc = new TextEncoder();
        const pwdBuffer = enc.encode(password);
        
        // Imports password as a key
        const bKey = await crypto.subtle.importKey(
            'raw',
            pwdBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        // Derives AES key
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            bKey,
            { name: 'AES-GCM', length: 256 },
            false,  // Not exportable
            ['encrypt', 'decrypt']
        );
        
        // Clears the password buffer - FIXED
        if (typeof Security !== 'undefined' && Security.zeroize) {
            Security.zeroize(pwdBuffer);
        } else {
            pwdBuffer.fill(0);
        }
        
        return key;
    },
    
    /**
     * Encrypts data with AES-GCM
     * Uses a unique IV and AAD for integrity
     */
    async encrypt(data, key) {
        const enc = new TextEncoder();
        const plaintext = enc.encode(JSON.stringify(data));
        
        // Unique random IV
        const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
        
        // Additional Authenticated Data - IMPROVED
        const aadData = {
            version: 'VAULT_V1',
            timestamp: Date.now(),
            context: 'encryption'
        };
        const aad = enc.encode(JSON.stringify(aadData));
        
        // Encrypts
        const ciphertxt = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: aad,
                tagLength: this.TAG_LENGTH
            },
            key,
            plaintext
        );
        
        // Returns everything needed to decrypt
        return {
            iv: Array.from(iv),
            aad: Array.from(aad),
            data: Array.from(new Uint8Array(ciphertxt))
        };
    },
    
    /**
     * Decrypts data with AES-GCM
     * Validates integrity via AAD
     */
    async decrypt(encData, key) {
        if (!encData || !encData.iv || !encData.data) {
            return null;
        }
        
        try {
            const iv = new Uint8Array(encData.iv);
            const aad = new Uint8Array(encData.aad || []);
            const ciphertxt = new Uint8Array(encData.data);
            
            const plaintext = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: aad,
                    tagLength: this.TAG_LENGTH
                },
                key,
                ciphertxt
            );
            
            const dec = new TextDecoder();
            return JSON.parse(dec.decode(plaintext));
        } catch (e) {
            // Decryption or validation failure
            return null;
        }
    }
};
