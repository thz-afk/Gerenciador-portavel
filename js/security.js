'use strict';

/**
 * Security Module
 * Input validation and rate limiting
 */
const Security = {
    /**
     * Validates input against XSS and injections
     * Blocks: HTML tags, javascript:, data:, events, etc.
     */
    validate(str, maxLen = 1000) {
        if (typeof str !== 'string') return false;
        if (str.length > maxLen) return false;
        
        // Regex to detect XSS attempts
        const dangerous = [
            /<[^>]*>/gi,           // Any HTML tag
            /javascript:/gi,        // javascript: protocol
            /on\w+\s*=/gi,         // Event handlers
            /data:[^,]*script/gi,  // data: URLs with script
            /<script/gi,           // Script tags
            /<iframe/gi,           // iframes
            /<object/gi,           // objects
            /<embed/gi,            // embeds
            /<img/gi,              // images (can have onerror)
            /<svg/gi,              // SVG (can contain scripts)
            /eval\s*\(/gi,         // eval()
            /expression\s*\(/gi,   // CSS expressions
            /import\s+/gi,         // ES6 imports
            /require\s*\(/gi       // CommonJS requires
        ];
        
        for (const regex of dangerous) {
            if (regex.test(str)) return false;
        }
        
        return true;
    },
    
    /**
     * Rate limiting to prevent brute force
     */
    attempts: new Map(),
    
    checkRate(key, max = 5, window = 60000) {
        const now = Date.now();
        const attempt = this.attempts.get(key);
        
        if (!attempt || now - attempt.first > window) {
            this.attempts.set(key, { count: 1, first: now });
            return true;
        }
        
        attempt.count++;
        return attempt.count <= max;
    },
    
    /**
     * Clears sensitive data from memory
     */
    zeroize(obj) {
        if (typeof obj === 'string') {
            // Strings are immutable in JS, the best we can do
            obj = null;
        } else if (obj instanceof Uint8Array) {
            crypto.getRandomValues(obj); // Overwrites with random
            obj.fill(0); // Then zeros out
        } else if (obj && typeof obj === 'object') {
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    this.zeroize(obj[key]);
                    delete obj[key];
                }
            }
        }
    }
};

