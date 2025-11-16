'use strict';

/**
 * VaultStore Module
 * Manages vault storage and encryption
 */
class VaultStore {
    constructor() {
        this.currentKey = null;  // Temporary key in memory
        this.vault = null;       // Temporary decrypted data
        this.salt = null;
        this.authExpiry = 0;
        this.config = { emailSvc: 'tuamae' };
        
        // Tries to restore the session from localStorage if it is still valid
        this.restoreSession();
    }
    
    /**
     * Restores the session from localStorage if it is still valid
     */
    restoreSession() {
        try {
            const savExp = localStorage.getItem('sessionExpiry');
            if (savExp) {
                const expiry = parseInt(savExp, 10);
                if (expiry > Date.now()) {
                    // Session still valid, restores expiry
                    this.authExpiry = expiry;
                } else {
                    // Session expired, remove
                    localStorage.removeItem('sessionExpiry');
                }
            }
        } catch (e) {
            // Ignores errors when restoring the session
        }
    }
    
    /**
     * Saves the session expiry in localStorage
     */
    saveSessionExpiry() {
        try {
            if (this.authExpiry > Date.now()) {
                localStorage.setItem('sessionExpiry', this.authExpiry.toString());
            } else {
                localStorage.removeItem('sessionExpiry');
            }
        } catch (e) {
            // Ignores errors when saving the session
        }
    }
    
    /**
     * Creates a new vault
     */
    async createVault(password, sessDur = 60000) {
        // Generates a random salt
        this.salt = crypto.getRandomValues(new Uint8Array(Crypto.SALT_LENGTH));
        
        // Derives key (password is discarded)
        this.currentKey = await Crypto.deriveKey(password, this.salt);
        
        // Initial structure with default blocks
        // All payload annotations go to the "General" (default) block
        const pNotes = [
            ...XSSPayloads.map((payload, index) => ({
                id: `note_xss_${index}_${Date.now()}`,
                blk: 'default',
                title: payload.title,
                content: payload.content
            })),
            ...SQLiPayloads.map((payload, index) => ({
                id: `note_sqli_${index}_${Date.now()}`,
                blk: 'default',
                title: payload.title,
                content: payload.content
            })),
            ...PentestPayloads.map((payload, index) => ({
                id: `note_pentest_${index}_${Date.now()}`,
                blk: 'default',
                title: payload.title,
                content: payload.content
            }))
        ];
        
        this.vault = {
            version: 1,
            blks: [
                { id: 'default', name: 'Geral' }
            ],
            pwds: [],
            prs: [],
            notes: pNotes
        };
        
        // Saves encrypted
        await this.saveVault();
        
        // Defines the authentication expiration (default 1 minute, or 30 minutes if extended)
        this.authExpiry = Date.now() + sessDur;
        this.saveSessionExpiry();
        
        return true;
    }
    
    /**
     * Opens an existing vault
     * Tests decryption to validate the password
     */
    async openVault(password, sessDur = 60000) {
        const stored = localStorage.getItem('vault');
        if (!stored) return false;
        
        try {
            const vData = JSON.parse(stored);
            this.salt = new Uint8Array(vData.salt);
            
            // Derives key
            const tKey = await Crypto.deriveKey(password, this.salt);
            
            // Tries to decrypt to validate the password
            const dec = await Crypto.decrypt(vData.data, tKey);
            
            if (!dec) {
                // Incorrect password or corrupted data
                return false;
            }
            
            // Success - keeps key and data
            this.currentKey = tKey;
            this.vault = dec;
            this.authExpiry = Date.now() + sessDur;
            this.saveSessionExpiry();
            
            // Removes old pentest blocks (xss, sqli, pentest) if they exist
            const pBlockIds = ['xss', 'sqli', 'pentest'];
            if (this.vault.blks) {
                this.vault.blks = this.vault.blks.filter(b => !pBlockIds.includes(b.id));
            }
            
            // Ensures that the "General" (default) block exists
            const exBlockIds = this.vault.blks ? this.vault.blks.map(b => b.id) : [];
            if (!exBlockIds.includes('default')) {
                if (!this.vault.blks) {
                    this.vault.blks = [];
                }
                this.vault.blks.push({ id: 'default', name: 'Geral' });
            }
            
            // Removes all passwords from old pentest blocks (incorrect data)
            if (this.vault.pwds && this.vault.pwds.length > 0) {
                this.vault.pwds = this.vault.pwds.filter(p => !pBlockIds.includes(p.blk));
            }
            
            // Migrates old annotations from pentest blocks to the "General" block
            if (!this.vault.notes) {
                this.vault.notes = [];
            }
            
            // Updates the block of old annotations from the pentest blocks to "default"
            this.vault.notes.forEach(note => {
                if (pBlockIds.includes(note.blk)) {
                    note.blk = 'default';
                }
            });
            
            // Removes old default annotations that may have duplicate IDs
            // Removes annotations that start with note_xss_, note_sqli_, note_pentest_
            const timestamp = Date.now();
            const exNoteIds = this.vault.notes.map(n => n.id);
            this.vault.notes = this.vault.notes.filter(n => {
                // Keeps only annotations that are not old default payloads
                return !n.id.match(/^note_(xss|sqli|pentest)_\d+_/);
            });
            
            // Creates all payload annotations in the "General" (default) block
            const pNotes = [
                ...XSSPayloads.map((payload, index) => ({
                    id: `note_xss_${index}_${timestamp}_${Math.random().toString(36).substr(2, 9)}`,
                    blk: 'default',
                    title: payload.title,
                    content: payload.content
                })),
                ...SQLiPayloads.map((payload, index) => ({
                    id: `note_sqli_${index}_${timestamp}_${Math.random().toString(36).substr(2, 9)}`,
                    blk: 'default',
                    title: payload.title,
                    content: payload.content
                })),
                ...PentestPayloads.map((payload, index) => ({
                    id: `note_pentest_${index}_${timestamp}_${Math.random().toString(36).substr(2, 9)}`,
                    blk: 'default',
                    title: payload.title,
                    content: payload.content
                }))
            ];
            
            // Adds only annotations that do not exist yet (checks by title to avoid duplicates)
            const exTitles = new Set(this.vault.notes.map(n => n.title));
            pNotes.forEach(note => {
                if (!exTitles.has(note.title)) {
                    this.vault.notes.push(note);
                    exTitles.add(note.title);
                }
            });
            
            // Saves the changes
            await this.saveVault();
            
            // Loads settings
            const cfg = localStorage.getItem('config');
            if (cfg) {
                try {
                    this.config = JSON.parse(cfg);
                } catch {}
            }
            
            return true;
        } catch {
            return false;
        }
    }
    
    /**
     * Re-authenticates by testing decryption
     * Never compares passwords directly
     */
    async reAuthenticate(password) {
        if (!this.salt) return false;
        
        try {
            // Derives new key
            const tKey = await Crypto.deriveKey(password, this.salt);
            
            // Gets saved data
            const stored = localStorage.getItem('vault');
            if (!stored) return false;
            
            const vData = JSON.parse(stored);
            
            // Tests decryption
            const dec = await Crypto.decrypt(vData.data, tKey);
            
            if (!dec) {
                return false;
            }
            
            // Success - updates key and expiry (maintains default duration of 1 minute for re-auth)
            this.currentKey = tKey;
            this.authExpiry = Date.now() + 60000;
            this.saveSessionExpiry();
            
            return true;
        } catch {
            return false;
        }
    }
    
    /**
     * Saves encrypted vault
     */
    async saveVault() {
        if (!this.currentKey || !this.vault) return false;
        
        try {
            const enc = await Crypto.encrypt(this.vault, this.currentKey);
            
            localStorage.setItem('vault', JSON.stringify({
                salt: Array.from(this.salt),
                data: enc,
                timestamp: Date.now()
            }));
            
            return true;
        } catch {
            return false;
        }
    }
    
    /**
     * Checks if vault exists
     */
    exists() {
        return localStorage.getItem('vault') !== null;
    }
    
    /**
     * Checks if authentication is still valid
     */
    isAuthenticated() {
        return this.currentKey !== null && Date.now() < this.authExpiry;
    }
    
    /**
     * Returns the remaining session time in milliseconds
     */
    getSessionTimeRemaining() {
        if (!this.currentKey || !this.authExpiry) {
            return 0;
        }
        const remaining = this.authExpiry - Date.now();
        return remaining > 0 ? remaining : 0;
    }
    
    /**
     * Extends the session by adding time
     * @param {number} additionalMinutes - Additional minutes to extend the session
     */
    extendSession(addMin = 30) {
        if (!this.isAuthenticated()) {
            return false;
        }
        
        const addMs = addMin * 60 * 1000;
        const currRem = this.getSessionTimeRemaining();
        const newExp = Date.now() + currRem + addMs;
        
        // Limits the maximum session to 60 minutes
        const maxSessMs = 60 * 60 * 1000;
        this.authExpiry = Math.min(newExp, Date.now() + maxSessMs);
        this.saveSessionExpiry();
        
        return true;
    }
    
    /**
     * Clears sensitive data from memory
     */
    lock() {
        this.currentKey = null;
        Security.zeroize(this.vault);
        this.vault = null;
        this.authExpiry = 0;
        localStorage.removeItem('sessionExpiry');
    }
    
    /**
     * Checks if there is a valid saved session (without needing to decrypt)
     */
    hasValidSession() {
        try {
            const savExp = localStorage.getItem('sessionExpiry');
            if (savExp) {
                const expiry = parseInt(savExp, 10);
                return expiry > Date.now();
            }
        } catch (e) {
            // Ignores errors
        }
        return false;
    }
    
    /**
     * Saves settings (not encrypted)
     */
    saveConfig() {
        localStorage.setItem('config', JSON.stringify(this.config));
    }
}


