'use strict';


class App {
    constructor() {
        this.store = new VaultStore();
        this.currentBlock = 'default';
        this.pendingAction = null;
        this.editingNoteId = null;
        this.sessionTimerInterval = null;
        
        this.init();
    }
    
    
     // Initializes the application
     
    init() {
        this.attachEventListeners();
        
        if (this.store.exists()) {
            // Checks if there is a valid saved session
            if (this.store.hasValidSession()) {
                // Session still valid, but needs to be decrypted
                // Shows a message indicating that it can continue
                this.showLoginWithSession();
            } else {
                this.showLogin();
            }
        } else {
            this.showRegister();
        }
    }
    
    
     // Shows login screen with active session indication
     
    showLoginWithSession() {
        const msg = document.getElementById('authMsg');
        if (msg) {
            msg.textContent = 'Sessão ainda ativa. Digite sua senha para continuar.';
        }
        this.showLogin();
    }
    
    /**
     * Attaches all event listeners
     * Avoids inline handlers for CSP
     */
    attachEventListeners() {
        // Auth form
        const authForm = document.getElementById('authForm');
        if (authForm) {
            authForm.addEventListener('submit', (e) => this.handleAuth(e));
        }
        
        // Re-auth form
        const reauthForm = document.getElementById('reauthForm');
        if (reauthForm) {
            reauthForm.addEventListener('submit', (e) => this.handleReAuth(e));
        }
        
        // Menu items
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => this.switchSection(e));
        });
        
        // Buttons
        this.attachButtonListener('logoutBtn', () => this.logout());
        this.attachButtonListener('configBtn', () => this.openModal('configModal'));
        this.attachButtonListener('extendSessionBtn', () => this.extendSession());
        this.attachButtonListener('addBlkBtn', () => this.checkAuthAndDo(() => this.openModal('blkModal')));
        this.attachButtonListener('addPwdBtn', () => this.checkAuthAndDo(() => this.openPasswordModal()));
        this.attachButtonListener('addNoteBtn', () => this.checkAuthAndDo(() => this.openNoteModal()));
        this.attachButtonListener('genPwdBtn', () => this.generatePassword());
        this.attachButtonListener('copyGenBtn', () => this.copyGenerated());
        this.attachButtonListener('genQuickPwdBtn', () => this.generateQuickPassword());
        this.attachButtonListener('genPersonBtn', () => this.generatePerson());
        this.attachButtonListener('showSavedPersonsBtn', () => this.showSavedPersons());
        this.attachButtonListener('saveConfigBtn', () => this.saveConfig());
        
        // Initializes session timer
        this.startSessionTimer();
        
        // Modal close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modal = e.target.dataset.modal;
                if (modal) this.closeModal(modal);
            });
        });
        
        // Forms
        this.attachFormListener('blkForm', (e) => this.saveBlock(e));
        this.attachFormListener('pwdForm', (e) => this.savePassword(e));
        this.attachFormListener('noteForm', (e) => this.saveNote(e));
    }
    
    attachButtonListener(id, handler) {
        const btn = document.getElementById(id);
        if (btn) btn.addEventListener('click', handler);
    }
    
    attachFormListener(id, handler) {
        const form = document.getElementById(id);
        if (form) form.addEventListener('submit', handler);
    }
    
    /**
     * Shows login screen
     */
    showLogin() {
        const authMsg = document.getElementById('authMsg');
        const authBtnTxt = document.getElementById('authBtnTxt');
        const confirmGroup = document.getElementById('confirmGroup');
        
        if (authMsg) authMsg.textContent = 'Digite sua senha mestre para acessar';
        if (authBtnTxt) authBtnTxt.textContent = 'Entrar';
        if (confirmGroup) confirmGroup.style.display = 'none';
    }
    
    /**
     * Shows registration screen
     */
    showRegister() {
        const authMsg = document.getElementById('authMsg');
        const authBtnTxt = document.getElementById('authBtnTxt');
        const confirmGroup = document.getElementById('confirmGroup');
        
        if (authMsg) authMsg.textContent = 'Crie uma senha mestre para proteger seus dados';
        if (authBtnTxt) authBtnTxt.textContent = 'Criar Senha';
        if (confirmGroup) confirmGroup.style.display = 'block';
    }
    
    /**
     * Processes authentication
     */
    async handleAuth(e) {
        e.preventDefault();
        
        // Rate limiting
        if (!Security.checkRate('auth')) {
            this.showToast('Muitas tentativas. Aguarde 1 minuto.', 'error');
            return;
        }
        
        const pwdInput = document.getElementById('masterPwd');
        const confInput = document.getElementById('confirmPwd');
        const btn = document.getElementById('authBtn');
        
        const password = pwdInput.value;
        const confirm = confInput ? confInput.value : '';
        
        // Validation
        if (!Security.validate(password, 128)) {
            this.showToast('Senha contém caracteres inválidos', 'error');
            return;
        }
        
        // Disables button during processing
        btn.disabled = true;
        
        try {
            // Checks if the session should be extended (30 minutes)
            const extSession = document.getElementById('extendSession');
            let sessDuration = extSession && extSession.checked ? 1800000 : 60000; // 30 minutos ou 1 minuto
            
            // If there is already a valid session, preserves the remaining time
            if (this.store.hasValidSession()) {
                const rem = this.store.getSessionTimeRemaining();
                if (rem > 0) {
                    // Uses the remaining time + new chosen duration
                    sessDuration = rem + (extSession && extSession.checked ? 1800000 : 60000);
                }
            }
            
            if (this.store.exists()) {
                // Login
                const success = await this.store.openVault(password, sessDuration);
                
                if (success) {
                    this.enterDashboard();
                } else {
                    this.showToast('Senha incorreta', 'error');
                }
            } else {
                // Registration
                if (password !== confirm) {
                    this.showToast('Senhas não coincidem', 'error');
                    return;
                }
                
                await this.store.createVault(password, sessDuration);
                this.enterDashboard();
            }
        } finally {
            // Clears fields and re-enables the button
            pwdInput.value = '';
            if (confInput) confInput.value = '';
            btn.disabled = false;
        }
    }
    
    /**
     * Processes re-authentication
     */
    async handleReAuth(e) {
        e.preventDefault();
        
        if (!Security.checkRate('reauth')) {
            this.showToast('Muitas tentativas. Aguarde.', 'error');
            return;
        }
        
        const pwdInput = document.getElementById('authPwd');
        const password = pwdInput.value;
        
        if (!Security.validate(password, 128)) {
            this.showToast('Senha inválida', 'error');
            return;
        }
        
        const success = await this.store.reAuthenticate(password);
        
        if (success) {
            this.closeModal('authModal');
            
            // Executes pending action
            if (this.pendingAction) {
                this.pendingAction();
                this.pendingAction = null;
            }
            
            this.showToast('Autenticado', 'success');
        } else {
            this.showToast('Senha incorreta', 'error');
        }
        
        pwdInput.value = '';
    }
    
    /**
     * Enters the dashboard
     */
    enterDashboard() {
        // Checks authentication before entering the dashboard
        if (!this.store.isAuthenticated()) {
            this.showToast('Autenticação necessária', 'error');
            return;
        }
        
        document.getElementById('authScreen').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        
        this.loadBlocks();
        this.loadPasswords();
        this.loadNotes();
        
        // Starts session timer
        this.startSessionTimer();
        
        this.showToast('Bem-vindo!', 'success');
    }
    
    /**
     * Starts session timer
     */
    startSessionTimer() {
        // Clears previous timer if it exists
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }
        
        // Updates immediately
        this.updateSessionTimer();
        
        // Updates every second
        this.sessionTimerInterval = setInterval(() => {
            this.updateSessionTimer();
        }, 1000);
    }
    
    /**
     * Updates the session timer display
     */
    updateSessionTimer() {
        const timerDisp = document.getElementById('timerDisplay');
        const extendBtn = document.getElementById('extendSessionBtn');
        const sessTimer = document.getElementById('sessionTimer');
        
        if (!timerDisp || !extendBtn || !sessTimer) return;
        
        if (!this.store.isAuthenticated()) {
            timerDisp.textContent = 'Expirada';
            timerDisp.style.color = 'var(--danger)';
            extendBtn.disabled = true;
            return;
        }
        
        const rem = this.store.getSessionTimeRemaining();
        
        if (rem <= 0) {
            timerDisp.textContent = 'Expirada';
            timerDisp.style.color = 'var(--danger)';
            extendBtn.disabled = true;
            return;
        }
        
        // Calculates minutes and seconds
        const totalSec = Math.floor(rem / 1000);
        const min = Math.floor(totalSec / 60);
        const sec = totalSec % 60;
        
        // Formats as MM:SS
        const fmt = `${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
        timerDisp.textContent = fmt;
        
        // Changes color if below 1 minute
        if (totalSec < 60) {
            timerDisp.style.color = 'var(--danger)';
        } else if (totalSec < 300) { // Less than 5 minutes
            timerDisp.style.color = 'var(--warn)';
        } else {
            timerDisp.style.color = 'var(--txt-sec)';
        }
        
        extendBtn.disabled = false;
    }
    
    /**
     * Extends session by 30 minutes
     */
    extendSession() {
        // Checks authentication before extending
        if (!this.store.isAuthenticated()) {
            this.showToast('Sessão expirada. Faça login novamente.', 'error');
            return;
        }
        
        const success = this.store.extendSession(30);
        
        if (success) {
            this.showToast('Sessão prolongada em 30 minutos', 'success');
            this.updateSessionTimer();
        } else {
            this.showToast('Não foi possível prolongar a sessão', 'error');
        }
    }
    
    /**
     * Clears the interface when authentication expires
     */
    clearInterfaceOnExpiry() {
        // Clears sensitive data from the interface
        const pwdList = document.getElementById('pwdList');
        if (pwdList) {
            pwdList.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Autenticação expirada</p>';
        }
        
        const notesList = document.getElementById('notesList');
        if (notesList) {
            notesList.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Autenticação expirada</p>';
        }
        
        const blkList = document.getElementById('blkList');
        if (blkList) {
            blkList.innerHTML = '';
        }
    }
    
    /**
     * Checks authentication before a sensitive action
     */
    checkAuthAndDo(action) {
        if (this.store.isAuthenticated()) {
            action();
        } else {
            this.pendingAction = action;
            this.openModal('authModal');
        }
    }
    
    /**
     * Logout
     */
    logout() {
        if (confirm('Deseja sair?')) {
            // Clears session timer
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
                this.sessionTimerInterval = null;
            }
            
            this.store.lock();
            location.reload();
        }
    }
    
    /**
     * Switches active section
     */
    switchSection(e) {
        const section = e.currentTarget.dataset.section;
        if (!section) return;
        
        // Checks authentication before switching sections (except for non-sensitive sections)
        const sensSections = ['passwords', 'notes'];
        if (sensSections.includes(section) && !this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.switchSection(e));
            return;
        }
        
        // Updates menu
        document.querySelectorAll('.menu-item').forEach(item => {
            item.classList.remove('active');
        });
        e.currentTarget.classList.add('active');
        
        // Updates content
        document.querySelectorAll('.section').forEach(sec => {
            sec.classList.remove('active');
        });
        
        const targetSec = document.getElementById(section);
        if (targetSec) {
            targetSec.classList.add('active');
        }
        
        // Reloads data if necessary and authenticated
        if (this.store.isAuthenticated()) {
            if (section === 'passwords') {
                this.loadPasswords();
            } else if (section === 'notes') {
                this.loadNotes();
            }
        }
    }
    
    /**
     * Loads block list
     */
    loadBlocks() {
        // Checks authentication before loading blocks
        if (!this.store.isAuthenticated()) {
            const container = document.getElementById('blkList');
            if (container) {
                container.innerHTML = '';
            }
            return;
        }
        
        const container = document.getElementById('blkList');
        if (!container || !this.store.vault) return;
        
        // Clears container
        container.innerHTML = '';
        
        this.store.vault.blks.forEach(block => {
            const div = document.createElement('div');
            div.className = `blk-item ${block.id === this.currentBlock ? 'active' : ''}`;
            
            // Click event on the entire div for better hitbox
            div.style.cursor = 'pointer';
            div.addEventListener('click', (e) => {
                // Prevents click if it's on the delete button
                if (e.target.tagName === 'BUTTON') {
                    return;
                }
                this.selectBlock(block.id);
            });
            
            const span = document.createElement('span');
            span.textContent = block.name; // textContent prevents XSS
            
            div.appendChild(span);
            
            // Delete button (except default)
            if (block.id !== 'default') {
                const delBtn = document.createElement('button');
                delBtn.className = 'btn-icon';
                delBtn.style.padding = '4px';
                delBtn.textContent = '✕';
                delBtn.addEventListener('click', (e) => {
                    e.stopPropagation(); // Prevents propagation to the div
                    this.deleteBlock(block.id);
                });
                div.appendChild(delBtn);
            }
            
            container.appendChild(div);
        });
    }
    
    /**
     * Selects block
     */
    selectBlock(id) {
        // Checks authentication before switching blocks
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.selectBlock(id));
            return;
        }
        
        this.currentBlock = id;
        this.loadBlocks();
        this.loadPasswords();
        this.loadNotes();
    }
    
    /**
     * Saves new block
     */
    async saveBlock(e) {
        e.preventDefault();
        
        // Checks authentication before saving
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => {
                const form = document.getElementById('blkForm');
                if (form) form.requestSubmit();
            });
            return;
        }
        
        const nameInput = document.getElementById('blkName');
        const name = nameInput.value;
        
        if (!Security.validate(name, 50)) {
            this.showToast('Nome inválido', 'error');
            return;
        }
        
        const id = 'blk_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        this.store.vault.blks.push({ id, name });
        await this.store.saveVault();
        
        this.loadBlocks();
        this.closeModal('blkModal');
        this.showToast('Bloco criado');
        
        nameInput.value = '';
    }
    
    /**
     * Deletes block
     */
    async deleteBlock(id) {
        // Checks authentication before deleting
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.deleteBlock(id));
            return;
        }
        
        // Protects default block
        if (id === 'default') {
            this.showToast('Não é possível excluir o bloco padrão', 'error');
            return;
        }
        
        if (!confirm('Excluir bloco e todo conteúdo?')) return;
        
        this.store.vault.blks = this.store.vault.blks.filter(b => b.id !== id);
        this.store.vault.pwds = this.store.vault.pwds.filter(p => p.blk !== id);
        this.store.vault.notes = this.store.vault.notes.filter(n => n.blk !== id);
        
        await this.store.saveVault();
        
        if (this.currentBlock === id) {
            this.currentBlock = 'default';
        }
        
        this.loadBlocks();
        this.loadPasswords();
        this.loadNotes();
        
        this.showToast('Bloco excluído');
    }
    
    /**
     * Loads password list
     */
    loadPasswords() {
        // Checks authentication before loading passwords
        if (!this.store.isAuthenticated()) {
            const container = document.getElementById('pwdList');
            if (container) {
                container.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Autenticação necessária</p>';
            }
            return;
        }
        
        const container = document.getElementById('pwdList');
        if (!container || !this.store.vault) return;
        
        const pwds = this.store.vault.pwds.filter(p => p.blk === this.currentBlock);
        
        if (pwds.length === 0) {
            container.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Nenhuma senha salva</p>';
            return;
        }
        
        container.innerHTML = '';
        
        pwds.forEach(pwd => {
            const card = document.createElement('div');
            card.className = 'pwd-card';
            
            // Header
            const header = document.createElement('div');
            header.className = 'pwd-header';
            
            const info = document.createElement('div');
            
            const site = document.createElement('div');
            site.className = 'pwd-site';
            site.textContent = pwd.site; // textContent prevents XSS
            
            const user = document.createElement('div');
            user.className = 'pwd-user';
            user.textContent = pwd.usr;
            
            info.appendChild(site);
            info.appendChild(user);
            
            const expandBtn = document.createElement('button');
            expandBtn.className = 'btn btn-expand';
            expandBtn.textContent = 'Ver Mais';
            
            header.appendChild(info);
            header.appendChild(expandBtn);
            
            // Details
            const dtls = document.createElement('div');
            dtls.className = 'pwd-details';
            dtls.id = `pwd-${pwd.id}`;
            
            const field = document.createElement('div');
            field.className = 'pwd-field';
            
            const label = document.createElement('label');
            label.textContent = 'Senha';
            
            const wrap = document.createElement('div');
            wrap.className = 'pwd-value-wrapper';
            
            const value = document.createElement('div');
            value.className = 'pwd-value';
            value.id = `pwdval-${pwd.id}`;
            value.textContent = '••••••••';
            
            const showBtn = document.createElement('button');
            showBtn.className = 'btn-icon';
            showBtn.textContent = 'Ver';
            showBtn.addEventListener('click', () => this.togglePasswordVisibility(pwd.id));
            
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn-icon';
            copyBtn.textContent = 'Copiar';
            copyBtn.addEventListener('click', () => this.copyPassword(pwd.id));
            
            wrap.appendChild(value);
            wrap.appendChild(showBtn);
            wrap.appendChild(copyBtn);
            
            field.appendChild(label);
            field.appendChild(wrap);
            
            const actions = document.createElement('div');
            actions.style.marginTop = '16px';
            actions.style.display = 'flex';
            actions.style.gap = '8px';
            
            const delBtn = document.createElement('button');
            delBtn.className = 'btn btn-danger';
            delBtn.textContent = 'Excluir';
            delBtn.addEventListener('click', () => this.deletePassword(pwd.id));
            
            actions.appendChild(delBtn);
            
            dtls.appendChild(field);
            dtls.appendChild(actions);
            
            // Toggle details
            header.addEventListener('click', () => {
                dtls.classList.toggle('show');
            });
            
            card.appendChild(header);
            card.appendChild(dtls);
            container.appendChild(card);
        });
    }
    
    /**
     * Opens password modal
     */
    openPasswordModal() {
        const select = document.getElementById('pwdBlk');
        if (!select) return;
        
        select.innerHTML = '';
        
        this.store.vault.blks.forEach(blk => {
            const option = document.createElement('option');
            option.value = blk.id;
            option.textContent = blk.name;
            if (blk.id === this.currentBlock) {
                option.selected = true;
            }
            select.appendChild(option);
        });
        
        this.openModal('pwdModal');
    }
    
    /**
     * Saves password
     */
    async savePassword(e) {
        e.preventDefault();
        
        // Checks authentication before saving password
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => {
                const form = document.getElementById('pwdForm');
                if (form) form.requestSubmit();
            });
            return;
        }
        
        const blk = document.getElementById('pwdBlk').value;
        const site = document.getElementById('pwdSite').value;
        const usr = document.getElementById('pwdUsr').value;
        const val = document.getElementById('pwdVal').value;
        
        // Validation
        if (!Security.validate(site, 100) || 
            !Security.validate(usr, 200) || 
            !Security.validate(val, 500)) {
            this.showToast('Dados inválidos', 'error');
            return;
        }
        
        const pwd = {
            id: 'pwd_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            blk,
            site,
            usr,
            val
        };
        
        this.store.vault.pwds.push(pwd);
        await this.store.saveVault();
        
        this.loadPasswords();
        this.closeModal('pwdModal');
        this.showToast('Senha salva');
        
        e.target.reset();
    }
    
    /**
     * Toggles password visibility
     */
    togglePasswordVisibility(id) {
        // Checks authentication before showing password
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.togglePasswordVisibility(id));
            return;
        }
        
        const element = document.getElementById(`pwdval-${id}`);
        if (!element) return;
        
        const pwd = this.store.vault.pwds.find(p => p.id === id);
        if (!pwd) return;
        
        if (element.textContent === '••••••••') {
            element.textContent = pwd.val;
        } else {
            element.textContent = '••••••••';
        }
    }
    
    /**
     * Copies password
     */
    copyPassword(id) {
        // Checks authentication before copying password
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.copyPassword(id));
            return;
        }
        
        const pwd = this.store.vault.pwds.find(p => p.id === id);
        if (!pwd) return;
        
        navigator.clipboard.writeText(pwd.val).then(() => {
            this.showToast('Senha copiada');
        }).catch(() => {
            this.showToast('Erro ao copiar', 'error');
        });
    }
    
    /**
     * Deletes password
     */
    async deletePassword(id) {
        // Checks authentication before deleting password
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.deletePassword(id));
            return;
        }
        
        if (!confirm('Excluir senha?')) return;
        
        this.store.vault.pwds = this.store.vault.pwds.filter(p => p.id !== id);
        await this.store.saveVault();
        
        this.loadPasswords();
        this.showToast('Senha excluída');
    }
    
    /**
     * Generates strong password
     */
    generatePassword() {
        const len = parseInt(document.getElementById('genLen').value) || 16;
        const upper = document.getElementById('genUpper').checked;
        const lower = document.getElementById('genLower').checked;
        const num = document.getElementById('genNum').checked;
        const sym = document.getElementById('genSym').checked;
        
        let charset = '';
        if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (num) charset += '0123456789';
        if (sym) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        if (!charset) {
            this.showToast('Selecione pelo menos uma opção', 'error');
            return;
        }
        
        let password = '';
        const array = new Uint8Array(len);
        crypto.getRandomValues(array);
        
        for (let i = 0; i < len; i++) {
            password += charset[array[i] % charset.length];
        }
        
        const input = document.getElementById('genPwd');
        if (input) input.value = password;
    }
    
    /**
     * Copies generated password
     */
    copyGenerated() {
        const input = document.getElementById('genPwd');
        if (!input || !input.value) return;
        
        navigator.clipboard.writeText(input.value).then(() => {
            this.showToast('Copiado!');
        });
    }
    
    /**
     * Generates quick password
     */
    generateQuickPassword() {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        
        for (let i = 0; i < 16; i++) {
            password += charset[array[i] % charset.length];
        }
        
        const input = document.getElementById('pwdVal');
        if (input) input.value = password;
    }
    
    /**
     * Generates fictitious person
     */
    generateName() {
        const names = [
            'Joao', 'Maria', 'Pedro', 'Ana', 'Carlos', 'Julia', 'Lucas', 'Mariana',
            'Rafael', 'Beatriz', 'Andre', 'Fernanda', 'Gabriel', 'Larissa', 'Bruno',
            'Camila', 'Diego', 'Patricia', 'Rodrigo', 'Natalia', 'Felipe', 'Aline',
            'Gustavo', 'Isabela', 'Thiago', 'Renata', 'Eduardo', 'Carolina'
        ];
        const surnames = [
            'Silva', 'Santos', 'Oliveira', 'Souza', 'Lima', 'Costa', 'Ferreira',
            'Gomes', 'Ribeiro', 'Almeida', 'Pereira', 'Rodrigues', 'Martins',
            'Barbosa', 'Araujo', 'Cardoso', 'Melo', 'Correia', 'Teixeira', 'Dias',
            'Nunes', 'Batista', 'Freitas', 'Vieira', 'Rocha'
        ];
        return names[Math.floor(Math.random() * names.length)] + ' ' +
            surnames[Math.floor(Math.random() * surnames.length)];
    }

    generateBirthdate() {
        const year = 1950 + Math.floor(Math.random() * 50);
        const month = String(Math.floor(Math.random() * 12) + 1).padStart(2, '0');
        const day = String(Math.floor(Math.random() * 28) + 1).padStart(2, '0');
        return `${day}/${month}/${year}`;
    }

    generateAddress() {
        return StreetsData[Math.floor(Math.random() * StreetsData.length)] + ', ' +
            Math.floor(Math.random() * 9999);
    }

    generatePerson() {
        const name = this.generateName();
        const cpf = this.generateCPF();
        const birthdate = this.generateBirthdate();
        const address = this.generateAddress();

        const emailUser = name.toLowerCase().replace(' ', '') + Math.floor(Math.random() * 9999);
        const service = this.store.config.emailSvc || 'tuamae';

        let email, link;
        if (service === 'tuamae') {
            email = emailUser + '@tuamaeaquelaursa.com';
            link = `https://tuamaeaquelaursa.com/${emailUser}`;
        } else {
            email = emailUser + '@firemail.com.br';
            link = `https://firemail.com.br/${emailUser}`;
        }

        const person = { name, cpf, birthdate, email, link, address };

        this.currentPerson = person;
        this.displayPerson(this.currentPerson);
    }

    regenerateField(field) {
        if (!this.currentPerson) return;

        if (field === 'name') {
            const newName = this.generateName();
            if (this.currentPerson.name !== newName) {
                this.currentPerson.name = newName;

                const emailUser = newName.toLowerCase().replace(' ', '') + Math.floor(Math.random() * 9999);
                const service = this.store.config.emailSvc || 'tuamae';

                if (service === 'tuamae') {
                    this.currentPerson.email = emailUser + '@tuamaeaquelaursa.com';
                    this.currentPerson.link = `https://tuamaeaquelaursa.com/${emailUser}`;
                } else {
                    this.currentPerson.email = emailUser + '@firemail.com.br';
                    this.currentPerson.link = `https://firemail.com.br/${emailUser}`;
                }
                this.displayPerson(this.currentPerson);
            }
            return;
        }

        const generators = {
            cpf: this.generateCPF.bind(this),
            birthdate: this.generateBirthdate.bind(this),
            address: this.generateAddress.bind(this)
        };

        if (generators[field]) {
            const newValue = generators[field]();
            if (this.currentPerson[field] !== newValue) {
                this.currentPerson[field] = newValue;
                this.displayPerson(this.currentPerson);
            }
        } else {
            console.warn(`Campo desconhecido: ${field}`);
        }
    }

    
    /**
     * Generates valid CPF
     */
    generateCPF() {
        const nums = Array.from({length: 9}, () => Math.floor(Math.random() * 10));
        
        // First digit
        let sum = 0;
        for (let i = 0; i < 9; i++) {
            sum += nums[i] * (10 - i);
        }
        let d1 = 11 - (sum % 11);
        if (d1 >= 10) d1 = 0;
        nums.push(d1);
        
        // Second digit
        sum = 0;
        for (let i = 0; i < 10; i++) {
            sum += nums[i] * (11 - i);
        }
        let d2 = 11 - (sum % 11);
        if (d2 >= 10) d2 = 0;
        nums.push(d2);
        
        return nums.slice(0,3).join('') + '.' + 
               nums.slice(3,6).join('') + '.' + 
               nums.slice(6,9).join('') + '-' + 
               nums.slice(9,11).join('');
    }
    
    /**
     * Displays generated person
     */
    displayPerson(person) {
        const container = document.getElementById('personContent');
        if (!container) return;

        container.innerHTML = '';

        const card = document.createElement('div');
        card.className = 'person-card';

        const fieldMap = {
            'Nome': 'name',
            'CPF': 'cpf',
            'Nascimento': 'birthdate',
            'Endereço': 'address'
        };

        const fields = [
            { label: 'Nome', value: person.name, id: 'personName', regenerate: true },
            { label: 'CPF', value: person.cpf, id: 'personCPF', regenerate: true },
            { label: 'Nascimento', value: person.birthdate, id: 'personBirthdate', regenerate: true },
            { label: 'Email', value: person.email, id: 'personEmail', hasActions: true, link: person.link },
            { label: 'Endereço', value: person.address, id: 'personAddress', regenerate: true }
        ];

        fields.forEach(field => {
            const div = document.createElement('div');
            div.className = 'person-field';

            const label = document.createElement('span');
            label.className = 'field-label';
            label.textContent = field.label + ':';

            const valDiv = document.createElement('div');
            valDiv.className = 'field-value';

            const textSpan = document.createElement('span');
            textSpan.id = field.id;
            textSpan.textContent = field.value;
            valDiv.appendChild(textSpan);

            if (field.hasActions) {
                const editBtn = document.createElement('button');
                editBtn.className = 'btn-icon';
                editBtn.textContent = '✏';
                editBtn.addEventListener('click', () => this.changeEmailDomain());

                const linkBtn = document.createElement('button');
                linkBtn.className = 'btn-icon';
                linkBtn.textContent = '↗';
                linkBtn.id = 'personLinkBtn';
                linkBtn.addEventListener('click', () => {
                    const currentEmail = document.getElementById('personEmail').textContent;
                    const emailUser = currentEmail.split('@')[0];
                    const domain = currentEmail.split('@')[1];

                    let currentLink;
                    if (domain === 'tuamaeaquelaursa.com') {
                        currentLink = `https://tuamaeaquelaursa.com/${emailUser}`;
                    } else if (domain === 'firemail.com.br') {
                        currentLink = `https://firemail.com.br/${emailUser}`;
                    } else {
                        currentLink = field.link;
                    }
                    window.open(currentLink, '_blank');
                });
                valDiv.appendChild(editBtn);
                valDiv.appendChild(linkBtn);
            }

            if (field.regenerate) {
                const regenBtn = document.createElement('button');
                regenBtn.className = 'btn-icon';
                regenBtn.textContent = '↻';
                regenBtn.addEventListener('click', () => this.regenerateField(fieldMap[field.label]));
                valDiv.appendChild(regenBtn);
            }

            div.appendChild(label);
            div.appendChild(valDiv);
            card.appendChild(div);
        });

        container.appendChild(card);

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.gap = '12px';

        const saveBtn = document.createElement('button');
        saveBtn.className = 'btn btn-primary';
        saveBtn.textContent = 'Salvar Preset';
        saveBtn.addEventListener('click', () => this.savePerson());

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn btn-secondary';
        copyBtn.textContent = 'Copiar Dados';
        copyBtn.addEventListener('click', () => this.copyPerson(person));

        actions.appendChild(saveBtn);
        actions.appendChild(copyBtn);
        container.appendChild(actions);
    }
    
    /**
     * Changes email domain
     * Updates both the displayed email and the redirect link
     */
    changeEmailDomain() {
        const emailEl = document.getElementById('personEmail');
        if (!emailEl) return;
        
        const current = emailEl.textContent;
        const user = current.split('@')[0];
        
        let newEmail, newLink;
        
        if (current.includes('@tuamaeaquelaursa')) {
            newEmail = user + '@firemail.com.br';
            newLink = `https://firemail.com.br/${user}`;
        } else if (current.includes('@firemail')) {
            newEmail = user + '@tuamaeaquelaursa.com';
            newLink = `https://tuamaeaquelaursa.com/${user}`;
        } else {
            // If it doesn't recognize the domain, it keeps it as it is
            return;
        }
        
        // Updates the displayed email
        emailEl.textContent = newEmail;
        
        // Updates the current person object to maintain consistency
        if (this.currentPerson) {
            this.currentPerson.email = newEmail;
            this.currentPerson.link = newLink;
        }
    }
    
    /**
     * Saves person
     */
    async savePerson() {
        // Checks authentication before saving person
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.savePerson());
            return;
        }
        
        if (!this.currentPerson) {
            this.showToast('Nenhuma pessoa para salvar', 'error');
            return;
        }

        this.currentPerson.id = 'prs_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        if (!this.store.vault.prs) {
            this.store.vault.prs = [];
        }
        
        this.store.vault.prs.push(this.currentPerson);
        await this.store.saveVault();
        
        this.showToast('Pessoa salva');
    }
    
    /**
     * Copies person's data
     */
    copyPerson(person) {
        const text = `Nome: ${person.name}\nCPF: ${person.cpf}\nNascimento: ${person.birthdate}\nEmail: ${person.email}\nEndereço: ${person.address}`;
        
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Dados copiados');
        });
    }
    
    /**
     * Shows saved people
     */
    showSavedPersons() {
        // Checks authentication before showing saved people
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.showSavedPersons());
            return;
        }
        
        const container = document.getElementById('personContent');
        if (!container) return;
        
        if (!this.store.vault.prs || this.store.vault.prs.length === 0) {
            container.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Nenhuma pessoa salva</p>';
            return;
        }
        
        container.innerHTML = '';
        
        this.store.vault.prs.forEach(person => {
            const card = document.createElement('div');
            card.className = 'person-card';
            
            // Basic fields
            const fields = [
                { label: 'Nome', value: person.name },
                { label: 'CPF', value: person.cpf },
                { label: 'Nascimento', value: person.birthdate },
                { label: 'Email', value: person.email }
            ];
            
            fields.forEach(field => {
                const div = document.createElement('div');
                div.className = 'person-field';
                
                const label = document.createElement('span');
                label.className = 'field-label';
                label.textContent = field.label + ':';
                
                const value = document.createElement('span');
                value.className = 'field-value';
                value.textContent = field.value;
                
                div.appendChild(label);
                div.appendChild(value);
                card.appendChild(div);
            });
            
            // Actions
            const actions = document.createElement('div');
            actions.style.display = 'flex';
            actions.style.gap = '12px';
            actions.style.marginTop = '16px';
            
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn-icon';
            copyBtn.textContent = '📋';
            copyBtn.addEventListener('click', () => this.copyPerson(person));
            
            const delBtn = document.createElement('button');
            delBtn.className = 'btn-icon';
            delBtn.textContent = '🗑';
            delBtn.addEventListener('click', () => this.deletePerson(person.id));
            
            actions.appendChild(copyBtn);
            actions.appendChild(delBtn);
            card.appendChild(actions);
            
            container.appendChild(card);
        });
    }
    
    /**
     * Deletes person
     */
    async deletePerson(id) {
        // Checks authentication before deleting person
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.deletePerson(id));
            return;
        }
        
        if (!confirm('Excluir pessoa?')) return;
        
        this.store.vault.prs = this.store.vault.prs.filter(p => p.id !== id);
        await this.store.saveVault();
        
        this.showSavedPersons();
        this.showToast('Pessoa excluída');
    }
    
    /**
     * Loads notes
     */
    loadNotes() {
        // Checks authentication before loading notes
        if (!this.store.isAuthenticated()) {
            const container = document.getElementById('notesList');
            if (container) {
                container.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Autenticação necessária</p>';
            }
            return;
        }
        
        const container = document.getElementById('notesList');
        if (!container || !this.store.vault) return;
        
        const notes = this.store.vault.notes ? 
            this.store.vault.notes.filter(n => n.blk === this.currentBlock) : [];
        
        if (notes.length === 0) {
            container.innerHTML = '<p style="text-align:center;color:var(--txt-sec)">Nenhuma anotação salva</p>';
            return;
        }
        
        container.innerHTML = '';
        
        notes.forEach(note => {
            const card = document.createElement('div');
            card.className = 'note-card';
            
            // Header with title and buttons
            const header = document.createElement('div');
            header.style.display = 'flex';
            header.style.justifyContent = 'space-between';
            header.style.alignItems = 'center';
            header.style.marginBottom = '8px';
            
            const title = document.createElement('div');
            title.className = 'note-title';
            title.textContent = note.title;
            title.style.cursor = 'pointer';
            title.style.flex = '1';
            title.addEventListener('click', () => this.showNoteDetail(note));
            
            // Action buttons
            const actions = document.createElement('div');
            actions.style.display = 'flex';
            actions.style.gap = '8px';
            
            const editBtn = document.createElement('button');
            editBtn.className = 'btn-icon';
            editBtn.textContent = 'Editar';
            editBtn.title = 'Editar';
            editBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.editNote(note);
            });
            
            const delBtn = document.createElement('button');
            delBtn.className = 'btn-icon';
            delBtn.textContent = 'Apagar';
            delBtn.title = 'Excluir';
            delBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.deleteNote(note.id);
            });
            
            actions.appendChild(editBtn);
            actions.appendChild(delBtn);
            
            header.appendChild(title);
            header.appendChild(actions);
            
            const preview = document.createElement('div');
            preview.className = 'note-preview';
            preview.textContent = note.content.substring(0, 100) + '...';
            preview.style.cursor = 'pointer';
            preview.addEventListener('click', () => this.showNoteDetail(note));
            
            card.appendChild(header);
            card.appendChild(preview);
            container.appendChild(card);
        });
    }
    
    /**
     * Opens note modal
     */
    openNoteModal(note = null) {
        // Checks authentication before opening modal
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.openNoteModal(note));
            return;
        }
        
        const select = document.getElementById('noteBlk');
        const titleInput = document.getElementById('noteTitle');
        const contentInput = document.getElementById('noteContent');
        const modalTitle = document.querySelector('#noteModal .modal-title');
        const form = document.getElementById('noteForm');
        
        if (!select || !titleInput || !contentInput || !form) return;
        
        // Defines edit or create mode
        this.editingNoteId = note ? note.id : null;
        
        // Updates modal title
        if (modalTitle) {
            modalTitle.textContent = note ? 'Editar Anotação' : 'Nova Anotação';
        }
        
        // Fills fields if editing
        if (note) {
            titleInput.value = note.title;
            contentInput.value = note.content;
        } else {
            titleInput.value = '';
            contentInput.value = '';
        }
        
        // Fills block select
        select.innerHTML = '';
        this.store.vault.blks.forEach(blk => {
            const option = document.createElement('option');
            option.value = blk.id;
            option.textContent = blk.name;
            if (note && blk.id === note.blk) {
                option.selected = true;
            } else if (!note && blk.id === this.currentBlock) {
                option.selected = true;
            }
            select.appendChild(option);
        });
        
        this.openModal('noteModal');
    }
    
    /**
     * Saves note
     */
    async saveNote(e) {
        e.preventDefault();
        
        // Checks authentication before saving note
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => {
                const form = document.getElementById('noteForm');
                if (form) form.requestSubmit();
            });
            return;
        }
        
        const blk = document.getElementById('noteBlk').value;
        const title = document.getElementById('noteTitle').value;
        const content = document.getElementById('noteContent').value;
        
        if (!Security.validate(title, 100) || !Security.validate(content, 5000)) {
            this.showToast('Dados inválidos', 'error');
            return;
        }
        
        if (!this.store.vault.notes) {
            this.store.vault.notes = [];
        }
        
        // Checks if it is an edit or creation
        if (this.editingNoteId) {
            // Edits existing note
            const noteIndex = this.store.vault.notes.findIndex(n => n.id === this.editingNoteId);
            if (noteIndex !== -1) {
                this.store.vault.notes[noteIndex] = {
                    id: this.editingNoteId,
                    blk,
                    title,
                    content
                };
                await this.store.saveVault();
                this.loadNotes();
                this.closeModal('noteModal');
                this.showToast('Anotação atualizada');
                this.editingNoteId = null;
                e.target.reset();
                return;
            }
        }
        
        // Creates new note
        const note = {
            id: 'note_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            blk,
            title,
            content
        };
        
        this.store.vault.notes.push(note);
        await this.store.saveVault();
        
        this.loadNotes();
        this.closeModal('noteModal');
        this.showToast('Anotação salva');
        this.editingNoteId = null;
        
        e.target.reset();
    }
    
    /**
     * Edits note
     */
    editNote(note) {
        this.openNoteModal(note);
    }
    
    /**
     * Deletes note
     */
    async deleteNote(id) {
        // Checks authentication before deleting note
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.deleteNote(id));
            return;
        }
        
        if (!confirm('Excluir anotação?')) return;
        
        this.store.vault.notes = this.store.vault.notes.filter(n => n.id !== id);
        await this.store.saveVault();
        
        this.loadNotes();
        this.showToast('Anotação excluída');
    }
    
    /**
     * Shows note details
     */
    showNoteDetail(note) {
        // Checks authentication before showing details
        if (!this.store.isAuthenticated()) {
            this.checkAuthAndDo(() => this.showNoteDetail(note));
            return;
        }
        
        alert(`${note.title}\n\n${note.content}`);
    }
    
    /**
     * Saves settings
     */
    saveConfig() {
        const service = document.querySelector('input[name="emailSvc"]:checked');
        if (!service) return;
        
        this.store.config.emailSvc = service.value;
        this.store.saveConfig();
        
        this.closeModal('configModal');
        this.showToast('Configurações salvas');
    }
    
    /**
     * Opens modal
     */
    openModal(id) {
        const modal = document.getElementById(id);
        if (modal) modal.classList.add('active');
    }
    
    /**
     * Closes modal
     */
    closeModal(id) {
        // Clears edit state when closing note modal
        if (id === 'noteModal') {
            this.editingNoteId = null;
            const form = document.getElementById('noteForm');
            if (form) form.reset();
        }
        
        const modal = document.getElementById(id);
        if (modal) modal.classList.remove('active');
    }
    
    /**
     * Shows toast
     */
    showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        const msg = document.getElementById('toastMsg');
        
        if (!toast || !msg) return;
        
        msg.textContent = message;
        toast.className = `toast show ${type}`;
        
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }
}

