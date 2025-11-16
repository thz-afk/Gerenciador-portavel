'use strict';

/**
 * Main Entry Point
 * Initializes the application
 */
const app = new App();

// Periodically checks for authentication expiration
setInterval(() => {
    if (app.store && !app.store.isAuthenticated() && app.store.vault) {
        // If authentication has expired, redirects to the login screen
        app.store.lock();
        location.reload();
    }
}, 5000); // Checks every 5 seconds

window.addEventListener('load', () => {
    setTimeout(() => {
        const genBtn = document.getElementById('genPwdBtn');
        if (genBtn) genBtn.click();
    }, 100);
});

