/**
 * HackAgent Background Script
 *
 * Handles extension lifecycle and message routing.
 */

// Ensure content script is injected when extension is installed/enabled
browser.runtime.onInstalled.addListener(() => {
    console.log('HackAgent extension installed');
});

// Handle messages from popup that need background processing
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkBackend') {
        fetch('http://localhost:5000/api/status')
            .then(resp => resp.json())
            .then(data => sendResponse({ online: true, data }))
            .catch(() => sendResponse({ online: false }));
        return true;
    }
});
