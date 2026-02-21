/**
 * HackAgent Content Script
 *
 * Captures page data when requested by the popup.
 * Runs in the context of the web page.
 */

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPageData') {
        const data = {
            html: document.documentElement.outerHTML.substring(0, 100000),
            url: window.location.href,
            title: document.title,
            cookies: document.cookie ? document.cookie.split(';').map(c => {
                const [name, ...rest] = c.trim().split('=');
                return { name: name.trim(), value: rest.join('=').substring(0, 50) };
            }) : [],
            forms: Array.from(document.forms).slice(0, 10).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.elements).slice(0, 20).map(el => ({
                    name: el.name,
                    type: el.type,
                    id: el.id,
                })),
            })),
            scripts: Array.from(document.scripts).slice(0, 20).map(s => ({
                src: s.src || null,
                type: s.type || null,
                inline: s.src ? false : true,
                length: s.textContent.length,
            })),
            links: Array.from(document.links).slice(0, 50).map(a => ({
                href: a.href,
                text: a.textContent.trim().substring(0, 100),
            })),
            meta: Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.getAttribute('name') || m.getAttribute('property'),
                content: (m.getAttribute('content') || '').substring(0, 200),
            })).filter(m => m.name),
        };

        sendResponse(data);
    }
    return true;
});
