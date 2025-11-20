// IMPORTANT: Replace the backend URL with your live Render URL
const backendUrl = 'https://amini-app-new.onrender.com';

// =================================================================
// 1. GLOBAL FUNCTIONS
// =================================================================

// Function to fetch and display the Activity Log

async function fetchAndRenderLog() {
    const logDisplay = document.getElementById('activity-log-display');
    logDisplay.innerHTML = '<p style="color: #1a3852ff;">Fetching latest reports...</p>';

    try {
        const token = localStorage.getItem('amini-token'); // Use the correct key: amini-token
        const response = await fetch(`${backendUrl}/api/reports`, {
            method: 'GET',
            headers: {
                // Ensure you send the token correctly: Bearer <token>
                'Authorization': `Bearer ${token}`, 
                'Content-Type': 'application/json'
            }
        });

        const reports = await response.json();

        if (response.ok) {
            logDisplay.innerHTML = ''; 
            if (reports.length === 0) {
                logDisplay.innerHTML = '<p>No reports found.</p>';
                return;
            }

            reports.forEach(report => {
                const logEntry = document.createElement('div');
                logEntry.className = 'log-entry';
                
                const date = new Date(report.date).toLocaleString(); 
                
                logEntry.innerHTML = `
                    <p style="font-weight: 600;">Status: SOS Report Sent</p>
                    <p style="font-size: 0.8rem; color: #333;">Date: ${date}</p>
                    <p style="font-size: 0.8rem; color: #333;">Message: ${report.message || 'N/A'}</p>
                    <hr style="border-top: 1px dashed #ddd; margin: 5px 0;">
                `;
                logDisplay.appendChild(logEntry);
            });
        } else {
            logDisplay.innerHTML = `<p style="color: var(--color-alert-red);">Error: ${reports.message || 'Failed to load log.'}</p>`;
        }

    } catch (error) {
        logDisplay.innerHTML = `<p style="color: var(--color-alert-red);">Network Error loading log.</p>`;
    }
}


// Function to switch to the main dashboard screen
function showMainApp(email) {
    document.getElementById('welcome-message').textContent = `Welcome, ${email}!`;
    document.getElementById('register-screen').classList.add('hidden');
    document.getElementById('main-app').classList.remove('hidden');

    // CRITICAL: Load the Activity Log when the app opens
    fetchAndRenderLog(); 
}

// =================================================================
// 2. PAGE LOAD LISTENER (MAIN CODE)
// =================================================================
document.addEventListener('DOMContentLoaded', () => {
    // This variable will hold our coordinates
    let userLocation = null; 
    
    // --- Initial Screen Check (No /profile route needed) ---
    const token = localStorage.getItem('amini-token');
    if (token) {
        // If a token exists, assume they are logged in and skip the login screen
        // NOTE: We can't know the email without a /profile route, so we use 'User'
        showMainApp("User"); 
    } else {
        document.getElementById('register-screen').classList.remove('hidden');
    }
    
    // --- Registration Form ---
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault(); 
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const messageArea = document.getElementById('message-area');

            try {
                const response = await fetch(`${backendUrl}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await response.json();

                if (response.ok) {
                    messageArea.textContent = 'Registration successful! You can now log in.';
                    messageArea.style.color = 'var(--color-success-green)';
                } else {
                    messageArea.textContent = `Error: ${data.message}`;
                    messageArea.style.color = 'var(--color-alert-red)';
                }
            } catch (error) {
                messageArea.textContent = 'A network error occurred. Please try again.';
                messageArea.style.color = 'var(--color-alert-red)';
            }
        });
    }

    // --- Login Form ---
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const messageArea = document.getElementById('login-message-area');

            try {
                const response = await fetch(`${backendUrl}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await response.json();

                if (response.ok) {
                    localStorage.setItem('amini-token', data.token); // Save the token
                    messageArea.textContent = 'Login successful!';
                    messageArea.style.color = 'var(--color-success-green)';
                    showMainApp(email); // Show app and pass the email
                } else {
                    messageArea.textContent = `Error: ${data.message || 'Login failed: Invalid credentials.'}`;
                    messageArea.style.color = 'var(--color-alert-red)';
                }
            } catch (error) {
                messageArea.textContent = 'A network error occurred. Could not reach server.';
                messageArea.style.color = 'var(--color-alert-red)';
            }
        });
    }

    // --- Update Location Button ---
    const locationButton = document.getElementById('get-location-btn');
    const locationDisplay = document.getElementById('location-display');
    if (locationButton) {
        locationButton.addEventListener('click', () => {
            if ("geolocation" in navigator) {
                locationDisplay.textContent = 'Finding your location...';
                navigator.geolocation.getCurrentPosition(
                    (position) => {
                        userLocation = { // Save the coordinates
                            lat: position.coords.latitude,
                            long: position.coords.longitude
                        };
                        locationDisplay.textContent = `Location updated: ${userLocation.lat.toFixed(4)}, ${userLocation.long.toFixed(4)}`;
                        locationDisplay.style.color = 'var(--color-success-green)';
                    },
                    (error) => {
                        locationDisplay.textContent = 'Unable to get location.';
                        locationDisplay.style.color = 'var(--color-alert-red)';
                    }
                );
            } else {
                locationDisplay.textContent = 'Geolocation is not available.';
            }
        });
    }

    // --- Send Secure Message Button ---
    const sendMessageButton = document.getElementById('send-message-btn');
    const messageInput = document.getElementById('secure-message-input');
    const statusLog = document.getElementById('status-log');
    if (sendMessageButton) {
        sendMessageButton.addEventListener('click', async () => {
            const message = messageInput.value;
            const token = localStorage.getItem('amini-token');

            if (!message) { alert('Please type a message first.'); return; }
            if (!token) { alert('You must be logged in.'); return; }

            try {
                const response = await fetch(`${backendUrl}/api/report`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}` // Use the standard Authorization header
                    },
                    body: JSON.stringify({
                        message: message,
                        location: userLocation // Send the location data
                    })
                });

                const data = await response.json();
                if (response.ok) {
                    statusLog.innerHTML += `<p>Status: ${data.message}</p>`;
                    messageInput.value = ''; // Clear the text box
                    // Refresh the log after sending a new report
                    fetchAndRenderLog();
                } else {
                    statusLog.innerHTML += `<p>Error: ${data.message}</p>`;
                }
            } catch (error) {
                statusLog.innerHTML += `<p>Network error. Could not send report.</p>`;
            }
        });
    }
    
    // --- Form Toggle Listeners ---
    const showRegisterLink = document.getElementById('show-register-link');
    const showLoginLink = document.getElementById('show-login-link');
    const loginMessage = document.getElementById('login-message-area');
    const registerMessage = document.getElementById('message-area');

    if (showRegisterLink && showLoginLink) {
        showRegisterLink.addEventListener('click', (event) => {
            event.preventDefault(); 
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
            if(loginMessage) loginMessage.textContent = ''; 
        });

        showLoginLink.addEventListener('click', (event) => {
            event.preventDefault(); 
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
            if(registerMessage) registerMessage.textContent = '';
        });
    }
});