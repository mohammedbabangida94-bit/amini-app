// =================================================================
// 1. GLOBAL FUNCTIONS
// =================================================================

// This function runs on page load and after login
async function fetchProfileData() {
  const token = localStorage.getItem('amini-token'); // Get the token
  const welcomeMessage = document.getElementById('welcome-message');

  if (!token) {
    // No token found, make sure login screen is visible
    document.getElementById('register-screen').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
    return;
  }

  // We have a token, let's use it
  try {
    const response = await fetch('https://amini-app-new.onrender.com/profile', {
      method: 'GET',
      headers: {
        'x-auth-token': token // Send the token in the header
      }
    });

    const data = await response.json();

    if (response.ok) {
      // SUCCESS! Token is valid.
      document.getElementById('register-screen').classList.add('hidden');
      document.getElementById('main-app').classList.remove('hidden');

      // Update the welcome message
      const email = data.message.split(', ')[1]; 
      welcomeMessage.textContent = `Welcome, ${email}!`;
    } else {
      // Token was bad (e.g., expired)
      localStorage.removeItem('amini-token');
      document.getElementById('register-screen').classList.remove('hidden');
      document.getElementById('main-app').classList.add('hidden');
    }
  } catch (error) {
    console.error('Error fetching profile:', error);
  }
}

// =================================================================
// 2. PAGE LOAD LISTENER (MAIN CODE)
// =================================================================
document.addEventListener('DOMContentLoaded', () => {
  // This variable will hold our coordinates
  let userLocation = null; 

  // Check if we are already logged in on page load
  fetchProfileData(); 

  // --- Registration Form ---
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault(); 
      const email = document.getElementById('register-email').value;
      const password = document.getElementById('register-password').value;
      const messageArea = document.getElementById('message-area');

      try {
        const response = await fetch('https://amini-app-new.onrender.com/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await response.json();

        if (response.ok) {
          messageArea.textContent = 'Registration successful! You can now log in.';
          messageArea.style.color = 'green';
        } else {
          messageArea.textContent = `Error: ${data.message}`;
          messageArea.style.color = 'red';
        }
      } catch (error) {
        messageArea.textContent = 'A network error occurred. Please try again.';
        messageArea.style.color = 'red';
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
        const response = await fetch('https://amini-app-new.onrender.com/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await response.json();

        if (response.ok) {
          localStorage.setItem('amini-token', data.token); // Save the token
          fetchProfileData(); // Fetch profile (this shows the app)
        } else {
          messageArea.textContent = `Error: ${data.message}`;
          messageArea.style.color = 'red';
        }
      } catch (error) {
        messageArea.textContent = 'A network error occurred. Please try again.';
        messageArea.style.color = 'red';
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
            locationDisplay.style.color = 'green';
          },
          (error) => {
            locationDisplay.textContent = 'Unable to get location.';
            locationDisplay.style.color = 'red';
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
        const response = await fetch('https://amini-app-new.onrender.com/api/report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-auth-token': token
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
        } else {
          statusLog.innerHTML += `<p>Error: ${data.message}</p>`;
        }
      } catch (error) {
        statusLog.innerHTML += `<p>Network error. Could not send report.</p>`;
      }
    });
  }
});

// =================================================================
// 3. AUTH TOGGLE LOGIC (Add this whole block)
// =================================================================
document.addEventListener('DOMContentLoaded', () => {
  // ... your existing code (fetchProfileData call, registerForm, loginForm, etc.) ...
  
  // --- Form Toggle Listeners ---
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const showRegisterLink = document.getElementById('show-register-link');
  const showLoginLink = document.getElementById('show-login-link');
  const loginMessage = document.getElementById('login-message-area');
  const registerMessage = document.getElementById('message-area');


  if (showRegisterLink && showLoginLink) {
    showRegisterLink.addEventListener('click', (event) => {
      event.preventDefault(); // Stop the link from jumping the page
      loginForm.classList.add('hidden');
      registerForm.classList.remove('hidden');
      // Also clear any old error messages
      if(loginMessage) loginMessage.textContent = ''; 
    });

    showLoginLink.addEventListener('click', (event) => {
      event.preventDefault(); // Stop the link from jumping the page
      loginForm.classList.remove('hidden');
      registerForm.classList.add('hidden');
      // Also clear any old error messages
      if(registerMessage) registerMessage.textContent = '';
    });
  }

  // ... your other existing code (locationButton, sendMessageButton, etc.) ...
});