// Add this new function at the top of your script.js file
async function fetchProfileData() {
  const token = localStorage.getItem('amini-token'); // Get the token from storage
  const welcomeMessage = document.getElementById('welcome-message');

  if (!token) {
    // If no token is found, the user needs to log in.
    // We'll hide the app and show the login screen.
    document.getElementById('register-screen').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
    return;
  }

  // We have a token. Let's try to use it.
  try {
    const response = await fetch('https://amin-app.onrender.com/profile', {
      method: 'GET',
      headers: {
        'x-auth-token': token // This is how you send the token!
      }
    });

    const data = await response.json();

    if (response.ok) {
      // SUCCESS! Token is valid.
      // 1. Show the main app
      document.getElementById('register-screen').classList.add('hidden');
      document.getElementById('main-app').classList.remove('hidden');

      // 2. Update the welcome message
      // The data.message is "Welcome to your profile, user@example.com"
      // Let's get the email from that message.
      const email = data.message.split(', ')[1]; 
      welcomeMessage.textContent = `Welcome, ${email}!`;

    } else {
      // Token was bad (e.g., expired)
      console.log('Token is not valid:', data.message);
      // Clean up the bad token and show the login screen
      localStorage.removeItem('amini-token');
      document.getElementById('register-screen').classList.remove('hidden');
      document.getElementById('main-app').classList.add('hidden');
    }
  } catch (error) {
    console.error('Error fetching profile:', error);
    // Handle network errors
  }
}

// Wait for the HTML to be fully loaded before running code
document.addEventListener('DOMContentLoaded', () => {
    let userLocation = null;
    fetchProfileData();

    // This is your existing code
  async function fetchProfileData() {
    // ...

    // Find the registration form
    const registerForm = document.getElementById('register-form');
    
    if (registerForm) {
        // 1. Listen for the user clicking the "Register" button
        
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault(); // Stop the browser from refreshing

            // 2. Get the values from the input boxes
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const messageArea = document.getElementById('message-area');

            // 3. Connect to your API on Render
            try {
                const response = await fetch('https://amin-app.onrender.com/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                });

                const data = await response.json();

                // 4. Show a success or error message to the user
                if (response.ok) {
                    messageArea.textContent = 'Registration successful! You can now log in.';
                    messageArea.style.color = 'green';
                } else {
                    messageArea.textContent = `Error: ${data.message}`; // e.g., "User already exists"
                    messageArea.style.color = 'red';
                }

            } catch (error) {
                console.error('Network error:', error);
                messageArea.textContent = 'A network error occurred. Please try again.';
                messageArea.style.color = 'red';
            }
        });
    }
});

// --- ADD THIS NEW LOGIN CODE AT THE END OF SCRIPT.JS ---

// Find the login form
const loginForm = document.getElementById('login-form');

if (loginForm) {
  // 1. Listen for the user clicking the "Login" button
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault(); // Stop the browser from refreshing

    // 2. Get the values from the login input boxes
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const messageArea = document.getElementById('login-message-area');

    // 3. Connect to your LOGIN API on Render
    try {
      const response = await fetch('https://amin-app.onrender.com/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: email,
          password: password
        })
      });

      // This is your existing loginForm code...
if (loginForm) {
  // ... all your login form code ...
}

// --- ADD THIS NEW CODE BLOCK BELOW IT ---
const sendMessageButton = document.getElementById('send-message-btn');
const messageInput = document.getElementById('secure-message-input');
const statusLog = document.getElementById('status-log'); // We'll show success here

if (sendMessageButton) {
  sendMessageButton.addEventListener('click', async () => {
    const message = messageInput.value;
    const token = localStorage.getItem('amini-token'); // Get the saved token

    if (!message) {
      alert('Please type a message first.');
      return;
    }
    if (!token) {
      alert('You must be logged in to send a message.');
      return;
    }

    // This is the fetch, just like your profile fetch
    try {
      const response = await fetch('https://amin-app.onrender.com/api/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token // <-- This proves you are logged in
        },
        body: JSON.stringify({
          message: message
          location: userLocation
        })
      });

      const data = await response.json();

      if (response.ok) {
        // Success!
        statusLog.innerHTML += `<p>Status: ${data.message}</p>`;
        messageInput.value = ''; // Clear the text box
      } else {
        // Handle errors from the server
        statusLog.innerHTML += `<p>Error: ${data.message}</p>`;
      }

    } catch (error) {
      console.error('Network error:', error);
      statusLog.innerHTML += `<p>Network error. Could not send report.</p>`;
    }
  });
}

// This is your existing sendMessageButton code...
if (sendMessageButton) {
  // ...
}

// --- ADD THIS NEW CODE BLOCK BELOW IT ---
const locationButton = document.getElementById('get-location-btn');
const locationDisplay = document.getElementById('location-display');

if (locationButton) {
  locationButton.addEventListener('click', () => {
    if ("geolocation" in navigator) {
      locationDisplay.textContent = 'Finding your location...';
      
      // This is the browser API that asks the user for permission
      navigator.geolocation.getCurrentPosition(
        (position) => {
          // Success! Save the coordinates
          userLocation = {
            lat: position.coords.latitude,
            long: position.coords.longitude
          };
          locationDisplay.textContent = `Location updated: ${userLocation.lat}, ${userLocation.long}`;
          locationDisplay.style.color = 'green';
        },
        (error) => {
          // Handle errors
          console.error("Error getting location:", error.message);
          locationDisplay.textContent = 'Unable to get location. Please check permissions.';
          locationDisplay.style.color = 'red';
        }
      );
    } else {
      locationDisplay.textContent = 'Geolocation is not available on your browser.';
      locationDisplay.style.color = 'red';
    }
  });
}
      const data = await response.json();

      // 4. Show a success or error message
      if (response.ok) {
        // 1. Save the new token
        localStorage.setItem('amini-token', data.token);

        // 2. Fetch the profile data (this will show the app)
        fetchProfileData();

      } else {
        messageArea.textContent = `Error: ${data.message}`; // e.g., "Invalid credentials"
        messageArea.style.color = 'red';
      }

    } catch (error) {
      console.error('Network error:', error);
      messageArea.textContent = 'A network error occurred. Please try again.';
      messageArea.style.color = 'red';
    }
  });
}