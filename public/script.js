// Wait for the HTML to be fully loaded before running code
document.addEventListener('DOMContentLoaded', () => {

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