javascript
document.addEventListener('DOMContentLoaded', () => {

    // --- DOM Element Selection ---
    const loginScreen = document.getElementById('login-screen');
    const mainApp = document.getElementById('main-app');
    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const usernameInput = document.getElementById('username');
    const welcomeMessage = document.getElementById('welcome-message');
    const sosBtn = document.getElementById('sos-btn');
    const locationDisplay = document.getElementById('location-display');
    const getLocationBtn = document.getElementById('get-location-btn');
    const contactList = document.getElementById('contact-list');
    const contactInput = document.getElementById('contact-input');
    const addContactBtn = document.getElementById('add-contact-btn');
    const secureMessageInput = document.getElementById('secure-message-input');
    const sendMessageBtn = document.getElementById('send-message-btn');
    const statusLog = document.getElementById('status-log');

    // --- App State ---
    let currentUser = null;
    let emergencyContacts = ["Police (911)", "Ambulance (112)"];
    let sosHoldTimer = null;
    let sosTriggered = false;

    // --- Utility Functions ---
    const logStatus = (message) => {
        const p = document.createElement('p');
        p.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        statusLog.prepend(p); // Add new logs to the top
    };

    // --- Authentication ---
    const handleLogin = () => {
        const username = usernameInput.value.trim();
        if (username) {
            currentUser = username;
            welcomeMessage.textContent = `Welcome, ${currentUser}!`;
            loginScreen.classList.add('hidden');
            mainApp.classList.remove('hidden');
            logStatus(`User '${currentUser}' logged in.`);
            updateLocation(); // Get location on login
        } else {
            alert('Please enter your name.');
        }
    };

    const handleLogout = () => {
        logStatus(`User '${currentUser}' logged out.`);
        currentUser = null;
        usernameInput.value = '';
        mainApp.classList.add('hidden');
        loginScreen.classList.remove('hidden');
    };

    // --- Geolocation ---
    const updateLocation = () => {
        if (!navigator.geolocation) {
            locationDisplay.textContent = 'Geolocation is not supported by your browser.';
            logStatus('Geolocation not supported.');
            return;
        }

        logStatus('Attempting to get location...');
        navigator.geolocation.getCurrentPosition(
            (position) => {
                const { latitude, longitude } = position.coords;
                const locationText = `Lat: ${latitude.toFixed(4)}, Lon: ${longitude.toFixed(4)}`;
                locationDisplay.textContent = locationText;
                logStatus(`Location acquired: ${locationText}`);
            },
            () => {
                locationDisplay.textContent = 'Unable to retrieve your location.';
                logStatus('Failed to acquire location.');
            }
        );
    };

    // --- SOS Panic Button ---
    const triggerSOS = () => {
        if (sosTriggered) return; // Prevent multiple triggers
        sosTriggered = true;
        sosBtn.style.backgroundColor = '#28a745'; // Change color to green to show it's active
        sosBtn.textContent = 'SENT';
        
        logStatus('!!! SOS TRIGGERED !!!');
        updateLocation(); // Get latest location
        
        // Simulate sending alerts
        setTimeout(() => {
            const currentLocation = locationDisplay.textContent;
            logStatus(`Alerting ${emergencyContacts.length} contacts...`);
            logStatus(`Sending location: ${currentLocation}`);
            
            // In a real app, this would be an API call to an SMS/Push notification service
            alert(`SOS ACTIVATED!\nNotifying emergency contacts with your location:\n${currentLocation}`);

            // Reset button after some time
            setTimeout(() => {
                sosBtn.style.backgroundColor = '#dc3545';
                sosBtn.textContent = 'SOS';
                sosTriggered = false;
                logStatus('SOS system reset.');
            }, 5000);

        }, 1000);
    };

    // --- Emergency Contacts ---
    const renderContacts = () => {
        contactList.innerHTML = '';
        emergencyContacts.forEach(contact => {
            const li = document.createElement('li');
            li.textContent = contact;
            contactList.appendChild(li);
        });
    };

    const addContact = () => {
        const newContact = contactInput.value.trim();
        if (newContact && !emergencyContacts.includes(newContact)) {
            emergencyContacts.push(newContact);
            renderContacts();
            logStatus(`Contact '${newContact}' added.`);
            contactInput.value = '';
        }
    };

    // --- Secure Messaging (Simulation) ---
    const sendSecureMessage = () => {
        const message = secureMessageInput.value.trim();
        if (!message) {
            alert('Please type a message to send.');
            return;
        }

        // SIMULATION: In a real app, you would use a robust crypto library (e.g., Web Crypto API).
        // Here, we use Base64 encoding to represent "encryption".
        const encryptedMessage = btoa(message);
        
        logStatus('Encrypting message...');
        logStatus(`Sending encrypted message: ${encryptedMessage.substring(0, 20)}...`);
        alert('Secure Message Sent!\n(Simulated encryption)');
        secureMessageInput.value = '';
    };

    // --- Event Listeners ---
    loginBtn.addEventListener('click', handleLogin);
    logoutBtn.addEventListener('click', handleLogout);
    getLocationBtn.addEventListener('click', updateLocation);
    addContactBtn.addEventListener('click', addContact);
    sendMessageBtn.addEventListener('click', sendSecureMessage);

    // SOS Button with press-and-hold logic
    sosBtn.addEventListener('mousedown', () => {
        sosBtn.style.transform = 'scale(0.95)';
        sosHoldTimer = setTimeout(triggerSOS, 3000); // Trigger after 3 seconds
    });

    sosBtn.addEventListener('mouseup', () => {
        sosBtn.style.transform = 'scale(1)';
        clearTimeout(sosHoldTimer); // Cancel if button is released early
    });
    
    // Also clear timer if mouse leaves the button area
    sosBtn.addEventListener('mouseleave', () => {
        clearTimeout(sosHoldTimer);
    });

    // --- Initial Setup ---
    renderContacts(); // Initial render of default contacts
});

// --- In your main HTML file's <script> or in your separate JavaScript file ---

// Import the necessary functions from the Firebase modular SDK
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged } from "firebase/auth";
import { initializeApp } from "firebase/app";

// Your Firebase project configuration (get this from Project settings -> Your apps -> Config)
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "amini-app-2c4d1.firebaseapp.com",
  projectId: "amini-app-2c4d1",
  storageBucket: "amini-app-2c4d1.appspot.com",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId: "YOUR_APP_ID"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Get a reference to the Firebase Authentication service
const auth = getAuth(app); // This 'auth' object is what you'll use for all auth operations

// Assuming you have an HTML form with ID 'signUpForm' and inputs for email and password
const signUpForm = document.getElementById('signUpForm');
signUpForm.addEventListener('submit', (e) => {
    e.preventDefault(); // Prevent default form submission

    const emailInput = document.getElementById('signUpEmail'); // Assuming ID for email input
    const passwordInput = document.getElementById('signUpPassword'); // Assuming ID for password input

    const email = emailInput.value;
    const password = passwordInput.value;

    createUserWithEmailAndPassword(auth, email, password)
      .then((userCredential) => {
        // Signed up successfully!
        const user = userCredential.user;
        console.log("New user signed up:", user);
        // You can redirect the user or update the UI here.
        // For example, display a welcome message:
        alert(`Welcome, ${user.email}! You've successfully signed up.`);
        // Or perhaps automatically sign them in:
        // (createUserWithEmailAndPassword automatically signs in the user upon success)
      })
      .catch((error) => {
        // Handle errors here.
        const errorCode = error.code;
        const errorMessage = error.message;
        console.error("Error signing up:", errorCode, errorMessage);
        // Display the error message to the user in your UI
        // e.g., document.getElementById('errorMessageDisplay').textContent = errorMessage;
      });
});

// Assuming you have an HTML form with ID 'signInForm' and inputs for email and password
const signInForm = document.getElementById('signInForm');
signInForm.addEventListener('submit', (e) => {
    e.preventDefault(); // Prevent default form submission

    const emailInput = document.getElementById('signInEmail'); // Assuming ID for email input
    const passwordInput = document.getElementById('signInPassword'); // Assuming ID for password input

    const email = emailInput.value;
    const password = passwordInput.value;

    signInWithEmailAndPassword(auth, email, password)
      .then((userCredential) => {
        // Signed in successfully!
        const user = userCredential.user;
        console.log("User signed in:", user);
        // You can redirect the user to a dashboard or update the UI.
        alert(`Welcome back, ${user.email}!`);
      })
      .catch((error) => {
        // Handle errors here.
        const errorCode = error.code;
        const errorMessage = error.message;
        console.error("Error signing in:", errorCode, errorMessage);
        // Display the error message to the user in your UI
        // e.g., document.getElementById('errorMessageDisplay').textContent = errorMessage;
      });
});

// Ensure 'auth' object is initialized as previously discussed:
// import { getAuth, onAuthStateChanged } from "firebase/auth";
// const auth = getAuth(app); // 'app' being your initialized Firebase app

// Get references to UI elements you might want to show/hide
const userDashboard = document.getElementById('userDashboard');
const loginForm = document.getElementById('loginForm');
const userNameDisplay = document.getElementById('userNameDisplay');
const signOutButton = document.getElementById('signOutButton');

// Attach the authentication state observer
onAuthStateChanged(auth, (user) => {
  if (user) {
    // User is signed in!
    // You can now access user details:
    const uid = user.uid;
    const email = user.email;

    console.log("User is signed in:", user);
    console.log("User UID:", uid);
    console.log("User Email:", email);

    // Update your UI to show signed-in state
    if (loginForm) loginForm.style.display = 'none'; // Hide login form
    if (userDashboard) userDashboard.style.display = 'block'; // Show dashboard
    if (userNameDisplay) userNameDisplay.textContent = `Hello, ${email}!`;
    if (signOutButton) signOutButton.style.display = 'block';

    // ... You can fetch user-specific data from Firestore/Realtime Database here
    // or redirect to a protected page.

  } else {
    // User is signed out.
    console.log("User is signed out.");

    // Update your UI to show signed-out state
    if (loginForm) loginForm.style.display = 'block'; // Show login form
    if (userDashboard) userDashboard.style.display = 'none'; // Hide dashboard
    if (userNameDisplay) userNameDisplay.textContent = '';
    if (signOutButton) signOutButton.style.display = 'none';

    // ... Potentially redirect to a public page or login screen.
  }
});

// Ensure 'auth' object is initialized as previously discussed:
// import { getAuth, signOut } from "firebase/auth";
// const auth = getAuth(app); // 'app' being your initialized Firebase app

// Get a reference to your sign-out button
const signOutButton = document.getElementById('signOutButton');

signOutButton.addEventListener('click', () => {
    signOut(auth).then(() => {
        // Sign-out successful.
        console.log("User signed out successfully.");
        // At this point, the onAuthStateChanged listener will fire
        // with 'user' as null, allowing your UI to update automatically.
        alert("You have been signed out.");

        // You might want to redirect the user to a login page or home page
        // window.location.href = '/login.html'; // Example redirection
    }).catch((error) => {
        // An error happened.
        console.error("Error signing out:", error);
        alert(`Error signing out: ${error.message}`);
    });
});

// Example of clearing specific items after sign-out
signOut(auth).then(() => {
    console.log("User signed out successfully.");
    localStorage.removeItem('userPreferences');
    localStorage.removeItem('lastVisitedPage');
    // ... any other user-specific localStorage items

    // You could also clear ALL local storage if all of it is user-specific:
    // localStorage.clear(); // Use with care!

    // ... additional UI resets
}).catch((error) => {
    // Handle error
});

// Example within onAuthStateChanged when user is null
onAuthStateChanged(auth, (user) => {
  if (user) {
    // User is signed in
    currentUserData = user; // Assign user data
    userSpecificSettings = fetchUserSettings(user.uid); // Fetch and store user settings
  } else {
    // User is signed out. Clear internal state.
    currentUserData = null; // Reset global user object
    userSpecificSettings = {}; // Clear user settings
    // If using a state management library, dispatch a 'RESET_USER_STATE' action
    // store.dispatch(resetUserState());
  }
});

// Example within either signOut().then() or onAuthStateChanged (user === null)
const userProfilePic = document.getElementById('userProfilePic');
const welcomeMessage = document.getElementById('welcomeMessage');
const personalDataList = document.getElementById('personalDataList');

if (userProfilePic) userProfilePic.src = '/images/default-avatar.png'; // Reset to default
if (welcomeMessage) welcomeMessage.textContent = 'Please sign in.'; // Clear personalized message
if (personalDataList) personalDataList.innerHTML = ''; // Clear user-specific data from a list/table


function clearUserDataAndState() {
    // Clear localStorage items
    localStorage.removeItem('userPreferences');
    localStorage.removeItem('lastVisitedPage');

    // Reset JavaScript variables
    currentUserData = null;
    userSpecificSettings = {};
    // ... any other relevant variables

    // Reset UI elements
    const userProfilePic = document.getElementById('userProfilePic');
    const welcomeMessage = document.getElementById('welcomeMessage');
    const personalDataList = document.getElementById('personalDataList');

    if (userProfilePic) userProfilePic.src = '/images/default-avatar.png';
    if (welcomeMessage) welcomeMessage.textContent = 'Please sign in.';
    if (personalDataList) personalDataList.innerHTML = '';

    // ... potentially redirect to a public page
    // window.location.href = '/';
}

// Call it on successful sign out
signOut(auth).then(() => {
    console.log("User signed out successfully.");
    clearUserDataAndState();
}).catch((error) => {
    console.error("Error signing out:", error);
});

// Call it within onAuthStateChanged if user becomes null
onAuthStateChanged(auth, (user) => {
  if (!user) {
    console.log("onAuthStateChanged detected user signed out.");
    clearUserDataAndState();
  }
  // ... rest of your onAuthStateChanged logic for signed in user
});

match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}

rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false; // Deny all by default
    }
  }
}

rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Allow authenticated users to read and write their own 'user' document
    // (where the document ID matches their authenticated UID)
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    // Allow authenticated users to create new posts, and read/update/delete
    // posts where the 'userId' field in the document matches their authenticated UID.
    match /posts/{postId} {
      allow read: if request.auth != null; // Any authenticated user can read posts
      allow create: if request.auth != null && request.auth.uid == request.resource.data.userId; // Can only create a post for themselves
      allow update, delete: if request.auth != null && request.auth.uid == resource.data.userId; // Can only update/delete their own posts
    }

    // Default catch-all (should still deny if not matched by more specific rules)
    match /{document=**} {
      allow read, write: if false;
    }
  }
}

rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Define a reusable function for title validation
    function isValidPostTitle(title) {
      return title is string && title.size() > 0 && title.size() < 50;
    }

    // Define a reusable function for content validation
    function isValidPostContent(content) {
      return content is string && content.size() > 0;
    }

    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    match /posts/{postId} {
      // Any authenticated user can read posts
      allow read: if request.auth != null;

      // Allow authenticated users to create new posts,
      // AND validate the incoming data for required fields and formats.
      allow create: if
        request.auth != null &&
        request.auth.uid == request.resource.data.userId && // User owns the post
        request.resource.data.keys().hasAll(['title', 'content', 'userId']) && // Required fields
        isValidPostTitle(request.resource.data.title) && // Title validation
        isValidPostContent(request.resource.data.content); // Content validation

      // Allow authenticated users to update their own posts,
      // AND validate the updated data.
      allow update: if
        request.auth != null &&
        request.auth.uid == resource.data.userId && // User owns the existing post
        request.resource.data.keys().hasAll(['title', 'content', 'userId']) && // Ensure required fields are present after update
        isValidPostTitle(request.resource.data.title) && // Title validation for updated data
        isValidPostContent(request.resource.data.content); // Content validation for updated data

      // Allow authenticated users to delete their own posts
      allow delete: if request.auth != null && request.auth.uid == resource.data.userId;
    }

    // Deny all other access by default
    match /{document=**} {
      allow read, write: if false;
    }
  }
}

npm install -g firebase-tools

firebase --version

firebase init

firebase init emulators

firebase emulators:start --only firestore

// AFTER you initialize your Firebase app:
import { getFirestore, connectFirestoreEmulator } from "firebase/firestore";
import { getAuth, connectAuthEmulator } from "firebase/auth"; // If using Auth emulator too

// ... your firebaseConfig and initializeApp(firebaseConfig) code ...

// Get the Firestore service instance
const db = getFirestore(app);
const auth = getAuth(app); // Get Auth service instance

// Connect to the Firestore emulator
if (location.hostname === "localhost") {
  connectFirestoreEmulator(db, "localhost", 8080); // Default port for Firestore
  connectAuthEmulator(auth, "http://localhost:9099"); // Default port for Auth
  console.log("Connected to Firebase Emulators!");
}

firebase login

firebase projects:list

firebase init hosting
