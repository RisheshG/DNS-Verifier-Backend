// Import Firebase App and necessary services
import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth'; // Import authentication module

// Your Firebase config
const firebaseConfig = {
    apiKey: "AIzaSyBPAKJ_QWehMaas3GQm75P2ceYYPKO7iC0",
    authDomain: "dns-verifier.firebaseapp.com",
    projectId: "dns-verifier",
    storageBucket: "dns-verifier.firebasestorage.app",
    messagingSenderId: "849931378550",
    appId: "1:849931378550:web:05aecd612f3f4043bb2457",
    measurementId: "G-3EM9RDYYTZ"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firebase Auth
const auth = getAuth(app);

// Export auth to be used in your other files
export { auth };
