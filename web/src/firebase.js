import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore, connectFirestoreEmulator } from "firebase/firestore";
import { getFunctions, connectFunctionsEmulator } from "firebase/functions";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID,
};

console.log("firebase projectId:", firebaseConfig.projectId);
console.log("firebase authDomain:", firebaseConfig.authDomain);

// Emulators are now opt-in so local dev can point at the real project by default.
// Set `VITE_USE_EMULATORS=true` to use emulators.
const useEmulators = String(import.meta.env.VITE_USE_EMULATORS || "").toLowerCase() === "true";


const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const provider = new GoogleAuthProvider();
export const db = getFirestore(app);
export const fns = getFunctions(app);

if (useEmulators) {
  // Use "localhost" so it matches Vite's origin host.
  connectFirestoreEmulator(db, "localhost", 8080);
  connectFunctionsEmulator(fns, "127.0.0.1", 5001);
}