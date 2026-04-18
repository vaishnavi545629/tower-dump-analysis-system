import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyBwAAccPuDmrYiQDWvly0Tgnj6y316dOoo",
  authDomain: "towerdump-5ffe7.firebaseapp.com",
  projectId: "towerdump-5ffe7",
  storageBucket: "towerdump-5ffe7.firebasestorage.app",
  messagingSenderId: "660716143197",
  appId: "1:660716143197:web:4d1aa160ea8c54982103b4",
  measurementId: "G-8CTFTJ4V1Z",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
