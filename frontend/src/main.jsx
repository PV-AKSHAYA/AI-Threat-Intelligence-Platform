// import { StrictMode } from 'react'
// import { createRoot } from 'react-dom/client'
// import './index.css'
// import App from './App.jsx'

// createRoot(document.getElementById('root')).render(
//   <StrictMode>
//     <App />
//   </StrictMode>,
// )

import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { Toaster } from "react-hot-toast";

import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 2500,
        style: {
          background: "#111827",
          color: "#F9FAFB",
          border: "1px solid #1F2937",
          borderRadius: "16px",
          boxShadow: "0 18px 42px rgba(0, 0, 0, 0.36)",
          fontWeight: 700
        },
        success: {
          iconTheme: {
            primary: "#22C55E",
            secondary: "#0B1220"
          }
        },
        error: {
          iconTheme: {
            primary: "#EF4444",
            secondary: "#0B1220"
          }
        },
        loading: {
          duration: Infinity,
          iconTheme: {
            primary: "#3B82F6",
            secondary: "#0B1220"
          }
        }
      }}
    />
    <App />
  </BrowserRouter>
);
