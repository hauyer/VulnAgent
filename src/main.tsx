import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.js";
import { LanguageProvider } from "./i18n.js";
import "./index.css";

const rootElement = document.getElementById("root");
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <LanguageProvider>
        <App />
      </LanguageProvider>
    </React.StrictMode>
  );
}
