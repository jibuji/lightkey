import React from "react";
import ReactDOM from "react-dom/client";
import { CordisHost } from "./host/CordisHost";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <CordisHost />
  </React.StrictMode>,
);
