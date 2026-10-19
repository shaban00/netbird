import React from "react";
import Toaster from "@components/Toast";
import Topbar from "@components/Topbar";
import "./globals.css";

export const metadata = {
  title: "NetBird SSH Session Recordings",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Topbar />
        {children}
        <Toaster />
      </body>
    </html>
  );
}
