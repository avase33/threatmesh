import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "threatmesh · real-time SIEM",
  description: "Autonomous log forensics & threat intel across a Go / Rust / Python / TypeScript mesh.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
