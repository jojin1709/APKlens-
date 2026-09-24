import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APKLens — Android APK Analyzer",
  description: "Privacy-first static Android APK inspection in your browser."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}