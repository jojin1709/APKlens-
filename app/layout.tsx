import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APKLens — Android APK Security & Architecture Suite",
  description: "Privacy-first static Android APK inspection, binary AXML decoding, and JADX source decompilation in your browser.",
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
    ],
    shortcut: "/icon.svg",
    apple: "/apple-icon.png",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}