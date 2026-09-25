import type { Metadata, Viewport } from "next";
import "./globals.css";
import "./atomic-landing.css";

export const viewport: Viewport = {
  themeColor: "#08080a",
};

export const metadata: Metadata = {
  title: "APKLens — Android APK Security & Architecture Suite",
  description: "Privacy-first static Android APK inspection, binary AXML decoding, and JADX source decompilation in your browser.",
  manifest: "/manifest.json",
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
      <head>
        <link rel="manifest" href="/manifest.json" />
      </head>
      <body>
        {children}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              // Auto-recover from Next.js ChunkLoadError after new deployments
              window.addEventListener('error', function(event) {
                var msg = (event && (event.message || (event.error && event.error.message))) || '';
                if (msg.indexOf('ChunkLoadError') !== -1 || msg.indexOf('Loading chunk') !== -1) {
                  var key = 'apklens_chunk_reload_ts';
                  var last = sessionStorage.getItem(key);
                  var now = Date.now();
                  if (!last || now - parseInt(last, 10) > 8000) {
                    sessionStorage.setItem(key, now.toString());
                    if ('caches' in window) {
                      caches.keys().then(function(names) {
                        for (var i = 0; i < names.length; i++) caches.delete(names[i]);
                      });
                    }
                    window.location.reload();
                  }
                }
              });

              if ('serviceWorker' in navigator && window.location.protocol === 'https:') {
                window.addEventListener('load', function() {
                  navigator.serviceWorker.register('/sw.js').then(function(reg) {
                    reg.update();
                  }).catch(function() {});
                });
              }
            `,
          }}
        />
      </body>
    </html>
  );
}