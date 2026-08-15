import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "LinkSecure | Enterprise Security",
  description: "Enterprise-grade malicious link and phishing detection.",
  // Isotipo de brakescode: LinkSecure se presenta desde el sitio del
  // estudio, así que la pestaña lo identifica como parte de esa familia.
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="dark">
      <body className={`${inter.className} min-h-screen antialiased`}>
        {children}
      </body>
    </html>
  );
}
