import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "LinkSecure | Enterprise Security",
  description: "Enterprise-grade malicious link and phishing detection.",
  // El isotipo de brakescode va como `app/icon.svg`: esa convención de
  // archivo de Next tiene prioridad sobre `icons` en metadata, así que
  // declararlo acá además sería ruido que no se aplica.
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
