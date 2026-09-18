import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LLM-SEC Prototype",
  description: "Demo -- static sample data; no backend connected",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}