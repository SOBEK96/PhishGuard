import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard SOC Console",
  description:
    "Decentralized Web3 anti-phishing & drainer triage oracle on GenLayer: 3-host threat-intel quorum, staked reporters, on-chain firewall.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
