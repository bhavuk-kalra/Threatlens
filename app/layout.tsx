import type React from "react"
import type { Metadata } from "next"
import localFont from "next/font/local"
import "./globals.css"
import { Footer } from "@/components/footer"

const instrumentSans = localFont({
  src: "./fonts/instrument-sans-latin.woff2",
  variable: "--font-instrument-sans",
  weight: "400 600",
  style: "normal",
  display: "swap",
})

const ibmPlexMono = localFont({
  src: "./fonts/ibm-plex-mono-latin.woff2",
  variable: "--font-ibm-plex-mono",
  weight: "400",
  style: "normal",
  display: "swap",
})

export const metadata: Metadata = {
  title: "ThreatLens — Personal Threat Intelligence Research",
  description: "A personal research tool for reviewing threat intelligence source evidence and context."
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${instrumentSans.variable} ${ibmPlexMono.variable}`}>
      <body className="font-sans">
        <div className="flex flex-col min-h-screen">
          <main className="flex-grow">{children}</main>
          <Footer />
        </div>
      </body>
    </html>
  )
}
