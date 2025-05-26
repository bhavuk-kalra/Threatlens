import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { UIFixes } from "@/components/ui-fixes"
import { Footer } from "@/components/footer" // Added Footer import

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "ThreatLens - Threat Intelligence Lookup",
  description: "One-stop threat intelligence lookup for cybersecurity professionals"
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <body className={inter.className}>
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} disableTransitionOnChange>
          <UIFixes />
          <div className="flex flex-col min-h-screen">
            <main className="flex-grow">{children}</main>
            <Footer /> {/* Added Footer component */}
          </div>
        </ThemeProvider>
      </body>
    </html>
  )
}
