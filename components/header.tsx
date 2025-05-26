import Link from "next/link"
import { Shield } from "lucide-react"

export function Header() {
  return (
    <header>
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Link href="/" className="flex items-center space-x-2">
          <Shield className="h-6 w-6 text-white" />
          <span className="font-bold text-xl">ThreatLens</span>
        </Link>
        <div className="flex items-center space-x-4">
        </div>
      </div>
    </header>
  )
}
