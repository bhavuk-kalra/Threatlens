import { Shield, Linkedin, Mail } from "lucide-react"

export function Footer() {
  return (
    <footer className="border-t border-gray-900 py-6">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row items-center justify-between">
          <div className="flex items-center space-x-2 mb-4 md:mb-0">
            <Shield className="h-5 w-5 text-white" />
            <span className="font-semibold">ThreatLens</span>
          </div>
          <div className="text-sm text-gray-500 mb-4 md:mb-0">
            For cybersecurity professionals, SOC analysts, and developers
          </div>
          <div className="flex items-center space-x-3 text-sm text-gray-400">
            <span>Contact -</span>
            <a
              href="https://www.linkedin.com/in/bhavuk-kalra"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Bhavuk Kalra's LinkedIn Profile"
              className="hover:text-white transition-colors"
            >
              <Linkedin size={18} />
            </a>
            <a
              href="mailto:bhavukinfosec@gmail.com"
              aria-label="Email Bhavuk Kalra"
              className="hover:text-white transition-colors"
            >
              <Mail size={18} />
            </a>
          </div>
        </div>
      </div>
    </footer>
  )
}
