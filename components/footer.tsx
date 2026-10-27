import { Linkedin, Mail } from "lucide-react"

export function Footer() {
  return (
    <footer className="mx-auto w-full max-w-[960px] px-5 sm:px-8 lg:px-12">
      <div className="flex flex-col gap-3 border-t border-border py-5 text-xs text-text-muted sm:flex-row sm:items-center sm:justify-between">
        <p>Evidence before conclusions.</p>
        <nav aria-label="Contact" className="flex items-center gap-4">
          <a
            href="https://www.linkedin.com/in/bhavuk-kalra"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Bhavuk Kalra on LinkedIn"
            className="inline-flex min-h-9 items-center gap-1.5 rounded-sm hover:text-action"
          >
            <Linkedin aria-hidden="true" size={14} />
            <span>LinkedIn</span>
          </a>
          <a
            href="mailto:bhavukinfosec@gmail.com"
            aria-label="Email Bhavuk Kalra"
            className="inline-flex min-h-9 items-center gap-1.5 rounded-sm hover:text-action"
          >
            <Mail aria-hidden="true" size={14} />
            <span>Email</span>
          </a>
        </nav>
      </div>
    </footer>
  )
}
