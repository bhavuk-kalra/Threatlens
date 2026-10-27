import Link from "next/link"
import { Focus } from "lucide-react"

export function Header() {
  return (
    <header className="h-[72px]">
      <div className="mx-auto flex h-full w-full max-w-[960px] items-center justify-between px-5 sm:px-8 lg:px-12">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-text focus-visible:rounded-sm"
          aria-label="ThreatLens home"
        >
          <Focus aria-hidden="true" className="h-[18px] w-[18px] shrink-0 text-action" strokeWidth={1.8} />
          <span className="text-[17px] font-semibold tracking-[-0.035em]">threatlens.</span>
        </Link>
        <span className="hidden text-[12px] tracking-[0.01em] text-text-muted sm:block">
          Independent threat research
        </span>
      </div>
    </header>
  )
}
