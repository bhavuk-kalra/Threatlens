import { Header } from "@/components/header"
import { LookupForm } from "@/components/lookup-form"

export default function Home() {
  return (
    <div className="min-h-full">
      <Header />
      <div className="mx-auto w-full max-w-[960px] px-5 pb-16 pt-8 sm:px-8 sm:pt-10 lg:px-12 lg:pt-12">
        <LookupForm />
      </div>
    </div>
  )
}
