import { LookupForm } from "@/components/lookup-form"
import { Header } from "@/components/header"

export default function Home() {
  return (
    <div className="bg-black text-white">
      <Header />
      <main className="container mx-auto px-4 py-8">
        <section className="max-w-4xl mx-auto mb-12 text-center">
          <h1 className="text-4xl font-bold mb-4 text-white">
            ThreatLens
          </h1>
          <p className="text-xl text-gray-400 mb-8">
            One-stop threat intelligence lookup for cybersecurity professionals
          </p>
          <LookupForm />
        </section>
      </main>
    </div>
  )
}
