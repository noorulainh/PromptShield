import { AppSidebar } from "@/components/app-sidebar";
import { TopStrip } from "@/components/top-strip";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen lg:flex">
      <AppSidebar />
      <main className="mx-auto w-full max-w-[1400px] px-4 py-5 md:px-6 lg:px-8">
        <TopStrip />
        {children}
      </main>
    </div>
  );
}
