import type { ReactNode } from "react";

export default function Panel({ id, title, icon, children, aside }: { id?: string; title: string; icon?: ReactNode; children: ReactNode; aside?: ReactNode }) {
  return (
    <section id={id} className="rounded-lg border border-edge bg-panel/80 p-4 shadow-[0_0_0_1px_rgba(6,182,212,0.04)] backdrop-blur sm:p-5">
      <header className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.14em] text-radar">
          {icon}
          {title}
        </h2>
        {aside}
      </header>
      {children}
    </section>
  );
}
