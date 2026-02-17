const apiBase = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

const App = (): JSX.Element => {
  return (
    <main className="layout">
      <header className="hero">
        <p className="eyebrow">Security-First Fullstack Template</p>
        <h1>Template restored and ready</h1>
        <p>
          This starter includes React, nginx edge routing, Node domain services, PostgreSQL migrations,
          authentication scaffolding, RBAC checks, and audit trail fundamentals.
        </p>
      </header>

      <section className="card-grid">
        <article className="card">
          <h2>Edge</h2>
          <p>Single nginx entrypoint with TLS termination and route ownership by service domain.</p>
        </article>

        <article className="card">
          <h2>Identity</h2>
          <p>JWT access, refresh rotation, lockout controls, and optional TOTP MFA workflows.</p>
        </article>

        <article className="card">
          <h2>Operations</h2>
          <p>Health endpoints, idempotent migrations with advisory lock, and audit logging hooks.</p>
        </article>
      </section>

      <footer className="footer">
        <span>API base: {apiBase}</span>
      </footer>
    </main>
  );
};

export default App;
