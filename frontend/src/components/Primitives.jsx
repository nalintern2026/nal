export function SectionHeading({ title, subtitle, actions }) {
    return (
        <div className="section-shell">
            <div>
                <h2 className="section-title">{title}</h2>
                {subtitle ? <p className="section-subtitle">{subtitle}</p> : null}
            </div>
            {actions ? <div className="section-actions">{actions}</div> : null}
        </div>
    );
}

export function StatusBanner({ tone = 'info', children, action }) {
    return (
        <div className={`status-banner status-${tone}`}>
            <div className="status-text">{children}</div>
            {action ? <div>{action}</div> : null}
        </div>
    );
}

export function SurfacePanel({ className = '', children }) {
    return <section className={`surface-panel ${className}`.trim()}>{children}</section>;
}

export function TogglePills({ value, onChange, options }) {
    return (
        <div className="toggle-pills">
            {options.map((o) => (
                <button
                    key={o.value}
                    type="button"
                    onClick={() => onChange(o.value)}
                    className={`toggle-pill ${value === o.value ? 'active' : ''}`}
                >
                    {o.label}
                </button>
            ))}
        </div>
    );
}
