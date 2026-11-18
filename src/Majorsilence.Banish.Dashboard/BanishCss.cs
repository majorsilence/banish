namespace Majorsilence.Banish.Dashboard;

/// <summary>
/// The dashboard stylesheet, inlined into the page so nothing depends on static-asset hosting.
/// Colors are the reference data-viz palette: one series hue (blue), recessive hairline grid,
/// text always in ink tokens, status colors only ever paired with an icon and a label.
/// </summary>
public static class BanishCss
{
    public const string Text = """
        :root, .banish {
          color-scheme: light;
          --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #6f6d68;
          --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10); --series-1: #2a78d6; --accent: #1c5cab;
          --good: #0ca30c; --good-text: #006300; --warning: #fab219; --critical: #d03b3b; --critical-text: #b02a2a;
          --wash: rgba(11,11,11,0.05);
        }
        @media (prefers-color-scheme: dark) {
          :root:where(:not([data-theme="light"])), :root:where(:not([data-theme="light"])) .banish {
            color-scheme: dark;
            --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #a09e97;
            --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10); --series-1: #3987e5; --accent: #6da7ec;
            --good-text: #0ca30c; --critical-text: #ec6b6b; --wash: rgba(255,255,255,0.07);
          }
        }
        :root[data-theme="dark"], :root[data-theme="dark"] .banish {
          color-scheme: dark;
          --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #a09e97;
          --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10); --series-1: #3987e5; --accent: #6da7ec;
          --good-text: #0ca30c; --critical-text: #ec6b6b; --wash: rgba(255,255,255,0.07);
        }
        * { box-sizing: border-box; }
        html, body { margin: 0; background: var(--page); color: var(--ink); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
        a { color: var(--accent); }
        h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 1rem; }
        h2 { font-size: 1rem; font-weight: 600; margin: 0 0 .75rem; }
        .muted { color: var(--muted); }
        .banish { min-height: 100vh; }
        .top { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem 1.5rem; padding: .75rem 16px; background: var(--surface); border-bottom: 1px solid var(--grid); }
        .brand { font-weight: 700; font-size: 1.1rem; color: var(--ink); text-decoration: none; letter-spacing: .02em; }
        .top nav { display: flex; flex-wrap: wrap; gap: .25rem; flex: 1; }
        .top nav a { color: var(--ink-2); text-decoration: none; padding: .3rem .65rem; border-radius: 8px; }
        .top nav a:hover { background: var(--wash); }
        .top nav a.active { color: var(--ink); background: var(--wash); font-weight: 600; }
        .who { display: flex; align-items: center; gap: .75rem; color: var(--ink-2); }
        .who form { margin: 0; }
        main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
        footer { max-width: 1100px; margin: 0 auto; padding: 0 16px 24px; color: var(--muted); font-size: .85rem; }
        .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
        .tile, .card { background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 16px; }
        .tile-label { color: var(--ink-2); font-size: .85rem; }
        .tile-value { font-size: 2rem; font-weight: 600; line-height: 1.2; margin-top: 2px; }
        .tile-sub { color: var(--muted); font-size: .8rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 16px; }
        .wide { grid-column: 1 / -1; }
        .chart { margin: 0; }
        .chart svg { width: 100%; height: auto; display: block; }
        .chart .grid-line { stroke: var(--grid); stroke-width: 1; }
        .chart .axis-line { stroke: var(--axis); stroke-width: 1; }
        .chart .tick, .chart .xlabel { fill: var(--muted); font-size: 11px; }
        .chart .vlabel { fill: var(--ink); font-size: 12px; font-weight: 600; }
        .chart .col { fill: var(--series-1); }
        .chart .col:hover { fill: var(--accent); }
        .chart .hit { fill: transparent; }
        .tableview { margin-top: 8px; color: var(--ink-2); font-size: .85rem; }
        .tableview summary { cursor: pointer; }
        .barlist { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
        .barlist li { display: grid; grid-template-columns: minmax(80px, 38%) 1fr auto; align-items: center; gap: 10px; }
        .bl-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); }
        .bl-track { height: 10px; }
        .bl-bar { display: block; height: 10px; min-width: 2px; background: var(--series-1); border-radius: 0 4px 4px 0; }
        .bl-value { color: var(--ink-2); font-variant-numeric: tabular-nums; }
        table { border-collapse: collapse; width: 100%; font-size: .9rem; }
        th { text-align: left; color: var(--ink-2); font-weight: 600; border-bottom: 1px solid var(--axis); padding: 6px 10px 6px 0; white-space: nowrap; }
        td { border-bottom: 1px solid var(--grid); padding: 6px 10px 6px 0; vertical-align: top; font-variant-numeric: tabular-nums; }
        td.addr { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        .scroll { overflow-x: auto; }
        .status { display: inline-flex; align-items: center; gap: 6px; }
        .status .icon { font-size: .8rem; line-height: 1; }
        .status.good .icon { color: var(--good); }
        .status.warn .icon { color: var(--warning); }
        .status.bad .icon { color: var(--critical); }
        form.row, .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }
        label { display: grid; gap: 2px; font-size: .8rem; color: var(--ink-2); }
        input, select, button { font: inherit; color: var(--ink); background: var(--surface); border: 1px solid var(--axis); border-radius: 8px; padding: 6px 10px; }
        input:focus-visible, select:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
        input[type=checkbox] { width: 1rem; height: 1rem; padding: 0; }
        label.check { display: flex; align-items: center; gap: 6px; font-size: .9rem; }
        button { cursor: pointer; }
        button:hover { background: var(--wash); }
        button.primary { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
        button.primary:hover { filter: brightness(1.1); }
        button.danger { border-color: var(--critical); color: var(--critical-text); }
        button.link { background: none; border: none; color: var(--accent); padding: 0; }
        .notice { padding: 8px 12px; border-radius: 8px; margin-bottom: 12px; border: 1px solid var(--ring); background: var(--wash); }
        .notice.error { border-color: var(--critical); }
        .pager { display: flex; gap: 8px; align-items: center; margin-top: 12px; color: var(--ink-2); }
        .login { max-width: 360px; margin: 8vh auto 0; }
        .login form { display: grid; gap: 12px; }
        .kind { display: inline-block; padding: 0 8px; border-radius: 999px; border: 1px solid var(--axis); font-size: .8rem; }
        @media (max-width: 560px) { .barlist li { grid-template-columns: 1fr auto; } .bl-track { grid-column: 1 / -1; grid-row: 2; } }
        """;
}
