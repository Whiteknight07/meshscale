# Menu bar template icons

| Size | Connected | Disconnected |
| --- | --- | --- |
| 16pt | [SVG](meshscale-connected-16.svg) | [SVG](meshscale-disconnected-16.svg) |
| 18pt | [SVG](meshscale-connected-18.svg) | [SVG](meshscale-disconnected-18.svg) |

Three rounded nodes and an elbow link describe a small personal mesh. Disconnected opens the horizontal links; it remains distinguishable without color. The assets have transparent backgrounds and pure black strokes. Use the SVG as a mask/template, never as a fixed black image on a dark menu bar.

Native integration: rasterize at the target backing scale if the tray API requires PNG, preserve alpha, set the logical size to 16 or 18pt, and mark the NSImage as `isTemplate = true` (or the Wails equivalent). macOS applies the appropriate foreground for light/dark and highlighted menu bars. Do not bake a background, color, or shadow into the icon. Select disconnected for signed-out/error, connected only after the local connection is confirmed; the popover communicates connecting with text and a reduced-motion-aware progress indicator.
