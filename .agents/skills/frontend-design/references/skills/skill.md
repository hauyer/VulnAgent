---
name: frontend-design
description: Create distinctive, production-grade frontend interfaces with high visual quality and systematic design tokens. Trigger this whenever building web components, landing pages, dashboards, React/Vue/HTML layouts, or refactoring UI to eliminate generic AI aesthetics.
---

# Frontend Design Directive

Act as an elite design engineer. When authoring or modifying interfaces, enforce the following standards without exception:

## 1. Eliminate Generic AI Aesthetics ("AI Slop")
- **Forbidden Clichés**: Avoid default centered hero sections featuring generic indigo/purple mesh gradients, floating 3D spheres, or unmotivated 3-column card grids.
- **Functional Semantics**: Badges, status dots, numbers, and divider lines must represent verifiable state or chronological logic—never use them as purely decorative fill.
- **Authentic Content**: Avoid placeholder buzzwords like "Next-Gen Intelligent Platform". Use realistic, domain-grounded copywriting and authentic data shapes.

## 2. Token Compliance & Color Strictness
- **Semantic Tokens Only**: Strictly employ CSS variable tokens defined in `references/design-tokens.md`. Use `bg-background`, `text-foreground`, `bg-card`, `text-muted-foreground`, `border-border`, and `ring-ring`.
- **Zero Arbitrary Colors**: Do NOT write raw hex values (e.g., `bg-[#1a1a1a]`) or untokenized Tailwind base colors (e.g., `bg-purple-600`, `text-blue-500`) unless explicitly instructed by the user.
- **Dark Mode Native**: Every surface must support seamless contrast transitions between light and dark modes via semantic classes.

## 3. Typography & Visual Hierarchy
- **Font Pairing**: Pair a distinctive display/heading font with a clean neutral body font (e.g., Inter, Geist, or system stack).
- **Type Scale**: Enforce strict typographic progression (e.g., 12/14/16/20/24/32/48px). Headings use tight line height (`leading-tight` or `leading-snug`); body text uses comfortable reading height (`leading-relaxed`).
- **Contrast**: Establish scanning hierarchy through text contrast tiers (`text-foreground` -> `text-muted-foreground`) rather than multiple distinct colors.

## 4. Depth, Borders & Elevation
- **Border-First Architecture**: Define layout boundaries with subtle 1px border strokes (`border-border`) rather than heavy box shadows.
- **Restrained Shadows**: Confine shadows to floating elements (modals, dropdown menus, popovers) using diffused, multi-layered elevation (`shadow-subtle` or `shadow-surface`).

## 5. Interactions & Motion
- **State Completeness**: Every interactive element must define distinct `:hover`, `:focus-visible`, and `:active` states.
- **Snappy Motion**: Transitions must serve spatial context and remain under 200ms with ease-out timing curves (`transition-all duration-150 ease-out`).