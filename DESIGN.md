# Design System

## Visual Theme

Dark cyberpunk security console, tuned for focused desktop use rather than spectacle. Near-black blue surfaces create depth; cyan identifies primary interaction, violet supports secondary actions, and a restrained pink/red is reserved for warnings.

## Colors

- Background: `#0B1020`
- Raised surface: `#111A2E`
- Field surface: `#0D1527`
- Border: `#263553`
- Primary cyan: `#35D5FF`
- Secondary violet: `#9D7AFF`
- Text: `#EDF4FF`
- Muted text: `#9AAAC5`
- Success: `#49E6A1`
- Warning: `#FF6B9A`

## Typography

Use the platform system sans-serif for all UI copy. Section titles are semibold; supporting labels use a smaller regular weight; console output uses Menlo or another platform monospace font.

## Components

- One consistent outlined field treatment with cyan focus state.
- Flat, rectangular action buttons with modest 8px-radius-equivalent geometry.
- Panel borders separate groups; no nested cards or decorative shadows.
- Primary button is cyan, secondary button is violet, disabled controls recede visibly.

## Layout

A compact fixed desktop canvas: title/status bar, two-column workspace, a wide live-activity panel, and an action footer. The primary configuration lives in the left column; scope and output options live in the right.
