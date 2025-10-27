# Missing Dependencies

The following packages are imported in source code but not installed:

## Chart.js Related
- `react-chartjs-2` - Used in:
  - `src/components/Dashboard.tsx`
  - `src/components/Statistics.tsx`
- `chart.js` - Peer dependency of react-chartjs-2

## Installation Command

```bash
npm install react-chartjs-2 chart.js
```

## Temporary Fix

For now, we need to either:
1. Install these dependencies
2. Comment out the chart components in Dashboard and Statistics
3. Create placeholder components without charts

**Current Status:** Choosing option 2 (comment out) to get build working first

