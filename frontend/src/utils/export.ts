import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import Papa from 'papaparse';

/**
 * Export data to CSV format
 */
export function exportToCSV(data: any[], filename: string = 'export.csv') {
  const csv = Papa.unparse(data);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, filename);
}

/**
 * Export data to PDF format with table
 */
export function exportToPDF(
  data: any[],
  columns: { header: string; dataKey: string }[],
  filename: string = 'export.pdf',
  title?: string
) {
  const doc = new jsPDF();

  // Add title if provided
  if (title) {
    doc.setFontSize(18);
    doc.text(title, 14, 22);
  }

  // Add table
  autoTable(doc, {
    startY: title ? 30 : 20,
    head: [columns.map(col => col.header)],
    body: data.map(row => columns.map(col => row[col.dataKey] || '')),
    theme: 'grid',
    headStyles: {
      fillColor: [6, 182, 212], // Cyan-500
      textColor: [255, 255, 255],
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [249, 250, 251],
    },
    margin: { top: 30 },
  });

  doc.save(filename);
}

/**
 * Export data to JSON format
 */
export function exportToJSON(data: any[], filename: string = 'export.json') {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  downloadBlob(blob, filename);
}

/**
 * Download blob as file
 */
function downloadBlob(blob: Blob, filename: string) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Export component for easy integration
 */
export interface ExportButtonProps {
  data: any[];
  columns?: { header: string; dataKey: string }[];
  filename?: string;
  title?: string;
  format: 'csv' | 'pdf' | 'json';
}

export function exportData({
  data,
  columns,
  filename,
  title,
  format,
}: ExportButtonProps) {
  const timestamp = new Date().toISOString().split('T')[0];
  const defaultFilename = `export-${timestamp}`;

  switch (format) {
    case 'csv':
      exportToCSV(data, filename || `${defaultFilename}.csv`);
      break;
    case 'pdf':
      if (!columns) {
        throw new Error('Columns are required for PDF export');
      }
      exportToPDF(data, columns, filename || `${defaultFilename}.pdf`, title);
      break;
    case 'json':
      exportToJSON(data, filename || `${defaultFilename}.json`);
      break;
    default:
      throw new Error(`Unsupported export format: ${format}`);
  }
}

