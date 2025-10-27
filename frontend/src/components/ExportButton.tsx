import { useState } from 'react';
import { Download, FileText, File, FileJson } from 'lucide-react';
import { exportData, ExportButtonProps } from '../utils/export';

interface ExportButtonComponentProps extends Omit<ExportButtonProps, 'format'> {
  formats?: ('csv' | 'pdf' | 'json')[];
}

export default function ExportButton({
  data,
  columns,
  filename,
  title,
  formats = ['csv', 'pdf', 'json'],
}: ExportButtonComponentProps) {
  const [showMenu, setShowMenu] = useState(false);

  const handleExport = (format: 'csv' | 'pdf' | 'json') => {
    try {
      exportData({ data, columns, filename, title, format });
      setShowMenu(false);
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please try again.');
    }
  };

  const formatIcons = {
    csv: <FileText className="w-4 h-4" />,
    pdf: <File className="w-4 h-4" />,
    json: <FileJson className="w-4 h-4" />,
  };

  const formatLabels = {
    csv: 'Export as CSV',
    pdf: 'Export as PDF',
    json: 'Export as JSON',
  };

  return (
    <div className="relative">
      <button
        onClick={() => setShowMenu(!showMenu)}
        className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors"
      >
        <Download className="w-4 h-4" />
        <span>Export</span>
      </button>

      {showMenu && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setShowMenu(false)}
          />
          <div className="absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-xl border border-gray-700 z-20">
            {formats.map((format) => (
              <button
                key={format}
                onClick={() => handleExport(format)}
                className="w-full flex items-center gap-3 px-4 py-3 text-sm text-gray-300 hover:bg-gray-700 transition-colors first:rounded-t-lg last:rounded-b-lg"
              >
                {formatIcons[format]}
                <span>{formatLabels[format]}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

