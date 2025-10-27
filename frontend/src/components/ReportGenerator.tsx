import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { useAuth } from '../hooks/useAuth';

export const ReportGenerator: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [newReportForm, setNewReportForm] = useState({
    name: '',
    description: '',
    template: 'standard',
    includeExecutiveSummary: true,
    includeTechnicalDetails: true,
    includeRecommendations: true,
    format: 'pdf'
  });
  const [isGenerating, setIsGenerating] = useState(false);

  const { user } = useAuth();

  useEffect(() => {
    // Load existing reports
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      const response = await fetch('/api/v2/reports', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setReports(data);
      }
    } catch (error) {
      console.error('Failed to load reports:', error);
    }
  };

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsGenerating(true);
    try {
      const response = await fetch('/api/v2/reports/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(newReportForm)
      });

      if (response.ok) {
        const newReport = await response.json();
        setReports([newReport, ...reports]);
        setNewReportForm({
          name: '',
          description: '',
          template: 'standard',
          includeExecutiveSummary: true,
          includeTechnicalDetails: true,
          includeRecommendations: true,
          format: 'pdf'
        });
        alert('Report generated successfully!');
      } else {
        alert('Failed to generate report');
      }
    } catch (error) {
      console.error('Generate report error:', error);
      alert('Error generating report');
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadReport = async (reportId: string, format: string) => {
    try {
      const response = await fetch(`/api/v2/reports/${reportId}/download`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `report-${reportId}.${format}`;
        link.click();
        window.URL.revokeObjectURL(url);
      } else {
        alert('Failed to download report');
      }
    } catch (error) {
      console.error('Download report error:', error);
      alert('Error downloading report');
    }
  };

  const deleteReport = async (reportId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return;

    try {
      const response = await fetch(`/api/v2/reports/${reportId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        setReports(reports.filter(report => report.id !== reportId));
        alert('Report deleted successfully');
      } else {
        alert('Failed to delete report');
      }
    } catch (error) {
      console.error('Delete report error:', error);
      alert('Error deleting report');
    }
  };

  return (
    <Card className="w-full">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Report Management</CardTitle>
        <Dialog>
          <DialogTrigger asChild>
            <Button>Generate New Report</Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Generate New Report</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleGenerateReport} className="space-y-4 py-4">
              <div>
                <Label htmlFor="report-name">Report Name</Label>
                <Input
                  id="report-name"
                  required
                  value={newReportForm.name}
                  onChange={(e) => setNewReportForm({ ...newReportForm, name: e.target.value })}
                  placeholder="Enter report name"
                />
              </div>
              <div>
                <Label htmlFor="report-description">Description</Label>
                <Input
                  id="report-description"
                  value={newReportForm.description}
                  onChange={(e) => setNewReportForm({ ...newReportForm, description: e.target.value })}
                  placeholder="Brief description of the report"
                />
              </div>
              <div>
                <Label>Template</Label>
                <select
                  value={newReportForm.template}
                  onChange={(e) => setNewReportForm({ ...newReportForm, template: e.target.value })}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="standard">Standard Security Report</option>
                  <option value="executive">Executive Summary</option>
                  <option value="technical">Technical Deep Dive</option>
                  <option value="compliance">Compliance Report</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Include Sections:</Label>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="executive-summary"
                    checked={newReportForm.includeExecutiveSummary}
                    onChange={(e) => setNewReportForm({ ...newReportForm, includeExecutiveSummary: e.target.checked })}
                  />
                  <Label htmlFor="executive-summary">Executive Summary</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="technical-details"
                    checked={newReportForm.includeTechnicalDetails}
                    onChange={(e) => setNewReportForm({ ...newReportForm, includeTechnicalDetails: e.target.checked })}
                  />
                  <Label htmlFor="technical-details">Technical Details</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="recommendations"
                    checked={newReportForm.includeRecommendations}
                    onChange={(e) => setNewReportForm({ ...newReportForm, includeRecommendations: e.target.checked })}
                  />
                  <Label htmlFor="recommendations">Recommendations</Label>
                </div>
              </div>
              <div>
                <Label>Format</Label>
                <select
                  value={newReportForm.format}
                  onChange={(e) => setNewReportForm({ ...newReportForm, format: e.target.value })}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="pdf">PDF</option>
                  <option value="html">HTML</option>
                  <option value="docx">Word Document</option>
                  <option value="json">JSON</option>
                </select>
              </div>
              <Button type="submit" className="w-full" disabled={isGenerating}>
                {isGenerating ? 'Generating...' : 'Generate Report'}
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Template</TableHead>
              <TableHead>Generated</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Format</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports.map((report) => (
              <TableRow key={report.id}>
                <TableCell className="font-medium">{report.name}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{report.template}</Badge>
                </TableCell>
                <TableCell>{new Date(report.createdAt).toLocaleDateString()}</TableCell>
                <TableCell>
                  <Badge className={
                    report.status === 'completed' ? 'bg-green-500' :
                    report.status === 'failed' ? 'bg-red-500' : 'bg-yellow-500'
                  }>
                    {report.status}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{report.format}</Badge>
                </TableCell>
                <TableCell>
                  <div className="flex space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => downloadReport(report.id, report.format)}
                      disabled={report.status !== 'completed'}
                    >
                      Download
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteReport(report.id)}
                      disabled={report.status === 'generating'}
                    >
                      Delete
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>

        {reports.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            <p>No reports generated yet.</p>
            <p className="text-sm">Generate your first report to get started.</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ReportGenerator;