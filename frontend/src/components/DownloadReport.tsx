import { Download } from 'lucide-react';
import { getReportUrl } from '../api';

interface DownloadReportProps {
  jobId: string;
}

export function DownloadReport({ jobId }: DownloadReportProps) {
  const handleDownload = () => {
    const url = getReportUrl(jobId);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vuln-report-${jobId.slice(0, 8)}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <button className="btn btn-secondary" onClick={handleDownload} id="download-report-btn" type="button">
      <Download size={15} />
      Download HTML Report
    </button>
  );
}
