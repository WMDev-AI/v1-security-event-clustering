'use client';

import { useState, useRef } from 'react';
import { uploadEventLog, FileUploadResponse } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface EventLogUploadProps {
  onEventsLoaded?: (events: string[], filename: string) => void;
}

export function EventLogUpload({ onEventsLoaded }: EventLogUploadProps) {
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<FileUploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError(null);
    setUploadResult(null);

    try {
      const result = await uploadEventLog(file);
      setUploadResult(result);
      
      if (onEventsLoaded) {
        onEventsLoaded(result.events, result.filename);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const files = e.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    setUploading(true);
    setError(null);
    setUploadResult(null);

    try {
      const result = await uploadEventLog(file);
      setUploadResult(result);
      
      if (onEventsLoaded) {
        onEventsLoaded(result.events, result.filename);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <Card className="w-full p-6 space-y-4">
      <div className="space-y-2">
        <h3 className="text-lg font-semibold">Upload Event Log File</h3>
        <p className="text-sm text-gray-600">
          Upload security event logs in TXT, CSV, or JSON format
        </p>
      </div>

      <Tabs defaultValue="upload" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="upload">Upload File</TabsTrigger>
          <TabsTrigger value="info">Supported Formats</TabsTrigger>
        </TabsList>

        <TabsContent value="upload" className="space-y-4">
          {/* Drag and Drop Area */}
          <div
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-500 transition-colors cursor-pointer"
          >
            <div className="space-y-2">
              <svg
                className="mx-auto h-12 w-12 text-gray-400"
                stroke="currentColor"
                fill="none"
                viewBox="0 0 48 48"
              >
                <path
                  d="M28 8H12a4 4 0 00-4 4v20a4 4 0 004 4h24a4 4 0 004-4V20m-18-12v12m0 0l4-4m-4 4l-4-4"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <div>
                <p className="font-medium text-gray-900">
                  Drag and drop your file here
                </p>
                <p className="text-sm text-gray-600">or click to browse</p>
              </div>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileSelect}
              disabled={uploading}
              accept=".txt,.csv,.json"
              className="hidden"
              onClick={(e) => {
                (e.target as HTMLInputElement).click();
              }}
              onClickCapture={(e) => {
                // Allow click through
              }}
            />
            <Button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              variant="outline"
              className="mt-4"
            >
              {uploading ? 'Uploading...' : 'Select File'}
            </Button>
          </div>

          {/* Error Alert */}
          {error && (
            <div className="border border-red-200 bg-red-50 rounded-lg p-4">
              <p className="text-sm font-medium text-red-900">{error}</p>
            </div>
          )}

          {/* Upload Result */}
          {uploadResult && (
            <div className="space-y-3 border rounded-lg p-4 bg-green-50 border-green-200">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-green-600" />
                <p className="font-medium text-green-900">Upload Successful</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-600">Filename</p>
                  <p className="font-medium text-gray-900">{uploadResult.filename}</p>
                </div>
                <div>
                  <p className="text-gray-600">Total Events</p>
                  <p className="font-medium text-gray-900">{uploadResult.total_events}</p>
                </div>
                <div>
                  <p className="text-gray-600">Format Detected</p>
                  <p className="font-medium text-gray-900">{uploadResult.format_detected}</p>
                </div>
              </div>

              {uploadResult.sample_events.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-sm font-medium text-gray-700">Sample Events:</p>
                  <div className="space-y-1">
                    {uploadResult.sample_events.slice(0, 3).map((event, i) => (
                      <div
                        key={i}
                        className="text-xs bg-white p-2 rounded border border-gray-200 text-gray-700 truncate"
                        title={event}
                      >
                        {event}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {uploadResult.errors.length > 0 && (
                <div className="border border-yellow-200 bg-yellow-50 rounded-lg p-4 mt-3">
                  <p className="font-medium text-sm text-yellow-900">There were some warnings:</p>
                  <ul className="list-disc list-inside mt-2 text-sm text-yellow-800">
                    {uploadResult.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="info" className="space-y-4">
          <div className="space-y-4">
            <div className="space-y-2">
              <h4 className="font-medium">Text Format (.txt)</h4>
              <p className="text-sm text-gray-600">One event per line</p>
              <div className="bg-gray-50 p-3 rounded text-xs font-mono text-gray-700">
                "timestamp"="2024-01-15 08:30:00" "subsys"="firewall" "proto"="HTTPS" "srcip"="192.168.1.100" "dstip"="10.0.0.50" "srcport"="51555" "dstport"="443" "rule"="site_unreachable" "action"="pass" "count"="8" "len"="512" "ttl"="64" "tos"="0" "initf"="eth0" "outitf"="eth1"
                <br />
                "timestamp"="2024-01-15 08:31:00" "subsys"="ips" "proto"="TCP" "srcip"="203.0.113.50" "dstip"="10.0.0.1" "srcport"="44221" "dstport"="22" "rule"="shellcode_error" "action"="block" "groupid"="1201" "reason"="shellcode_error" "alertcount"="12" "dropcount"="12"
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">CSV Format (.csv)</h4>
              <p className="text-sm text-gray-600">First row as headers, each row as an event</p>
              <div className="bg-gray-50 p-3 rounded text-xs font-mono text-gray-700">
                timestamp,subsys,proto,srcip,dstip,srcport,dstport,rule,action,count,len,ttl,tos,initf,outitf
                <br />
                2024-01-15 08:30:00,firewall,HTTPS,192.168.1.100,10.0.0.50,51555,443,site_unreachable,pass,8,512,64,0,eth0,eth1
                <br />
                2024-01-15 08:31:00,ips,TCP,203.0.113.50,10.0.0.1,44221,22,shellcode_error,block,12,,,,,
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">JSON Format (.json)</h4>
              <p className="text-sm text-gray-600">Array of objects or JSONL (one JSON per line)</p>
              <div className="bg-gray-50 p-3 rounded text-xs font-mono text-gray-700">
                [
                <br />
                &nbsp;&nbsp;{'{'}timestamp: "2024-01-15 08:30:00", subsys: "waf", srcip: "198.51.100.25", dstip: "10.0.0.80", rule: "bannedextension", action: "block", reason: "banned extension", client: "198.51.100.25", server: "10.0.0.80", vhost: "10.0.0.80:80", count: 3{'}'}
                <br />
                ]
              </div>
            </div>

            <div className="border border-blue-200 bg-blue-50 rounded-lg p-4">
              <p className="text-sm text-blue-900">
                <strong>Note:</strong> Uploaded files are processed immediately and parsed 
                into a standardized format. The maximum file size is typically limited by your 
                server configuration. Very large files may take longer to process.
              </p>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </Card>
  );
}
