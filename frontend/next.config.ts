import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://cve-backend:8000',
  },
  allowedDevOrigins: ['119.45.160.169', 'localhost','10.0.0.190','127.0.0.1'],
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://cve-backend:8000/api/:path*',
      },
    ];
  },
};

export default nextConfig;
