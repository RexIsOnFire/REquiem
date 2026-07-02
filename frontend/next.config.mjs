/** @type {import('next').NextConfig} */
const API = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

const nextConfig = {
  reactStrictMode: true,
  // Proxy /api/* to the FastAPI backend so the browser never hits CORS and the
  // frontend needs no knowledge of the backend host at build time.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API}/:path*` }];
  },
};

export default nextConfig;
