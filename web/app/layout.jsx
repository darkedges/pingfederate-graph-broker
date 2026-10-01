import './globals.css';

export const metadata = {
  title: 'Broker Portal · Secure directory access',
  description: 'Manage Microsoft Graph connections and delegated read access through PingFederate.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
