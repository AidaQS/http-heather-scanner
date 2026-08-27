# 📱 HTTP Header Scanner

This repository contains the implementation of the HTTP header Scanner.

## 🎯 Assignment Goal

Develop a simple and intuitive desktop application capable of scan websites and analize thei HTTP security headers. The goal is to help users understand the security configuration of a website through a visual interface and a security score.

## ✅ Implemented Features

- HTTP/HTTPS URL scanning.
- HTTP status code detection.
- Automatic redirect handling.
- Security header analysis.
- Security score calculation.
- Detection of missing security headers.
- Display of detected header values.
- Connection timout protection.
- Background scanning to prevent the interface from freezing.
- Scan cancellation.
- URL input placeholder text.
- Clear URL and results button.
- Enter key support for sarting scans.
- Blue and intuitive graphical interface.
- Error handling for connection and SSL problems.


## 🚧 Known Issues

- Some websites may block automated HTTP requests.
- Some servers may return different headers depending on the client security configuration.
- A scan may fail when a website requires authentication.
- Some websites may use security systems, CDNs or WABs that interfere with the scan.
- The security score is only an indicator and does not represent a complete security audit.
- The application currently analizes a predefined set of security headers.
- Scan cancellation cannot alqays inmediately terminate an already stablished network connection.
- Some websites may take several seconds to respond beacuse of network or sever-side delays.

## 📝 Notes

- Tha application is intended for educational and security-awareness purposes.
- Only scan websites that you own or have explicit permision to test.
- The scanner focuses exclusively on HTTP response headers and does not perform active vulnerability explotation.
- Results may vary depending on the target server, CDN, WAF, network conditions or HTTP configuration.
- The security score should be used as a quick reference, not as a complete security assessment.
- The project was developed using Python and Tkinter.
- Not external HTTP library is required in the current version.

---

