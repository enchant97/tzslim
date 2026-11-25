# TZslim
Compact timezone database format, designed for easy access to the latest offsets.

> [!CAUTION]
> Experimental and currently VIBE-CODED with NO developer checks

## Goal
- Allow for applications/embedded devices to download the latest relevant timestamp information
- No legacy zones
- Smaller memory footprint required
- Only store latest available timezone data; plus a reasonable number of future transitions
- Be easy to pass & validate when stale
- Be cacheable and hostable on CDNs/S3 via a static-site
- Integrity checking built-in via content hash with cryptographic signature, allowing for a device to request over unencrypted HTTP

## License
This project is Copyright (c) 2026 Leo Spratt, licences shown below:

    Apache-2.0. Full license found in `LICENSE.txt`
