# MEV Shell Finder

A PHP script that scans your server's directory for potentially malicious code in PHP files and displays the results in a well-formatted HTML table.

## Features

- Recursively scans the current directory and subdirectories for PHP files
- Detects three types of suspicious code:
  - **Suspicious PHP Functions**: `shell_exec`, `eval`, `base64_decode`, `exec`, `system`, `passthru`, `popen`, `proc_open`, `assert`, and `gzuncompress`
  - **Encoded/Obfuscated Files**: Patterns like `eval(`, `base64_decode`, `gzinflate`, `gzuncompress`, `str_rot13`, `urldecode`, and `assert(`
  - **Reverse Shell**: Patterns like `php...system(`, `php...exec(`, `php...shell_exec(`, `php...popen(`, and `php...proc_open(`
- Displays results in a clean, modern UI built with TailwindCSS and DaisyUI
- Interactive features including:
  - Detailed view modal for each suspicious code finding
  - Color-coded badges for different types of issues
  - Responsive design that works on mobile and desktop
- Provides a summary of the scan including execution time and number of files scanned
- **Robust self-exclusion**: Uses multiple methods to ensure the script doesn't scan itself, preventing false positives

## Requirements

- PHP 5.4 or higher
- Web server (Apache, Nginx, etc.)
- Internet connection (for loading TailwindCSS and DaisyUI from CDN)

## Installation

1. Download the `mev-shell-finder.php` file to your server
2. Place it in the root directory you want to scan or any directory from which you want to start the scan

## Usage

1. Access the script through your web browser:
   ```
   http://your-server.com/path/to/mev-shell-finder.php
   ```

2. The script will automatically scan the directory it's placed in and all subdirectories for suspicious PHP code.

3. Results will be displayed in an interactive UI showing:
   - File Path
   - Line Number
   - Matched Pattern
   - Type of Check
   - View button to see details in a modal

## Security Considerations

- This tool is meant for server administrators to scan their own servers
- Do not leave this tool accessible on a production server after use
- The script excludes itself from the scan to avoid false positives using multiple methods:
  - Full path comparison using `realpath()`
  - Directory and filename comparison
  - Simple filename comparison as a fallback
- Consider running the script with limited permissions
- The debug information section can help verify that the script is properly excluding itself

## Limitations

- The script may produce false positives as some legitimate code might use the functions being checked
- Large directories with many PHP files may take longer to scan
- The script has a default execution time limit of 300 seconds (5 minutes)

## License

This script is provided as-is with no warranty. Use at your own risk. 