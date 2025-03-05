I need a single PHP file that scans the server's directory for potentially malicious code in PHP files and displays the results in a well-formatted HTML table. The script should perform the following checks:

1. **Check for Suspicious PHP Functions:**
   - Search for PHP files containing functions like `shell_exec`, `eval`, `base64_decode`, `exec`, `system`, `passthru`, `popen`, `proc_open`, `assert`, and `gzuncompress`.
   - Use a command similar to:  
     `grep -rnw . -E -e 'shell_exec|eval|base64_decode|exec|system|passthru|popen|proc_open|assert|gzuncompress' --include="*.php"`

2. **Check for Encoded/Obfuscated Files:**
   - Search for PHP files containing patterns like `eval(`, `base64_decode`, `gzinflate`, `gzuncompress`, `str_rot13`, `urldecode`, and `assert(`.
   - Use a command similar to:  
     `grep -R --include="*.php" -E "(eval\(|base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|assert\()" .`

3. **Check for Reverse Shell:**
   - Search for PHP files containing patterns like `php.+?system(`, `php.+?exec(`, `php.+?shell_exec(`, `php.+?popen(`, and `php.+?proc_open(`.
   - Use a command similar to:  
     `grep -r --include="*.php" -E "php.+?system\(|php.+?exec\(|php.+?shell_exec\(|php.+?popen\(|php.+?proc_open\(" .`

**Requirements:**
- The script should recursively scan the current directory and its subdirectories.
- The results should be displayed in a clean, readable HTML table with the following columns:
  - **File Path**: The path to the file where the suspicious code was found.
  - **Line Number**: The line number where the suspicious code was detected.
  - **Matched Pattern**: The specific pattern or function that was matched.
  - **Type of Check**: Indicate whether it's a 'Suspicious Function', 'Encoded/Obfuscated Code', or 'Reverse Shell' check.
- The table should be styled using basic CSS for better readability.
- The script should be efficient and avoid unnecessary resource usage.
- Ensure the script is secure and does not expose sensitive server information.

**Additional Notes:**
- Use PHP's built-in functions like `glob`, `file_get_contents`, and `preg_match` to implement the checks instead of relying on shell commands like `grep`.
- Handle large directories efficiently to avoid timeouts or memory issues.
- Provide clear error handling and logging if something goes wrong during the scan.

Please provide the complete PHP code for this script.