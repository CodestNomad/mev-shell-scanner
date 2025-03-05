<?php
/**
 * MEV Shell Finder
 * 
 * A script to scan PHP files for potentially malicious code and display results in a formatted HTML table.
 */

// Set execution time limit to avoid timeouts for large directories
set_time_limit(300);

// Function to recursively get all PHP files in a directory
function getPHPFiles($dir) {
    $phpFiles = [];
    
    // Get current script information using multiple methods to ensure accurate exclusion
    $currentScriptPath = realpath(__FILE__);
    $currentScriptName = basename(__FILE__);
    $currentScriptDir = dirname(__FILE__);
    
    // Add debug info
    global $debugInfo;
    $debugInfo[] = "Current script path: " . $currentScriptPath;
    $debugInfo[] = "Current script name: " . $currentScriptName;
    $debugInfo[] = "Current script directory: " . $currentScriptDir;
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            // Skip the current script to avoid scanning itself - using multiple checks
            $filePath = $file->getPathname();
            $realFilePath = realpath($filePath);
            $fileName = basename($filePath);
            
            // Method 1: Check by full path
            if ($realFilePath === $currentScriptPath) {
                $debugInfo[] = "Excluded by full path: " . $filePath;
                continue;
            }
            
            // Method 2: Check by basename and directory
            if ($fileName === $currentScriptName && dirname($realFilePath) === $currentScriptDir) {
                $debugInfo[] = "Excluded by name and directory: " . $filePath;
                continue;
            }
            
            // Method 3: Simple basename check as last resort
            if ($fileName === $currentScriptName) {
                $debugInfo[] = "Excluded by basename: " . $filePath;
                continue;
            }
            
            $phpFiles[] = $filePath;
        }
    }
    
    return $phpFiles;
}

// Function to check for suspicious patterns in a file
function scanFile($filePath) {
    $results = [];
    $content = file_get_contents($filePath);
    $lines = explode("\n", $content);
    
    // Check for suspicious PHP functions
    $suspiciousFunctions = [
        'shell_exec', 'eval', 'base64_decode', 'exec', 'system', 
        'passthru', 'popen', 'proc_open', 'assert', 'gzuncompress'
    ];
    
    foreach ($suspiciousFunctions as $function) {
        $pattern = "/\b" . preg_quote($function, '/') . "\s*\(/i";
        foreach ($lines as $lineNumber => $line) {
            if (preg_match($pattern, $line)) {
                $results[] = [
                    'file' => $filePath,
                    'line' => $lineNumber + 1,
                    'pattern' => $function . '()',
                    'type' => 'Suspicious Function'
                ];
            }
        }
    }
    
    // Check for encoded/obfuscated files
    $obfuscationPatterns = [
        '/eval\s*\(/i' => 'eval()',
        '/base64_decode\s*\(/i' => 'base64_decode()',
        '/gzinflate\s*\(/i' => 'gzinflate()',
        '/gzuncompress\s*\(/i' => 'gzuncompress()',
        '/str_rot13\s*\(/i' => 'str_rot13()',
        '/urldecode\s*\(/i' => 'urldecode()',
        '/assert\s*\(/i' => 'assert()'
    ];
    
    foreach ($obfuscationPatterns as $pattern => $name) {
        foreach ($lines as $lineNumber => $line) {
            if (preg_match($pattern, $line)) {
                $results[] = [
                    'file' => $filePath,
                    'line' => $lineNumber + 1,
                    'pattern' => $name,
                    'type' => 'Encoded/Obfuscated Code'
                ];
            }
        }
    }
    
    // Check for reverse shell patterns
    $reverseShellPatterns = [
        '/php.+?system\s*\(/i' => 'php...system()',
        '/php.+?exec\s*\(/i' => 'php...exec()',
        '/php.+?shell_exec\s*\(/i' => 'php...shell_exec()',
        '/php.+?popen\s*\(/i' => 'php...popen()',
        '/php.+?proc_open\s*\(/i' => 'php...proc_open()'
    ];
    
    foreach ($reverseShellPatterns as $pattern => $name) {
        foreach ($lines as $lineNumber => $line) {
            if (preg_match($pattern, $line)) {
                $results[] = [
                    'file' => $filePath,
                    'line' => $lineNumber + 1,
                    'pattern' => $name,
                    'type' => 'Reverse Shell'
                ];
            }
        }
    }
    
    return $results;
}

// Start the scan
$startTime = microtime(true);
$scanResults = [];
$errorMessages = [];
$debugInfo = [];
$selfScanned = false;
$currentScriptName = basename(__FILE__);

// Add debug information
$debugInfo[] = "Current script path: " . realpath(__FILE__);

try {
    $phpFiles = getPHPFiles('.');
    $totalFiles = count($phpFiles);
    $scannedFiles = 0;
    
    // Add first few files to debug info
    $debugInfo[] = "First 5 files being scanned:";
    for ($i = 0; $i < min(5, count($phpFiles)); $i++) {
        $debugInfo[] = "- " . $phpFiles[$i];
    }
    
    foreach ($phpFiles as $file) {
        try {
            // Check if we're scanning ourselves
            if (basename($file) === $currentScriptName) {
                $selfScanned = true;
                $debugInfo[] = "WARNING: Script is scanning itself! File: " . $file;
            }
            
            $fileResults = scanFile($file);
            if (!empty($fileResults)) {
                $scanResults = array_merge($scanResults, $fileResults);
            }
            $scannedFiles++;
        } catch (Exception $e) {
            $errorMessages[] = "Error scanning file {$file}: " . $e->getMessage();
        }
    }
} catch (Exception $e) {
    $errorMessages[] = "Error during scan: " . $e->getMessage();
}

$endTime = microtime(true);
$executionTime = round($endTime - $startTime, 2);

// HTML output
?>
<!DOCTYPE html>
<html lang="en" data-theme="black">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEV Shell Finder</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.4.19/dist/full.min.css" rel="stylesheet" type="text/css" />
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-300 shadow-lg flex justify-center"><span class="font-bold">MShellScanner</span></div>

    <div class="container mx-auto px-4 py-8">
        <div class="card bg-base-100 shadow-xl mb-8">
            <div class="card-body">
                <h2 class="card-title text-2xl mb-4">Scan Summary</h2>
                
                <?php if ($selfScanned): ?>
                <div class="alert alert-warning mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div>
                        <h3 class="font-bold">Warning: Script is scanning itself!</h3>
                        <div class="text-xs">The script is still scanning itself, which may lead to false positives. Please check the debug information for details.</div>
                    </div>
                </div>
                <?php endif; ?>
                
                <div class="stats stats-vertical lg:stats-horizontal shadow">
                    <div class="stat">
                        <div class="stat-title">Execution Time</div>
                        <div class="stat-value"><?php echo $executionTime; ?> s</div>
                        <div class="stat-desc">Scan completed at <?php echo date('Y-m-d H:i:s'); ?></div>
                    </div>
                    
                    <div class="stat">
                        <div class="stat-title">Files Scanned</div>
                        <div class="stat-value"><?php echo $scannedFiles; ?></div>
                        <div class="stat-desc">PHP files in directory</div>
                    </div>
                    
                    <div class="stat">
                        <div class="stat-title">Issues Found</div>
                        <div class="stat-value <?php echo count($scanResults) > 0 ? 'text-error' : 'text-success'; ?>">
                            <?php echo count($scanResults); ?>
                        </div>
                        <div class="stat-desc">Potential security issues</div>
                    </div>
                </div>
            </div>
        </div>
        
        <?php if (!empty($errorMessages)): ?>
            <div class="alert alert-error mb-8">
                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                    <h3 class="font-bold">Errors encountered during scan:</h3>
                    <ul class="list-disc list-inside mt-2">
                        <?php foreach ($errorMessages as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        <?php endif; ?>
        
        <?php if (empty($scanResults)): ?>
            <div class="alert alert-success">
                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>No suspicious code patterns were found in the scanned files.</span>
            </div>
        <?php else: ?>
            <div class="card bg-base-100 shadow-xl">
                <div class="card-body">
                    <h2 class="card-title text-2xl mb-4">Scan Results</h2>
                    <div class="overflow-x-auto">
                        <table class="table table-zebra">
                            <thead>
                                <tr>
                                    <th>File Path</th>
                                    <th>Line</th>
                                    <th>Matched Pattern</th>
                                    <th>Type of Check</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($scanResults as $index => $result): ?>
                                    <?php 
                                        $badgeClass = '';
                                        switch ($result['type']) {
                                            case 'Suspicious Function':
                                                $badgeClass = 'badge-warning';
                                                break;
                                            case 'Encoded/Obfuscated Code':
                                                $badgeClass = 'badge-error';
                                                break;
                                            case 'Reverse Shell':
                                                $badgeClass = 'badge-error';
                                                break;
                                        }
                                    ?>
                                    <tr>
                                        <td class="font-mono text-xs"><?php echo htmlspecialchars($result['file']); ?></td>
                                        <td><?php echo $result['line']; ?></td>
                                        <td class="font-mono"><?php echo htmlspecialchars($result['pattern']); ?></td>
                                        <td><span class="badge <?php echo $badgeClass; ?>"><?php echo htmlspecialchars($result['type']); ?></span></td>
                                        <td>
                                            <button class="btn btn-xs btn-outline" onclick="showDetails(<?php echo $index; ?>)">View</button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Modal for file details -->
            <dialog id="details_modal" class="modal">
                <div class="modal-box">
                    <h3 class="font-bold text-lg" id="modal_title">File Details</h3>
                    <p class="py-4" id="modal_content">Loading...</p>
                    <div class="modal-action">
                        <form method="dialog">
                            <button class="btn">Close</button>
                        </form>
                    </div>
                </div>
            </dialog>
            
            <script>
                const results = <?php echo json_encode($scanResults); ?>;
                
                function showDetails(index) {
                    const result = results[index];
                    const modal = document.getElementById('details_modal');
                    const modalTitle = document.getElementById('modal_title');
                    const modalContent = document.getElementById('modal_content');
                    
                    modalTitle.textContent = `Issue in ${result.file}:${result.line}`;
                    modalContent.innerHTML = `
                        <div class="overflow-x-auto">
                            <table class="table table-zebra w-full">
                                <tr>
                                    <td class="font-bold">File Path</td>
                                    <td class="font-mono text-xs">${result.file}</td>
                                </tr>
                                <tr>
                                    <td class="font-bold">Line Number</td>
                                    <td>${result.line}</td>
                                </tr>
                                <tr>
                                    <td class="font-bold">Matched Pattern</td>
                                    <td class="font-mono">${result.pattern}</td>
                                </tr>
                                <tr>
                                    <td class="font-bold">Type of Check</td>
                                    <td>${result.type}</td>
                                </tr>
                            </table>
                        </div>
                        <div class="mt-4">
                            <p class="text-sm text-warning">This code might be malicious. Please review it carefully.</p>
                        </div>
                    `;
                    
                    modal.showModal();
                }
            </script>
        <?php endif; ?>
    </div>
    
    <footer class="footer footer-center p-4 bg-base-300 text-base-content mt-8">
        <aside>
            <p>Scan completed at <?php echo date('Y-m-d H:i:s'); ?></p>
        </aside>
    </footer>
    
    <!-- Debug Information (Collapsible) -->
    <div class="collapse collapse-arrow bg-base-200 mx-auto max-w-4xl my-4">
        <input type="checkbox" /> 
        <div class="collapse-title text-xl font-medium">
            Debug Information
        </div>
        <div class="collapse-content"> 
            <div class="bg-base-300 p-4 rounded-lg">
                <h3 class="font-bold mb-2">File Exclusion Debug</h3>
                <pre class="whitespace-pre-wrap text-xs"><?php echo implode("\n", $debugInfo); ?></pre>
            </div>
        </div>
    </div>
</body>
</html> 