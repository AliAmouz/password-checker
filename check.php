<?php
/**
 * Enhanced Password Strength Checker
 * Provides detailed analysis and security recommendations
 */

// Security headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get input and validate
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (!isset($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Password field is required']);
        exit;
    }
    
    $password = $data['password'];
    
    // Validate password length constraints
    if (strlen($password) > 128) {
        http_response_code(400);
        echo json_encode(['error' => 'Password exceeds maximum length']);
        exit;
    }
    
    $analysis = analyzePassword($password);
    echo json_encode($analysis);
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed']);

/**
 * Comprehensive password analysis
 * 
 * @param string $password The password to analyze
 * @return array Detailed analysis including strength, score, and recommendations
 */
function analyzePassword($password) {
    $length = strlen($password);
    $score = 0;
    $maxScore = 100;
    $feedback = [];
    $criteria = [];
    
    // Length scoring (0-30 points)
    if ($length < 8) {
        $score += $length * 2;
        $feedback[] = 'Password should be at least 8 characters long';
        $criteria['length'] = false;
    } elseif ($length < 12) {
        $score += 20;
        $feedback[] = 'Consider using 12+ characters for better security';
        $criteria['length'] = true;
    } elseif ($length < 16) {
        $score += 25;
        $criteria['length'] = true;
    } else {
        $score += 30;
        $criteria['length'] = true;
    }
    
    // Character variety (0-40 points)
    $hasLower = preg_match('/[a-z]/', $password);
    $hasUpper = preg_match('/[A-Z]/', $password);
    $hasNumber = preg_match('/[0-9]/', $password);
    $hasSpecial = preg_match('/[!@#$%^&*()_+\-=\[\]{};:\'",.<>?\/\\|`~]/', $password);
    
    $criteria['lowercase'] = $hasLower;
    $criteria['uppercase'] = $hasUpper;
    $criteria['numbers'] = $hasNumber;
    $criteria['special'] = $hasSpecial;
    
    $varietyCount = $hasLower + $hasUpper + $hasNumber + $hasSpecial;
    $score += $varietyCount * 10;
    
    if (!$hasLower) $feedback[] = 'Add lowercase letters (a-z)';
    if (!$hasUpper) $feedback[] = 'Add uppercase letters (A-Z)';
    if (!$hasNumber) $feedback[] = 'Add numbers (0-9)';
    if (!$hasSpecial) $feedback[] = 'Add special characters (!@#$%^&*, etc.)';
    
    // Complexity bonus (0-20 points)
    $uniqueChars = count(array_unique(str_split($password)));
    $complexityRatio = $uniqueChars / max($length, 1);
    
    if ($complexityRatio > 0.7) {
        $score += 20;
    } elseif ($complexityRatio > 0.5) {
        $score += 15;
    } elseif ($complexityRatio > 0.3) {
        $score += 10;
    } else {
        $feedback[] = 'Avoid too many repeated characters';
    }
    
    // Pattern penalties (0-10 points)
    $penalties = checkWeakPatterns($password);
    $score -= $penalties['score'];
    $feedback = array_merge($feedback, $penalties['messages']);
    
    // Ensure score is within bounds
    $score = max(0, min($maxScore, $score));
    
    // Determine strength level
    $strength = getStrengthLevel($score);
    
    // Calculate entropy (optional advanced metric)
    $entropy = calculateEntropy($password);
    
    return [
        'score' => $score,
        'strength' => $strength['level'],
        'color' => $strength['color'],
        'label' => $strength['label'],
        'criteria' => $criteria,
        'feedback' => $feedback,
        'entropy' => round($entropy, 2),
        'estimatedCrackTime' => estimateCrackTime($entropy)
    ];
}

/**
 * Check for weak password patterns
 * 
 * @param string $password
 * @return array Penalty score and messages
 */
function checkWeakPatterns($password) {
    $penalty = 0;
    $messages = [];
    
    // Sequential characters
    if (preg_match('/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i', $password)) {
        $penalty += 5;
        $messages[] = 'Avoid sequential characters (abc, 123, etc.)';
    }
    
    // Repeated characters
    if (preg_match('/(.)\1{2,}/', $password)) {
        $penalty += 5;
        $messages[] = 'Avoid repeating the same character multiple times';
    }
    
    // Common patterns
    $commonPatterns = ['password', 'qwerty', 'asdfgh', '111111', '000000', 'letmein', 'admin'];
    foreach ($commonPatterns as $pattern) {
        if (stripos($password, $pattern) !== false) {
            $penalty += 10;
            $messages[] = 'Avoid common words and patterns';
            break;
        }
    }
    
    // Keyboard patterns
    if (preg_match('/qwert|asdfg|zxcvb|12345|!@#\$%/i', $password)) {
        $penalty += 5;
        $messages[] = 'Avoid keyboard patterns';
    }
    
    return ['score' => $penalty, 'messages' => $messages];
}

/**
 * Determine strength level based on score
 * 
 * @param int $score
 * @return array Strength information
 */
function getStrengthLevel($score) {
    if ($score >= 80) {
        return ['level' => 5, 'label' => 'Very Strong', 'color' => '#22c55e'];
    } elseif ($score >= 60) {
        return ['level' => 4, 'label' => 'Strong', 'color' => '#84cc16'];
    } elseif ($score >= 40) {
        return ['level' => 3, 'label' => 'Moderate', 'color' => '#eab308'];
    } elseif ($score >= 20) {
        return ['level' => 2, 'label' => 'Weak', 'color' => '#f97316'];
    } else {
        return ['level' => 1, 'label' => 'Very Weak', 'color' => '#ef4444'];
    }
}

/**
 * Calculate password entropy (bits)
 * 
 * @param string $password
 * @return float Entropy in bits
 */
function calculateEntropy($password) {
    $charsetSize = 0;
    
    if (preg_match('/[a-z]/', $password)) $charsetSize += 26;
    if (preg_match('/[A-Z]/', $password)) $charsetSize += 26;
    if (preg_match('/[0-9]/', $password)) $charsetSize += 10;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $charsetSize += 32;
    
    $length = strlen($password);
    return $length * log($charsetSize, 2);
}

/**
 * Estimate time to crack password
 * 
 * @param float $entropy
 * @return string Human-readable time estimate
 */
function estimateCrackTime($entropy) {
    // Assume 1 billion guesses per second (modern GPU)
    $guessesPerSecond = 1e9;
    $possibleCombinations = pow(2, $entropy);
    $seconds = $possibleCombinations / (2 * $guessesPerSecond);
    
    if ($seconds < 1) return 'Instant';
    if ($seconds < 60) return round($seconds) . ' seconds';
    if ($seconds < 3600) return round($seconds / 60) . ' minutes';
    if ($seconds < 86400) return round($seconds / 3600) . ' hours';
    if ($seconds < 31536000) return round($seconds / 86400) . ' days';
    if ($seconds < 3153600000) return round($seconds / 31536000) . ' years';
    return 'Centuries+';
}
?>
