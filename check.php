<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'];
    $strength = getPasswordStrength($password);
    echo json_encode(['strength' => $strength]);
}

function getPasswordStrength($password) {
    $strength = 0;
    $patterns = [
        '/[a-z]/',  // Lowercase
        '/[A-Z]/',  // Uppercase
        '/[0-9]/',  // Numbers
        '/[!@#$%^&*(),.?":{}|<>]/'  // Special characters
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $password)) {
            $strength++;
        }
    }

    $length = strlen($password);
    if ($length >= 8) {
        $strength++;
    }

    return $strength;
}
?>
