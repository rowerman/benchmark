<?php
// Create a Contributor user for CVE-2025-0366 attack scenario
require_once '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

if (!username_exists('contributor_user')) {
    wp_insert_user([
        'user_login' => 'contributor_user',
        'user_pass' => 'Password123!',
        'user_email' => 'contributor@example.com',
        'role' => 'contributor'
    ]);
    echo "Contributor user created.\n";
} else {
    echo "Contributor user already exists.\n";
}
