<?php
// Vulnerable MySQL web app with SQLi entry point
$mysqli = new mysqli(getenv('DB_HOST') ?: 'db', 'root', 'rootpass123', 'vulnapp');
if ($mysqli->connect_error) {
    die("DB connection failed: " . $mysqli->connect_error);
}

if (isset($_GET['id'])) {
    // Vulnerable: direct string interpolation into SQL
    $id = $_GET['id'];
    $result = $mysqli->query("SELECT name, price FROM items WHERE id = $id");
    echo "<h2>Search Results</h2>";
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars($row['name']) . " - $" . htmlspecialchars($row['price']) . "<br>";
    }
} else {
    echo "<h1>Product Catalog</h1>";
    $result = $mysqli->query("SELECT * FROM items");
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars($row['name']) . "<br>";
    }
    echo '<p><form action="/"><input name="id" placeholder="Product ID"></form></p>';
}
?>
<p><em>Flag is at /flag.txt — requires command execution to read.</em></p>
