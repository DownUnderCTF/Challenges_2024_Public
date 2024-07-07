<?php

include 'flag.php';

function theme() {
    return $_SESSION['theme'] == "dark" ? "dark" : "light";
}

function other_theme() {
    return $_SESSION['theme'] == "dark" ? "light" : "dark";
}

session_start();

$_SESSION['flag'] = FLAG; /* Flag is in the session here! */
$_SESSION['theme'] = $_GET['theme'] ?? $_SESSION['theme'] ?? 'light';

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sniffy</title>
    <link rel="stylesheet" href="/css/style-<?= theme() ?>.css" id="theme-style">
    <script src="/js/script.js" defer></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>sniffy</h1>
            <p>kookaburra wildlife sanctuary</p>
            <div class="theme-switcher">
                <a href="/?theme=<?= other_theme() ?>"><img src="/img/<?= other_theme() ?>.svg" width="25px" alt="<?= other_theme() ?> mode" id="<?= other_theme() ?>-icon"></a>
            </div>
        </header>
        <main>
            <p>listen to the sounds of our kookaburras</p>
            <div class="buttons">
<?php

foreach(scandir('audio/') as $v) {
    if ($v == '.' || $v == '..') continue;
    echo "                <img src='/img/play-" . other_theme() . ".svg' width='40px' onclick=\"playAudio('/audio.php?f=$v');\"/>\n";
}

?>            </div>
        </main>
    </div>
</body>
</html>
