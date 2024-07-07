<?php

$file = 'audio/' . $_GET['f'];

if (!file_exists($file)) {
	http_response_code(404); die;
}

$mime = mime_content_type($file);

if (!$mime || !str_starts_with($mime, 'audio')) {
	http_response_code(403); die;
}

header("Content-Type: $mime");
readfile($file);