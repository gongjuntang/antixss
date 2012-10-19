<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
 
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>antixss test</title>
	<meta content="text/html; charset=utf-8" http-equiv="content-type"/>
 
</head>
<body>
	 
	<!-- This <fieldset> holds the HTML code that you will usually find in your pages. -->
	<form action="index.php" method="post">
	 
		<p>
		<?php
			// Include the CKEditor class.
			include_once "ckeditor/ckeditor.php";
			// The initial value to be displayed in the editor.
			$initialValue = '<p>This is some <strong>sample text</strong>.</p>';
			// Create a class instance.
			$CKEditor = new CKEditor();
			// Path to the CKEditor directory, ideally use an absolute path instead of a relative dir.
		   $CKEditor->basePath = 'ckeditor/';
			// If not set, CKEditor will try to detect the correct path.
			//$CKEditor->basePath = '../../';
			// Create a textarea element and attach CKEditor to it.
			$CKEditor->editor("content", $initialValue);
		?>
			<input style="margin-left:200px" type="submit" value="提交"/>
		</p>
	</form> 
</body>
</html>
