<html>
<head>
<title>antixss test</title>
<meta content="text/html; charset=utf-8" http-equiv="content-type"/>
</head>
<body>
<div style="margin-left:30px;margin-top:20px;">
 <?php

if(isset($_POST['content']))
{
	require_once 'simple_html_dom.php';
	require_once 'anti_xss.class.php';
	$content = $_POST['content'];
	$antiXss = new anti_xss();
	$antiXss->debug = true;
	$purifyContent = $antiXss->purify($content);
	 
	echo $purifyContent;
	echo "<br/>过滤后的代码:<br/><div style=\"background-color:#B1ACFF;\">";
	echo htmlspecialchars($purifyContent);
    echo "</div><br/>";
	echo "提交的内容：<br />";
	echo htmlspecialchars($content);
	echo "<hr />";
	echo "<br />";
}
else
{
	$content="xss code ";
}
?>
 <form action="index.php" method="post">
  <textarea name="content" cols="40" rows="10"><?php echo htmlspecialchars($content);?></textarea>
<br/><br/>
 <input style="margin-left:200px" type="submit" value="提交"/> <a href="test.php">使用编辑器</a> 
<br/><br/>
 建议发送到 <a href="mailto:gongjun@staff.sina.com.cn">gongjun@staff.sina.com.cn</a> <a href="mailto:hancheng2@staff.sina.com.cn">hancheng2@staff.sina.com.cn</a>
 </form>
</div>
</body>
</html>
