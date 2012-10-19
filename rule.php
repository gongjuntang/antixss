<?php
/**
* antixss 规则配置
*/
$_                              = array();
$_['working']                   = true; //此文件规则是否生效
$_['default']                   = false; //对既不在黑名单也不在白名单中的属性的操作，默认为false不处理,true为调用函数dealAttrDefault
//定义全局黑名单标签
$_['black_dom']['global_dom'] = array(
    'layer',
    'base',
    'basefont',
    'head',
    'html',
    'body',
    'applet',
    /*'object',*/
    'iframe',
    'frame',
    'frameset',
    'script',
	'scriptlet',
    'ilayer',
	/*'embed',*/ 
    'bgsound',
    'link',
    'meta',
    'style',
    'ievbs' //规则是<!if
);
//定义全局黑名单属性
$_['black_attr']['global_attr'] = array(
    'onload',
    'onchange',
    'onsubmit',
    'onreset',
    'onerror',
    'onselect',
    'onblur',
    'onfocus',
    'onabort',
    'onkeydown',
    'onkeypress',
    'onkeyup',
    'onclick',
    'ondblclick',
    'onmousedown',
    'onmousemove',
    'onmouseout',
    'onmouseover',
    'onmouseup',
    'onbeforeupdate',
    'ondataavailable',
    'onrowsdelete',
    'onrowsinserted',
    'onscroll',
    'formaction',
    'oninput',
    'autofocus',
    'onfilterchange',
	'seeksegmenttime'
);
//定义全局白名单属性
$_['white_attr']['global_attr'] = array(
  /*  'id',
    'name'*/
);
//定义全局白名单标签
$_['white_dom']               = array();
//定义需要具体检测的标签
$_['filter_dom']              = array(
    'param' => array(
        'value' => array(
            'func' => 'url_xss',
            'set' => '#'
        )
    ),
    'object' => array(
        'data' => array(
            'func' => 'url_xss',
            'set' => '#'
        )
    ),
    'video' => array(
        'poster' => array(
            'func' => 'url_xss',
            'set' => '#'
        )
    )
);
//定义全局属性及规则
$_['filter_attr']               = array(
    'style' => array(
        'func' => 'style_xss',
    ),
    'background' => array(
        'func' => 'style_xss',
    ),
    'dynsrc' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'lowsrc' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'bgsound' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'src' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'href' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'xlink' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
	'xlink:href' => array(
        'func' => 'url_xss',
        'set' => '#'
    ),
    'allowscriptaccess' => array(
        'regx' => '/^never$/i',
        'set' => 'never'
    ),
    'allownetworking' => array(
	    'regx' => '/^none$/i',
        'set' => 'none'
    )
);
/**
 * 检查style属性的值是否含有xss代码
 * @return true 存在xss false 不存在xss
 */
function style_xss($str)
{
	$regx='/(expression|behavior|javascript)/i';
	if (preg_match($regx, $str))
    {
        return true;
    }
    else
    {
        return false;
    }
}
/**
 * 检查是否是标准的url属性值
 * @return true 存在xss false 不存在xss
 */
function url_xss($str)
{
    //$regx='/^(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:\+#]*[\w\-\@?^=%&amp;\+#])?/i';
    $regx = "/^(javascript|vbscript|about|data):?/i";
    if (preg_match($regx, $str))
    {
        return true;
    }
    else
    {
        return false;
    }
}
