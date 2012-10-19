<?php
/**
 * 通用防富文本xss程序 
 * @date 2012/09/04
 * @Author gongjun@staff.sina.com.cn hancheng2@staff.sina.com.cn
 */
class anti_xss
{
    public $config = array();
    private $log = '';
    public $debug = false;
    
    public function __construct($filename = 'rule.php')
    {
        $file = dirname(__FILE__) . '/' . $filename;
        if (file_exists($file)) {
            $_ = array();
            require_once($file);
            $this->config = $_;
            $key_array    = array(
                'black_dom',
                'black_attr',
                'white_dom',
                'white_attr',
                'filter_dom',
                'filter_attr'
            );
            foreach ($key_array as $v) {
                !is_array($this->config[$v]) ? ($this->config[$v] = array()) : '';
            }
        } else {
            die('Error: Could not load config ' . $filename . '!');
        }
    }
    
    
    
    /**
     *@Description:净化函数
     *@parama: String $content  html 
     *@return: String $content
     *@author:hancheng2@staff.sina.com.cn
     *
     */
    public function purify($content = '')
    {
        if (empty($content))
            return;
        
		//</都不是标签
        $content       = preg_replace("/<(?=[^a-zA-Z\!\/\?])/", '&lt;', $content);
        // Web documents shouldn't contains \x00 symbol
        $content       = str_replace("\x00", '', $content);
        // Opera6 bug workaround
        $content       = str_replace("\xC0\xBC", '&lt;', $content);
        $htmlDomObject = str_get_html($content);
        if (!$htmlDomObject) {
            return $content;
        }
        if ($this->debug) {
           // $htmlDomObject->dump();
            echo "<br />\r\n";
        }
        //加载配置
        $black_dom   = $this->config['black_dom']; //全局黑名单标签
        $black_attr  = $this->config['black_attr']; //全局黑名单属性
        $white_dom   = $this->config['white_dom']; //全局白名单标签
        $white_attr  = $this->config['white_attr']; //全局白名单属性
        $filter_dom  = $this->config['filter_dom']; //特定标签过滤规则
        $filter_attr = $this->config['filter_attr']; //需要具体检测属性
        
        foreach ($htmlDomObject->nodes as $node) {
            if ($node->tag == 'root' || $node->tag == 'text') {
				$node->outertext=str_replace("<","&lt;",$node->outertext);
                continue;
            }
            //判断全局黑名单标签
            if (!empty($black_dom['global_dom']) && in_array($node->tag, $black_dom['global_dom'])) {
                $this->remove_dom($node);
                continue;
            }
            
            //当前dom检查
            if (array_key_exists($node->tag, $filter_dom)) {
                $this->check_dom($node, $filter_dom[$node->tag]);
            }
            $attributes = $node->getAllAttributes();
            if (empty($attributes))
                continue;
            
            //全局规则检查
            foreach ($attributes as $attr => $value) {
                //在白名单列表中
                if (in_array($attr, $white_attr['global_attr'])) {
                    continue;
                }
                
                //在黑名单列表中
                if (in_array($attr, $black_attr['global_attr'])) {
                    $this->remove_attr($node, $attr);
                    continue;
                }
				 
                //检查对应规则
                if (array_key_exists($attr, $filter_attr)) {
                    $rules = $filter_attr[$attr];
                    $this->check_attr_rule($node, $attr, $rules);
                    continue;
                }
                
                //未配置检查规则的属性值进行转义
                $node->$attr = htmlspecialchars($value);
                //属性名为on*,都进行删除
                if (strpos($attr, "on") === 0) {
                    $this->remove_attr($node, $attr);
                }
            }
        }
        //处理完后回调后续函数
        $this->purifyCallBack();
        return $htmlDomObject->save();
    }
    
    
    /**
     * 删除属性
     */
    private function remove_attr(&$node, $key)
    {
        $this->log .= "删除了标签[" . $node->tag . "]的[" . $key . "]属性";
        $this->log .= "<br />\n";
        $node->$key = null;
        
    }
    /***
     * 删除dom
     */
    private function remove_dom(&$node)
    {
        $this->log .= "删除了标签[" . $node->tag . "]";
        $this->log .= "<br />\n";
        $node->clear();
        $node = null;
    }
    
    /**
     *检查当前属性
     *
     */
    
    private function check_attr_rule(&$node, $key, $rules)
    {
        if (empty($node->attr[$key]))
            return;
        $value = $node->attr[$key];
        $value = trim($value); 
		 
        // replace all & to &amp;
        $value            = str_replace('&amp;', '&', $value);
        $value            = str_replace('&', '&amp;', $value);
		$value            = str_replace(array("\r","\n","\t"," "), '', $value);
		$value            = str_replace(array("<",">"), array('&lt;','&gt;'), $value);
		$value            = str_replace("\\00", '', $value);

		while($_value=preg_replace("/\/\*.*?\*\//s", '', $value))  //过滤各种注释
		{
			if($_value==$value)
			{
				break;
			}
			$value=$_value;
		}

		while($_value = str_replace("\\00", '', $value))  //过滤各种进制的编码
		{
			if($_value==$value)
			{
				break;
			}
			$value=$_value;
		}
		 
		//对首特殊分隔符处理;
		while($_value=substr($value,1))
		{
			$f_char=substr($value,0,1);
			if(!$this->is_anti_ascii(ord($f_char))) //assic特殊字符
			{
				break;
			}
			$value=$_value;
		}
		//对尾特殊分隔符处理;
		while($_value=substr($value,0,-1))
		{
			$e_char=substr($value,-1);
			if(!$this->is_anti_ascii(ord($e_char))) //assic特殊字符
			{
				break;
			}
			$value=$_value;
		}		
		$value            = str_replace("\\", '/', $value);




        $node->attr[$key] = $value;
        
        //正则检测
        if (isset($rules['regx']) && !empty($rules['regx'])) {
            if (!preg_match($rules['regx'], $node->attr[$key])) {
                $this->log .= "标签[" . $node->tag . "]的[" . $key . "]值不符合正则[" . $rules['regx'] . "]:" . (empty($rules['set']) ? "删除" : "替换");
                $this->log .= "<br/>\r\n";
                empty($rules['set']) ? ($node->$key = null) : ($node->attr[$key] = $rules['set']);
            }
        }
        //函数检测
        if (isset($rules['func']) && function_exists($rules['func'])) {
            $func = $rules['func'];
            if ($func($node->attr[$key])) {
                $this->log .= "标签[" . $node->tag . "]的[" . $key . "]值满足威胁检测函数[" . $rules['func'] . "]:" . (empty($rules['set']) ? "删除" : "替换");
                $this->log .= "<br/>\r\n";
                empty($rules['set']) ? ($node->$key = null) : ($node->attr[$key] = $rules['set']);
            }
        }
        
    }
   /**
   *是否是特殊字符，不会显示的字符
   */
	public function is_anti_ascii($ascii)
	{
		if($ascii<32||in_array($ascii,array(96,39,94)))
		{
			return true;
		}
		else
			return false;
	}

    private function purifyCallBack()
    {
        if ($this->debug) {
            echo "<br /> \r\n";
            echo $this->log, "<br/>\r\n";
        }
    }

    /**
     * 对指定dom进行指定的规则检查
     */
    private function check_dom(&$node, $rules)
    {
        if (empty($rules))
            return;
        foreach ($rules as $key => $rule) {
            $this->check_attr_rule($node, $key, $rule);
        }
    }
    
}
