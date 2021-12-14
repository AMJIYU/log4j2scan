# log4j2scan 批量扫描脚本

随便写写，好像发现了百度还未完全修复。。。。

检测的DNSLog 基于 http://ceye.io ，需要如下信息Identifier  与 API Token

![image-20211214185833014](image-20211214185833014.png)

### 单个url 扫描

```
python3 log4j2_scan.py -k "xxxxxxx" -c "xxxxx.ceye.io" -u https://www.baidu.com
```

![image-20211214185425306](image-20211214185425306.png)



发现虽然请求了一次，但过一段时间DNSLog会收到好几个请求：

![image-20211214190933187](image-20211214190933187.png)

### 批量扫描 

```
python3 log4j2_scan.py -k "xxxxxxx" -c "xxxxx.ceye.io" -f url.txt
```

![image-20211214185254124](image-20211214185254124.png)



