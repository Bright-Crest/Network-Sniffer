# Network-Sniffer 目录结构

（仅显示必要的部分）


```tree
Network-Sniffer
│  README.md
│  requirements.txt --- python环境
│  
├─client --- 被监听的客户端代码
│  └─sniffer_client 
│      │  config.py
│      │  main.py
│      │  
│      ├─msg --- 通信
│      │      msg.py
│      │      sse.py
│      │      
│      ├─sniff --- 抓包
│      │      sniff.py
│      │      
│      └─utils --- 线程管理
│              utils.py
│              
├─scripts --- 可运行脚本
│      README.md --- 可运行脚本的说明
│      ...
│      
└─server --- 服务端代码，Django框架
    │  db.sqlite3 --- 测试用的数据库，superuser用户名admin，密码admin
    │  manage.py
    │  
    ├─libs --- 包处理 (原创)
    │      packet_handling.py
    │      utils.py
    │      
    ├─net_proj --- Django project
    │      settings.py
    │      urls.py
    │      
    ├─sniffer --- Django app 实现包捕获结果显示
    │  │  admin.py
    │  │  config.py
    │  │  models.py
    │  │  urls.py
    │  │  views.py
    │  │  
    │  ├─management --- app管理命令
    │  │  └─commands
    │  │          sniffer_init_db.py
    │  │          
    │  ├─migrations --- 数据库迁移
    │  │      ...
    │  │              
    │  └─templates --- Django templates
    │      └─sniffer
    │              error.html
    │              index.html
    │              show_net_cards.html
    │              show_packets.html
    │              show_packets_table_rows.html
    │              success.html
    │              
    ├─static --- apps共用静态文件
    │  ├─css
    │  │      tooltip.css
    │  │      
    │  ├─img
    │  │      sniffer_example.png
    │  │      
    │  ├─js
    │  │      color-modes.js
    │  │      tooltip.js
    │  │      
    │  └─plugins --- 外部插件
    │      │  jquery-3.7.1.min.js
    │      │  
    │      └─bootstrap-5.3.3-dist
    │                  
    └─templates --- apps共用模板
            base.html
            footer.html
            home.html
            navbar.html
            theme_toggler.html
```            
