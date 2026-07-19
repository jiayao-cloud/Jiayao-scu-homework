# 修复后应用

请先复制 `.env.example` 中的变量到进程环境，并为每个环境设置独立随机 Secret 和强密码；不要将真实值写入文件或提交 Git。

应用入口：`app.py`  ；依赖：`requirements.txt` ；安全回归测试位于上级 `tests/test_app.py`。
