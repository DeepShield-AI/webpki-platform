
'''
    Fifth step, run Zlint on certs replicas for Top-1m
'''

import subprocess

class LintAnalysis():
    def __init__(self) -> None:
        self.zlint_abs_path = r"D:/global_ca_monitor/app/zlint_3.6.3_Windows_x86_64/zlint.exe"
    pass

    def run_zlint(self, cert_path, additional_args=None):
        try:
            # 基本的 zlint 命令和证书路径
            command = [self.zlint_abs_path]
            
            # 如果有额外参数，加入命令中
            if additional_args:
                command.extend(additional_args)

            command.extend(cert_path)
            
            # 调用 ZLint 命令
            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )
            
            # 检查是否执行成功
            if result.returncode == 0:
                # 输出结果
                print("ZLint Output:\n", result.stdout)
            else:
                # 输出错误信息
                print("ZLint Error:\n", result.stderr)
        except FileNotFoundError:
            print("ZLint 未安装或未找到，请检查您的 ZLint 安装路径。")
        except Exception as e:
            print(f"运行 ZLint 时发生错误: {e}")

lint = LintAnalysis()
certificate_path = [r"D:/global_ca_monitor/test/test_certs/tsinghua.edu.cn_single.pem"]
extra_args = ['-summary']
lint.run_zlint(certificate_path, extra_args)
