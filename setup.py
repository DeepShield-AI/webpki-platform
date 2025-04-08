
from setuptools import setup, find_packages

def read_requirements():
    with open('requirements.txt') as f:
        return [line.strip() for line in f.readlines()]

setup(
    name='pki-internet-platform',  # 你的项目名称
    version='0.1',
    packages=find_packages(),  # 自动查找所有包含 __init__.py 的包
    install_requires=read_requirements(),  # 从 requirements.txt 读取依赖
    entry_points={             # 如果需要命令行工具，可以设置这个
        'console_scripts': [
            'pki-internet-platform=tool.start:main',  # 假设你的入口函数叫 main
        ],
    },
)

# use `pip install -e .` to set up
# use `pki-internet-platform` to run
