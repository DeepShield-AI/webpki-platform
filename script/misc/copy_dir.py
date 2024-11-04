
import shutil
import os

load_dir = r'H:/nimbus2024'
save_dir = r'C:/nimbus2024'

def copy_all(source_dir, destination_dir):
    # 检查源路径是否存在
    if not os.path.exists(source_dir):
        print(f"{source_dir} 路径不存在")
        return

    # 如果目标路径不存在，则创建
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
        print(f"已创建目标目录: {destination_dir}")

    # 使用 os.scandir() 遍历源目录中的文件和子文件夹
    with os.scandir(source_dir) as entries:
        for entry in entries:
            source_path = entry.path
            destination_path = os.path.join(destination_dir, entry.name)

            try:
                if entry.is_file():
                    shutil.copy2(source_path, destination_path)  # 拷贝文件和元数据
                    print(f"已拷贝文件: {source_path} -> {destination_path}")
                elif entry.is_dir():
                    # 如果是文件夹，递归调用 copy_all
                    copy_all(source_path, destination_path)
                    print(f"已拷贝文件夹: {source_path} -> {destination_path}")
            except Exception as e:
                print(f"拷贝 {source_path} 时出错: {e}")

# 调用函数来拷贝所有文件和文件夹
copy_all(load_dir, save_dir)
