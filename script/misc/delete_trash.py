

import os

def delete_files_in_directory_one_by_one(directory_path):
    # 检查路径是否存在
    if not os.path.exists(directory_path):
        print(f"{directory_path} 路径不存在")
        return
    
    # 使用 os.scandir() 逐个读取文件
    with os.scandir(directory_path) as entries:
        for entry in entries:
            file_path = entry.path
            
            if os.path.exists(file_path):  # 确保文件存在
                try:
                    if entry.is_file() or entry.is_symlink():
                        os.unlink(file_path)
                        print(f"已删除文件: {file_path}")
                    elif entry.is_dir():
                        os.rmdir(file_path)
                        print(f"已删除空文件夹: {file_path}")
                except Exception as e:
                    print(f"删除 {file_path} 时出错: {e}")
            else:
                print(f"文件不存在，跳过: {file_path}")
# 使用示例
directory_path = r"H:/sabre2024h2_old"
delete_files_in_directory_one_by_one(directory_path)
