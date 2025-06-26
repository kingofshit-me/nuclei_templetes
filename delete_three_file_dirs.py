import os

BASE_DIR = "/Users/airhao3/Documents/BAS/payload-collect/top200-payload-collect/critical_templetes_collect/sorted_templates/vendor_classified_templates"

def delete_dirs_with_three_files(base_path):
    deleted_dirs = []
    for dir_name in os.listdir(base_path):
        dir_path = os.path.join(base_path, dir_name)
        print('Checking directory: ', dir_path)
        if os.path.isdir(dir_path):
            files_in_dir = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            print('files in dir', files_in_dir)
            if len(files_in_dir) <= 3:
                print(f"Directory '{dir_name}' contains 3 files. Deleting...")
                for file_name in files_in_dir:
                    file_path = os.path.join(dir_path, file_name)
                    try:
                        os.remove(file_path)
                        print(f"  Deleted file: {file_path}")
                    except OSError as e:
                        print(f"  Error deleting file {file_path}: {e}")
                try:
                    os.rmdir(dir_path)
                    print(f"Deleted directory: {dir_path}")
                    deleted_dirs.append(dir_name)
                except OSError as e:
                    print(f"Error deleting directory {dir_path}: {e}")
    return deleted_dirs

if __name__ == "__main__":
    print(f"Starting to process directories in: {BASE_DIR}")
    deleted = delete_dirs_with_three_files(BASE_DIR)
    if deleted:
        print("\nSuccessfully deleted the following directories (contained 3 files):")
        for d in deleted:
            print(f"- {d}")
    else:
        print("\nNo directories with exactly 3 files were found for deletion.")
