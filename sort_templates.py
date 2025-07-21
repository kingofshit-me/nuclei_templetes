import os
import yaml
import shutil
import sys
import time  # For adding delays in debug output

# 要排除的关键词列表（不区分大小写）
# 主要包含国外常用而国内较少使用的平台和组件
EXCLUDE_KEYWORDS = [
    # 国内CMS和平台
    '74cms',
    
    # 国外CMS和建站平台
    'wordpress', 'wp-', 'joomla', 'drupal', 'magento', 'prestashop',
    'squarespace', 'wix', 'weebly', 'shopify', 'commerce', 'weaver',
    'jolokia', 'landray', 'lucee', 'malwared', 'opennms', 'opencpu', 'openstack', 'slack',
    'aem-crx', 'avaya', 'chanjet', 'cerio', 'chamilo', 'citrix', 'commax',
    
    # 云服务提供商
    'aws', 'amazon-web-services', 'azure', 'google-cloud', 'gcp', 
    'digitalocean', 'digital-ocean', 'linode', 'vultr', 'hetzner',
    
    # 开发工具和平台
    'heroku', 'netlify', 'vercel', 'github-pages', 'gitlab-pages',
    
    # 国外SaaS服务
    'slack', 'discord', 'teams', 'salesforce', 'hubspot', 'zendesk', 
    'intercom', 'okta', 'auth0', 'atlassian', 'zoho', 'splunk',
    'paloalto', 'checkpoint', 'sentry', 'datadog', 'newrelic',
    
    # 特定技术栈
    'ruby-on-rails', 'elixir', 'phoenix', 'dotnet-core',
    
    # 特定国家/地区服务
    'govuk', 'us-gov', 'eu-',
    
    # 其他国外常用服务
    'cpanel', 'plesk', 'whmcs', 'wordfence',
    'jupyter', 'photo', 'blog', 'cms', 'cisco',
    
    # 添加其他需要排除的关键词
    'camera', 'strapi', 'sponip', 'socicwall', 'sosial', 'netgear', 'netdisco',
    'horde', 'omnipcx', 'netsweeper',
    
    # 国外企业软件和系统
    'lutron', 'opendreambox', 'zimbra', 'pgadmin', 'apache-superset', 'mlflow',
    'spring-cloud', 'liferay', 'vbulletin', 'monitorr', 'sar2html', 'flexnet',
    
    # 国外网络设备
    'd-link', 'western-digital', 'seagate', 'zyxel', 'fortinet', 'fortinac',
    'blackarmor', 'mycloud', 'wavlink',
    
    # 国外开发/DevOps工具
    'mongo-express', 'metabase', 'sonatype-nexus', 'jfrog-artifactory',
    'apache-superset', 'apache-airflow', 'apache-ofbiz', 'jetbrains-teamcity',
    'langflow',
    
    # 国外企业软件
    'sysaid', 'gladinet', 'centrestack', 'zoneminder', 'majordomo',
    'icewarp', 'nostromo',
    
    # 其他国外产品
    'aj-report', 'rosario-sis', 'bigant', 'casdoor', 'circarlife', 'code42', 'dbgate',
    'dixell', 'dvwa', 'ecshop', 'ecsimagingpacs', 'elfinder', 'etouch',
    'f-secure', 'flir', 'fortiportal', 'fumasoft', 'fumengyun', 'gitea', 'gitlab', 'goanywhere',
    'gogs', 
]

# 1. 你的 groupsDict 直接粘贴到这里（只保留 dict 内容，不要 ref/等 vue 语法）
groupsDict = {
    "安全漏洞类型": {
        "远程命令执行（RCE）": {"tags": ["rce"], "lst": []},
        "本地文件包含（LFI）": {"tags": ["lfi"], "lst": []},
        "目录遍历": {"tags": ["traversal"], "lst": []},
        "反序列化": {"tags": ["deserialization"], "lst": []},
        "SQL 注入": {"tags": ["sqli", "time-based-sqli", "nosqli"], "lst": []},
        "XSS": {"tags": ["xss"], "lst": []},
        "SSRF": {"tags": ["ssrf"], "lst": []},
        "SSTI": {"tags": ["ssti"], "lst": []},
        "XXE": {"tags": ["xxe"], "lst": []},
        "JWT": {"tags": ["jwt"], "lst": []},
        "JNDI 注入": {"tags": ["jndi"], "lst": []},
        "权限绕过": {"tags": ["auth-bypass", "unauth", "bypass"], "lst": []},
        "配置错误": {
            "tags": ["misconfig", "exposure", "config", "default-login", "install", "installer", "metadata"],
            "lst": [],
        },
        "信息泄露": {"tags": ["disclosure"], "lst": []},
        "文件上传漏洞": {"tags": ["file-upload", "fileupload"], "lst": []},
        "子域接管/帐号劫持": {"tags": ["account-takeover"], "lst": []},
        "请求走私": {"tags": ["smuggling"], "lst": []},
        "入侵检测/偏侵入性测试": {"tags": ["instrusive", "intrusive"], "lst": []},
    },
    "厂商&平台&产品": {
        "CMS 系统": {
            "tags": [
                "dedecms", "wordpress", "wp", "wp-plugin", "joomla", "prestashop", "spip", "craftcms",
                "phpgurukul", "xwiki", "mcms", "mingsoft", "confluence", "chamilo", "learnpress", "glpi"
            ],
            "lst": [],
        },
        "Web平台/面板": {"tags": ["cockpit", "panel", "rconfig", "totolink"], "lst": []},
        "Java框架/平台": {"tags": ["struts", "java", "log4j", "weblogic"], "lst": []},
        "厂商": {"tags": ["microsoft", "oracle", "adobe", "php", "nginx", "hp", "hpe", "sap", "vmware"], "lst": []},
        "安全设备/防火墙/VPN": {
            "tags": [
                "fortinet", "fortios", "sonicwall", "vpn", "globalprotect", "dahua", "hikvision", "ruijie", "zyxel",
                "dlink", "wanhu", "wavlink", "netgear", "sangfor", "telesquare"
            ],
            "lst": [],
        },
        "开源软件": {"tags": ["oss"], "lst": []},
        "CI/CD 与 DevOps": {"tags": ["gitlab", "teamcity", "devops", "mlflow", "installer"], "lst": []},
        "云平台与虚拟化": {"tags": ["digitalocean", "k8s", "kubernetes", "nacos", "vmware"], "lst": []},
        "办公自动化": {
            "tags": ["oa", "tongda", "yonyou", "online-fire-reporting", "online_fire_reporting_system_project"],
            "lst": [],
        },
        "监控系统": {"tags": ["zabbix", "zoneminder"], "lst": []},
        "其他产品/平台": {
            "tags": ["jeecg", "kevinlab", "progress", "solarview", "std42", "thedigitalcraft", "manageengine"],
            "lst": [],
        },
    },
    "Owasp": {
        "01_A03注入": {"tags": ["sql", "xss", "ssti", "rce", "injection"], "lst": []},
        "02_A05安全配置错误": {"tags": ["misconfig", "default-login", "exposed-panel", "headers"], "lst": []},
        "03_A06存在漏洞或过时的组件": {"tags": ["cve", "vuln", "outdated", "version"], "lst": []},
        "04_A10服务器端请求伪造": {"tags": ["ssrf"], "lst": []},
    },
}

def should_exclude_template(doc):
    """检查模板是否应该被排除"""
    if not isinstance(doc, dict):
        return False
        
    # 检查info.name是否包含排除关键词
    if 'info' in doc and isinstance(doc['info'], dict) and 'name' in doc['info']:
        name = str(doc['info']['name']).lower()
        if any(keyword.lower() in name for keyword in EXCLUDE_KEYWORDS):
            return True
            
    # 检查标签是否包含排除关键词
    tags = []
    if "info" in doc and "tags" in doc["info"]:
        tags = doc["info"]["tags"].lower().split(",")
    elif "tags" in doc:
        tags = doc["tags"].lower().split(",")
    elif "metadata" in doc and "tags" in doc["metadata"]:
        tags = doc["metadata"]["tags"].lower().split(",")
        
    if any(any(keyword.lower() in tag for tag in tags) for keyword in EXCLUDE_KEYWORDS):
        return True
        
    return False

def extract_tags_from_yaml(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
            
            # 检查是否应该排除此模板
            if should_exclude_template(doc):
                print(f"[EXCLUDED] {filepath} - Matched exclusion keyword")
                return None  # 返回None表示应该跳过此文件
                
        except Exception as e:
            print(f"[ERROR] Error parsing {filepath}: {str(e)}")
            return None
            
    tags = []
    
    # 1. Check standard tag locations
    if isinstance(doc, dict):
        # Check info.tags
        if "info" in doc and isinstance(doc["info"], dict) and "tags" in doc["info"]:
            if isinstance(doc["info"]["tags"], str):
                tags.extend(t.strip().lower() for t in doc["info"]["tags"].split(","))
        
        # Check root level tags
        if "tags" in doc:
            if isinstance(doc["tags"], str):
                tags.extend(t.strip().lower() for t in doc["tags"].split(","))
        
        # Check metadata.tags
        if "metadata" in doc and isinstance(doc["metadata"], dict) and "tags" in doc["metadata"]:
            if isinstance(doc["metadata"]["tags"], str):
                tags.extend(t.strip().lower() for t in doc["metadata"]["tags"].split(","))
    
    # 2. Extract from CVE ID if present
    if "cve-20" in filepath.lower():
        cve_id = filepath.lower().split("cve-")[1].split(".")[0]
        tags.append(f"cve-{cve_id}")
    
    # 3. Extract from filename (lowercase without extension)
    filename = os.path.basename(filepath).lower().replace(".yaml", "")
    tags.append(filename)
    
    # 4. Add additional tags based on content
    if isinstance(doc, dict):
        # Add product/technology if mentioned in info.name or info.description
        if "info" in doc and isinstance(doc["info"], dict):
            if "name" in doc["info"] and isinstance(doc["info"]["name"], str):
                name_lower = doc["info"]["name"].lower()
                if "wordpress" in name_lower:
                    tags.append("wordpress")
                    tags.append("wp")
                if "drupal" in name_lower:
                    tags.append("drupal")
                if "joomla" in name_lower:
                    tags.append("joomla")
                if "apache" in name_lower:
                    tags.append("apache")
                if "nginx" in name_lower:
                    tags.append("nginx")
                if "iis" in name_lower:
                    tags.append("iis")
            
            # Add vulnerability type if mentioned
            if "description" in doc["info"] and isinstance(doc["info"]["description"], str):
                desc_lower = doc["info"]["description"].lower()
                if "sql injection" in desc_lower or "sqli" in desc_lower:
                    tags.append("sqli")
                if "cross-site scripting" in desc_lower or "xss" in desc_lower:
                    tags.append("xss")
                if "remote code execution" in desc_lower or "rce" in desc_lower:
                    tags.append("rce")
                if "server-side request forgery" in desc_lower or "ssrf" in desc_lower:
                    tags.append("ssrf")
                if "local file inclusion" in desc_lower or "lfi" in desc_lower:
                    tags.append("lfi")
                if "directory traversal" in desc_lower:
                    tags.append("traversal")
    
    # Remove duplicates and empty strings
    return list(set(t for t in tags if t))

def get_categories_for_tags(tags, groups_dict):
    matched = []
    print(f"\nMatching tags: {tags}")
    
    for big, smalls in groups_dict.items():
        for small, v in smalls.items():
            for t in v["tags"]:
                # Check if any tag starts with or contains our target tag
                for tag in tags:
                    if t.lower() in tag or tag in t.lower():
                        print(f"  Match found: '{t}' in '{tag}' -> {big}/{small}")
                        matched.append((big, small))
                        break  # Move to next category after first match
                else:
                    continue  # Only executed if the inner loop did NOT break
                break  # Only executed if the inner loop DID break
    
    print(f"Matched categories: {matched}")
    return matched

def delete_templates_by_keyword(keyword, base_dir):
    """
    删除所有匹配关键字的模板文件
    :param keyword: 要匹配的关键字（不区分大小写）
    :param base_dir: 要搜索的基准目录
    """
    deleted_count = 0
    
    # 遍历所有子目录中的YAML文件
    for root, _, files in os.walk(base_dir):
        for file in files:
            if not file.endswith('.yaml'):
                continue
                
            file_path = os.path.join(root, file)
            try:
                # 读取YAML文件
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # 解析YAML
                data = yaml.safe_load(content)
                
                # 检查info.name是否包含关键字
                if (isinstance(data, dict) and 
                    'info' in data and 
                    isinstance(data['info'], dict) and 
                    'name' in data['info'] and 
                    keyword.lower() in str(data['info']['name']).lower()):
                    
                    print(f"Deleting: {file_path}")
                    os.unlink(file_path)
                    deleted_count += 1
                    
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
    
    print(f"\nDeleted {deleted_count} files matching keyword: {keyword}")
    return deleted_count

def main():
    # 创建输出目录
    src_dir = os.path.dirname(os.path.abspath(__file__))
    dst_base = os.path.join(src_dir, "sorted_templates")
    all_dir = os.path.join(dst_base, 'all')
    
    # 检查是否提供了删除参数
    if len(sys.argv) > 1 and sys.argv[1] == '--delete':
        if len(sys.argv) < 3:
            print("请提供要删除的关键字，例如: python sort_templates.py --delete 74cms")
            return
            
        keyword = sys.argv[2]
        print(f"Searching for templates with keyword: {keyword}")
        delete_templates_by_keyword(keyword, dst_base)
        return
    
    print(f"Source directory: {src_dir}")
    print(f"Destination base directory: {dst_base}")
    print(f"All templates directory: {all_dir}")

def main():
    # 创建输出目录
    src_dir = os.path.dirname(os.path.abspath(__file__))
    dst_base = os.path.join(src_dir, "sorted_templates")
    all_dir = os.path.join(dst_base, 'all')
    
    # 检查是否提供了删除参数
    if len(sys.argv) > 1 and sys.argv[1] == '--delete':
        if len(sys.argv) < 3:
            print("请提供要删除的关键字，例如: python sort_templates.py --delete 74cms")
            return
            
        keyword = sys.argv[2]
        print(f"Searching for templates with keyword: {keyword}")
        delete_templates_by_keyword(keyword, dst_base)
        return
    
    print(f"Source directory: {src_dir}")
    print(f"Destination base directory: {dst_base}")
    print(f"All templates directory: {all_dir}")

    # 1. 确保目标目录存在
    print("\n=== Setting up directories ===")
    if not os.path.exists(all_dir):
        os.makedirs(all_dir, exist_ok=True)
        print(f"Created directory: {all_dir}")

    # 2. 直接从 src_dir/all/ 目录处理文件
    all_dir = os.path.join(src_dir, 'all')  # Update all_dir to point to the source all/ directory
    print(f"\n=== Processing files from directory: {all_dir} ===")
    print(f"Excluding templates matching keywords: {', '.join(EXCLUDE_KEYWORDS)}")

    # 3. 分类目录下创建硬链接（已存在则跳过）
    print("\n=== Processing files for categorization ===")
    files_processed = 0
    files_categorized = 0
    files_excluded = 0

    for fname in sorted(os.listdir(all_dir)):  # Sort for consistent output
        if not fname.endswith(".yaml"):
            print(f"Skipping non-YAML file: {fname}")
            continue
            
        all_path = os.path.join(all_dir, fname)
    
        # 提取标签（如果返回None，表示应该跳过此文件）
        tags = extract_tags_from_yaml(all_path)
        if tags is None:
            files_excluded += 1
            continue
                    
        files_processed += 1
        
        print(f"\n=== Processing: {fname} ===")
        print(f"Extracted {len(tags)} tags: {tags}")
        
        # Get matching categories
        print("\nMatching categories...")
        
        # 获取匹配的类别
        cats = get_categories_for_tags(tags, groupsDict)
    
        if not cats:
            print(f"  No categories matched for {fname}")
            continue
            
        files_categorized += 1
        
        # 为每个匹配的类别创建硬链接
        for category, subcategory in cats:
            # 创建类别目录（如果不存在）
            category_dir = os.path.join(dst_base, category, subcategory)
            os.makedirs(category_dir, exist_ok=True)
            
            # 创建硬链接
            link_path = os.path.join(category_dir, fname)
            
            # 如果硬链接已存在，则跳过
            if os.path.exists(link_path):
                print(f"  Link already exists: {link_path}")
                continue
                
            try:
                os.link(all_path, link_path)
                print(f"  Created link: {link_path}")
            except Exception as e:
                print(f"  Error creating link {link_path}: {e}")

    print(f"\n=== Processing complete ===")
    print(f"Total files processed: {files_processed}")
    print(f"Files excluded: {files_excluded}")
    print(f"Files categorized: {files_categorized}")
    
    # 4. 将所有安全漏洞类型的文件整合到sorted_templates/all
    print("\n=== Consolidating files to sorted_templates/all ===")
    vuln_dir = os.path.join(dst_base, '安全漏洞类型')
    all_consolidated_dir = os.path.join(dst_base, 'all')
    
    # 确保目标目录存在
    os.makedirs(all_consolidated_dir, exist_ok=True)
    
    # 使用集合来跟踪已处理的文件（去重）
    processed_files = set()
    files_copied = 0
    
    # 遍历安全漏洞类型目录下的所有YAML文件
    for root, _, files in os.walk(vuln_dir):
        for file in files:
            if file.endswith('.yaml'):
                src_path = os.path.join(root, file)
                dst_path = os.path.join(all_consolidated_dir, file)
                
                # 如果文件尚未处理过
                if file not in processed_files:
                    # 如果目标文件已存在，先删除（避免硬链接问题）
                    if os.path.exists(dst_path):
                        os.unlink(dst_path)
                    
                    try:
                        # 创建硬链接
                        os.link(src_path, dst_path)
                        processed_files.add(file)
                        files_copied += 1
                    except Exception as e:
                        print(f"  Error creating link for {file}: {e}")
    
    print(f"Consolidated {files_copied} unique files to {all_consolidated_dir}")
    print(f"Total unique YAML files in {all_consolidated_dir}: {len(processed_files)}")
    
    # 验证数量
    vuln_files = set()
    for root, _, files in os.walk(vuln_dir):
        for file in files:
            if file.endswith('.yaml'):
                vuln_files.add(file)
    
    all_files = set(f for f in os.listdir(all_consolidated_dir) if f.endswith('.yaml'))
    
    print(f"\nVerification:")
    print(f"- Total unique files in 安全漏洞类型: {len(vuln_files)}")
    print(f"- Total files in {all_consolidated_dir}: {len(all_files)}")
    
    if len(vuln_files) == len(all_files):
        print("✓ Verification passed: File counts match")
    else:
        print("⚠ Warning: File counts do not match. Some files may be missing from the consolidated directory.")
    
    print(f"\nOutput directory: {dst_base}")
    print("\nCategorization and consolidation complete.")

if __name__ == "__main__":
    main()
