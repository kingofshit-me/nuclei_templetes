import os
import shutil
import yaml

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
        "漏洞利用框架": {"tags": ["msf"], "lst": []},
        "安全测试数据集": {"tags": ["seclists"], "lst": []},
        "漏洞库": {"tags": ["vulhub"], "lst": []},
        "入侵检测/偏侵入性测试": {"tags": ["instrusive", "intrusive"], "lst": []},
    },
    "厂商&平台&产品": {
        "CMS 系统": {
            "tags": [
                "74cms", "dedecms", "wordpress", "wp", "wp-plugin", "joomla", "prestashop", "spip", "craftcms",
                "phpgurukul", "xwiki", "mcms", "mingsoft", "confluence", "chamilo", "learnpress", "glpi"
            ],
            "lst": [],
        },
        "Web平台/面板": {"tags": ["cockpit", "panel", "rconfig", "totolink"], "lst": []},
        "Java框架/平台": {"tags": ["struts", "java", "log4j", "weblogic"], "lst": []},
        "大厂厂商": {"tags": ["microsoft", "oracle", "adobe", "php", "nginx", "hp", "hpe", "sap", "vmware"], "lst": []},
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
        "A01访问控制失效": {"tags": ["access-control", "authorization", "bypass", "directory-traversal"], "lst": []},
        "A02加密失败": {"tags": ["ssl", "tls", "heartbleed", "crypto"], "lst": []},
        "A03注入": {"tags": ["sql", "xss", "ssti", "rce", "injection"], "lst": []},
        "A05安全配置错误": {"tags": ["misconfig", "default-login", "exposed-panel", "headers"], "lst": []},
        "A06存在漏洞或过时的组件": {"tags": ["cve", "vuln", "outdated", "version"], "lst": []},
        "A07身份验证失败": {"tags": ["auth", "bruteforce", "login", "token"], "lst": []},
        "A08软件/数据完整性失效": {"tags": ["git", "ci", "supply-chain", "ssrf"], "lst": []},
        "A10服务器端请求伪造": {"tags": ["ssrf"], "lst": []},
    },
}

def extract_tags_from_yaml(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
        except Exception:
            return []
    tags = []
    # 兼容 info/metadata 下的 tags
    if isinstance(doc, dict):
        if "info" in doc and "tags" in doc["info"]:
            tags = doc["info"]["tags"].split(",")
        elif "tags" in doc:
            tags = doc["tags"].split(",")
        elif "metadata" in doc and "tags" in doc["metadata"]:
            tags = doc["metadata"]["tags"].split(",")
    return [t.strip().lower() for t in tags]

def get_categories_for_tags(tags, groups_dict):
    matched = []
    for big, smalls in groups_dict.items():
        for small, v in smalls.items():
            for t in v["tags"]:
                if t.lower() in tags:
                    matched.append((big, small))
                    break
    return matched

src_dir = os.path.dirname(os.path.abspath(__file__))
dst_base = os.path.join(src_dir, "sorted_templates")
all_dir = os.path.join(dst_base, 'all')
os.makedirs(all_dir, exist_ok=True)

# 1. 先把所有 yaml 文件集中到 all/ 目录（只保留一份，已存在则跳过）
for fname in os.listdir(src_dir):
    if not fname.endswith(".yaml"):
        continue
    src_path = os.path.join(src_dir, fname)
    all_path = os.path.join(all_dir, fname)
    if not os.path.exists(all_path):
        shutil.copy(src_path, all_path)

# 2. 分类目录下创建硬链接（已存在则跳过）
for fname in os.listdir(all_dir):
    if not fname.endswith(".yaml"):
        continue
    all_path = os.path.join(all_dir, fname)
    tags = extract_tags_from_yaml(all_path)
    cats = get_categories_for_tags(tags, groupsDict)
    for big, small in cats:
        outdir = os.path.join(dst_base, big, small)
        os.makedirs(outdir, exist_ok=True)
        link_path = os.path.join(outdir, fname)
        if not os.path.exists(link_path):
            try:
                os.link(all_path, link_path)  # 硬链接
                # os.symlink(os.path.relpath(all_path, outdir), link_path)  # 软链接（如需软链，取消注释）
            except FileExistsError:
                pass
