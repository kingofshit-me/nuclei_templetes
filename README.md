# Nuclei 漏洞模板集合

## 项目简介

本项目收集并整理了大量适用于 [Nuclei](https://github.com/projectdiscovery/nuclei) 扫描器的安全漏洞检测模板，涵盖 OWASP Top 10、常见安全漏洞类型、主流厂商/平台/产品、以及各类 CVE 漏洞。适用于安全测试、渗透测试、自动化漏洞扫描等场景。

## 目录结构

- `01_Owasp/`  
  按照 OWASP Top 10 分类整理的漏洞模板，包含详细的子类说明与测试用例。
- `02_all/`  
  综合性模板集合，涵盖各类常见漏洞与 CVE，便于一站式批量检测。
- `03_厂商&平台&产品/`  
  按厂商、平台、产品分类的漏洞模板，适合定向测试特定目标。
- `04_安全漏洞类型/`  
  按漏洞类型（如 SQL 注入、XSS、SSRF、文件上传等）细分的模板库，便于针对性测试。
- `vendor_classified_templates/`  
  按厂商英文名归档的模板，便于国际化和快速定位特定厂商漏洞

## 使用方法

1. 安装并配置好 Nuclei 工具。
2. 选择对应目录下的 YAML 模板文件，结合目标系统进行扫描：
   ```bash
   nuclei -t 路径/xxx.yaml -u https://target.com
   ```
3. 可批量指定目录进行全量扫描：
   ```bash
   nuclei -t 01_Owasp/ -l urls.txt
   ```
4. 各子目录下 README.md 提供了详细的漏洞原理、测试重点和标签说明，建议结合阅读。

## 贡献指南

- 欢迎提交新的漏洞模板或完善现有模板。
- 模板需符合 Nuclei 官方格式规范，建议包含注释、参考链接、标签等。
- 命名建议：`CVE-xxxx-xxxx.yaml` 或 `产品-漏洞类型.yaml`。
- 请在对应分类目录下提交，并附带简要说明。

## 参考与致谢

- [Nuclei 官方文档](https://nuclei.projectdiscovery.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- 各安全社区、开源项目及贡献者
