# 卡密管理系统

基于 Laravel 12 + Filament 5 的卡密（授权码）发放与校验系统。

管理员在后台批量生成卡密，第三方客户端（Android / 桌面 / 游戏）通过
`/api/v1/*` 接口做验证、激活、扣次、查询、解绑。协议层提供三重安全：
**HMAC-SHA256 签名 + nonce 防重放 + AES-256-GCM 卡密传输加密**。

---

## 环境要求

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| PHP | **8.2+** | 必须，低于此版本无法运行 |
| MySQL | 5.7+ / 8.0 / MariaDB 10.3+ | 数据库 |
| Nginx | 任意较新版 | Web 服务器 |
| Node.js | **20.19+ 或 22.12+** | 可选，仅在需要重新构建前端时使用 |

PHP 扩展：`pdo_mysql`、`mbstring`、`openssl`、`fileinfo`、`ctype`、`json`、
`bcmath`、`tokenizer`、`xml`、`zip`、`curl`

可选扩展：`gd`（Excel 导出插入图片时需要）、`intl`

---

## 安装步骤

### 1. 上传代码

将整个项目上传到服务器，例如 `/www/wwwroot/cardkey`。

### 2. 设置目录权限

```bash
chown -R www:www /www/wwwroot/cardkey
chmod -R 755 /www/wwwroot/cardkey
chmod -R 775 /www/wwwroot/cardkey/storage /www/wwwroot/cardkey/bootstrap/cache
```

### 3. 配置站点

**网站目录必须指向 `public/`，不是项目根目录。**

这是最关键的一步。如果指向根目录，`.env`（含数据库密码与 APP_KEY）和
`storage/` 会被公网直接访问，等于泄露全部数据。

Nginx 伪静态规则：

```nginx
location / {
    try_files $uri $uri/ /index.php?query_string;
}
```

### 4. 安装依赖

```bash
cd /www/wwwroot/cardkey
composer install --no-dev --optimize-autoloader
```

如果服务器无法安装 Composer 或缺少扩展，可在本地执行同样的命令后，
把整个 `vendor/` 目录打包上传。

### 5. 构建前端资源

```bash
npm install --no-package-lock
npm run build
```

产物在 `public/build/`。

> **注意**：`public/build/` 已随仓库提供，**通常不需要执行这一步**。
> 只有在修改了 `resources/` 下的前端源码时才需要重新构建。
>
> 若必须构建，Node 版本需为 **20.19+ 或 22.12+**（Vite 7 的硬性要求）。
> 版本过低会报 `Vite requires Node.js version 20.19+`。

### 6. 运行安装向导

浏览器访问：

```
https://你的域名/install.php
```

按页面提示填写：

- **数据库信息** —— 地址、端口、库名、用户名、密码（库不存在会自动创建）
- **管理员账号** —— 用户名、邮箱（登录用）、密码
- **站点信息** —— 站点地址、站点名称、后台品牌名、备份加密密码

向导会自动完成：生成 APP_KEY、写入配置、创建数据表、创建管理员、
初始化系统设置、生成缓存。

### 7. 删除安装文件

安装完成后**立即删除 `public/install.php`**，否则他人可重置你的数据库。

同时确认根目录生成了 `install.lock`（防止重复安装）。

### 8. 配置定时任务

在宝塔「计划任务」添加 Shell 脚本，**每分钟执行一次**：

```bash
cd /www/wwwroot/cardkey && php artisan schedule:run >> /dev/null 2>&1
```

不配置的话，日志清理、nonce 清理、卡密状态同步、自动备份都不会运行。

### 9. 配置队列（建议）

```bash
cd /www/wwwroot/cardkey && php artisan queue:work --sleep=3 --tries=3
```

在宝塔「进程守护管理器」里添加为常驻进程。

### 10. 开启 HTTPS

申请 SSL 证书并强制 HTTPS。客户端走 HTTP 会带来中间人篡改风险。

---

## 重要提醒：APP_KEY 不可更换

`APP_KEY` 用于加密卡密明文与 AppSecret。**一旦生成就不能再改。**

更换后会导致：

- 所有卡密的 `code_encrypted` 无法解密 → 后台看不到卡密、无法导出
- 所有应用的 `app_secret_encrypted` 无法解密 → **API 全部验签失败，系统不可用**

数据是用旧密钥加密的，新密钥解不开，**不可恢复**。

因此安装完成后请立刻备份 `.env` 文件，迁移服务器时必须使用同一个 `APP_KEY`。

---

## 部署后必做

1. **删除 `public/install.php`**
2. **备份 `.env`**（特别是 `APP_KEY`）
3. 访问 `https://你的域名/.env` 确认返回 404
4. 登录后台，在「应用管理」创建应用，保存 AppID 与 AppSecret
5. 给应用配置**每日配额**和 **IP 白名单** —— 这是防滥用的实际防线
6. 在「系统设置」里开启：强制卡密密文传输、响应体附带签名
7. 手动执行一次 `php artisan cardkey:backup` 确认备份可用

---

## 目录结构

```
cardkey/
├── app/
│   ├── Filament/            后台页面、资源、表单、表格、统计组件
│   ├── Http/
│   │   ├── Controllers/Api/ 对外 API 控制器
│   │   └── Middleware/      签名校验、限流
│   ├── Models/              应用、批次、卡密、日志、设置
│   ├── Services/            卡密领域服务、系统设置服务
│   └── Support/             签名、卡密编码、传输加密
├── config/cardkey.php       协议参数与可配置项定义
├── database/migrations/     数据表结构
├── docs/                    API 文档与跨语言客户端模板
├── public/
│   ├── index.php            入口文件
│   └── install.php          安装向导（装完删除）
├── routes/
│   ├── api.php              五个 API 端点
│   └── console.php          定时清理与备份任务
└── 卡密验证模板/             Android 客户端模板（C++）
```

---

## API 概览

五个端点，全部为 `POST`，都需要签名头：

| 端点 | 作用 |
| --- | --- |
| `/api/v1/verify` | 校验卡密（会触发设备绑定） |
| `/api/v1/activate` | 激活卡密（时间卡开始计时） |
| `/api/v1/consume` | 扣减次数（仅次数卡） |
| `/api/v1/query` | 查询卡密状态 |
| `/api/v1/unbind` | 解绑设备 |

请求头：

```
X-App-Id: <AppID>
X-Timestamp: <Unix 秒>
X-Nonce: <随机数>
X-Signature-Version: v1
X-Signature: <HMAC-SHA256 小写十六进制>
```

签名规范：

```
canonical = METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256_HEX(raw_body)
X-Signature = HEX(HMAC-SHA256(AppSecret, canonical))
```

完整文档见 `docs/API.md`，跨语言客户端模板见 `docs/templates/` 与 `卡密验证模板/`。

---

## 常用命令

```bash
# 清理所有缓存
php artisan optimize:clear

# 生成生产缓存
php artisan optimize

# 手动执行备份
php artisan cardkey:backup

# 手动同步卡密状态
php artisan cardkey:sync-card-status

# 查看路由
php artisan route:list --path=api
```

**修改代码或配置后**，需要执行 `php artisan optimize:clear` 再 `php artisan optimize`，
否则可能读到旧缓存。

---

## 安全建议

- 生产环境 `APP_DEBUG` 必须为 `false`
- 网站目录必须指向 `public/`
- 安装完成后删除 `install.php`
- 定期备份 `.env` 与数据库
- 为每个应用配置独立的每日配额与 IP 白名单
- 定期在后台轮换 AppSecret

---

## 已知限制

以下设置项在后台「系统设置」中可改，但**当前版本尚未接线到运行时代码**，
不要依赖它们做安全加固：

- `security.force_https` —— HTTPS 重定向请在 Nginx 层面配置
- `security.session_idle_minutes` —— 会话空闲超时未生效
- `security.max_login_attempts` / `security.lockout_minutes` —— 登录失败锁定未生效
- `api.trusted_proxies` —— 反向代理真实 IP 识别未生效

如果部署在 CDN 或反向代理之后，需要在 `bootstrap/app.php` 中手动配置
`trustProxies` 中间件，否则 IP 白名单和限流会基于代理 IP 判断。
