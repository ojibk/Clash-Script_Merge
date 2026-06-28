/**
 * Clash-Script 全局扩展脚本 · 基于哨兵标记的规则幂等注入 v260628
 * 功能：白名单放行特定 AI 服务（Firefly）+ 拦截广告/遥测/激活域名，Hosts DNS 覆写，TLS 指纹注入等。
 * 使用：调整顶部配置区开关，在对应数组中增删域名，保存后重载订阅即可生效。
 */

function main(config) {
    const _startTime = Date.now();

    // ═══════════════ 配置区（按需调整） ═══════════════
    const ENABLE_SCRIPT       = true;            // 脚本总开关
    const ENABLE_BLOCK        = true;            // 拦截模块
    const ENABLE_FIREFLY      = true;            // Firefly 放行（需 ENABLE_BLOCK=true）
    const ENABLE_PROCESS_RULE = true;            // 进程规则（需 TUN + 管理员权限）
    const ENABLE_PROXY        = true;            // 代理模块
    const ENABLE_AGGRESSIVE   = false;           // 激进阻断（谨慎开启）
    const ENABLE_GLOBAL_KEYWORD_BLOCK = false;   // 全局关键词阻断（极度激进）
    const ENABLE_DIRECT          = true;         // 直连模块
    const ENABLE_HOSTS_OVERRIDE  = true;         // Hosts DNS 覆写
    const HOSTS_MODE = "ipv4-loopback";          // 模式: ipv4-loopback | ipv4-blackhole | dual-loopback | dual-blackhole
    const DEBUG_FAKEIPFILTER_CLEANUP = false;    // 检查 fake-ip-filter 中是否残留已废弃的历史托管域名（调试用）
    const ENABLE_CLIENT_FINGERPRINT = true;      // TLS 指纹注入开关（为代理节点批量添加 client-fingerprint）
    const DEFAULT_FINGERPRINT = "chrome";        // TLS 指纹预设
    const FINGERPRINT_SKIP = [];                 // 指纹跳过名单：节点名含这些关键词则不注入指纹
    const fireflyUseProxy = ENABLE_FIREFLY && ENABLE_BLOCK;  // 派生开关：决定 Firefly 规则的路由目标与动作（allow层代理 vs block层拦截）

    // ═══════════════ 防御性检查 ═══════════════
    if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw new Error("[Script] 非法 config");
    }
    if (!Array.isArray(config.rules))           config.rules = [];
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];

    if (ENABLE_FIREFLY && !ENABLE_BLOCK) console.warn("⚠️ Firefly 放行需 ENABLE_BLOCK=true");
    if (ENABLE_PROCESS_RULE && config["find-process-mode"] !== "strict" && config["find-process-mode"] !== "always") {
        console.warn(`⚠️ 进程规则要求 find-process-mode=strict/always，当前 [${config["find-process-mode"] ?? "未设置"}]`);
    }

    // ═══════════════ 无条件清理遗留调试标记 ═══════════════
    config.rules = config.rules.filter(r => r !== "DOMAIN,debug-script-disabled.marker.invalid,REJECT");

    // ═══════════════ 哨兵幂等清理 ═══════════════
    const _SENTINEL_START = "DOMAIN,START-rule-injection-sentinel.invalid,REJECT";
    const _SENTINEL_END   = "DOMAIN,END-rule-injection-sentinel.invalid,REJECT";
    {
        const newRules = [], _blockStartLengths = [];
        let _orphanEndCount = 0;
        for (const rule of config.rules) {
            if (rule === _SENTINEL_START) { _blockStartLengths.push(newRules.length); continue; }
            if (rule === _SENTINEL_END) {
                if (_blockStartLengths.length) newRules.length = _blockStartLengths.pop();
                else _orphanEndCount++;
                continue;
            }
            newRules.push(rule);
        }
        if (_blockStartLengths.length) console.warn(`⚠️ ${_blockStartLengths.length} 个未闭合哨兵块`);
        if (_orphanEndCount) console.warn(`⚠️ ${_orphanEndCount} 个孤立 END`);
        config.rules = newRules;
    }

    // ═══════════════ 脚本总开关与禁用标记逻辑 ═══════════════
    if (!ENABLE_SCRIPT) {
        config.rules.unshift("DOMAIN,debug-script-disabled.marker.invalid,REJECT");
        return config;
    }

    // ═══════════════ 时间戳 ═══════════════
    const _now = new Date();
    console.log("=".repeat(28));
    const _ts = [_now.getHours(), _now.getMinutes(), _now.getSeconds()]
        .map(n => String(n).padStart(2, "0")).join(":");
    console.log(`📊 配置注入开始 [${_ts}]`);
    console.log("=".repeat(28));
    
    // ═══════════════ client-fingerprint 注入 ═══════════════
    if (!ENABLE_CLIENT_FINGERPRINT) {
        console.log("ℹ️ TLS 指纹注入已禁用");
    } else if (DEFAULT_FINGERPRINT === "none") {
        console.log("ℹ️ TLS 指纹开关已开启，但指纹值配置为 'none'，等同禁用，跳过注入");
    } else if (!Array.isArray(config.proxies)) {
        console.log("ℹ️ config.proxies 不是数组，跳过指纹注入");
    } else {
        const _VALID = new Set(["chrome","firefox","safari","iOS","android","edge","360","qq","random","none"]);
        let _rawFP;
        if (_VALID.has(DEFAULT_FINGERPRINT)) {
            _rawFP = DEFAULT_FINGERPRINT;
        } else {
            console.warn(`⚠️ 无效指纹 "${DEFAULT_FINGERPRINT}"，降级为 "none"`);
            _rawFP = "none";
        }

        // random = 每次重载配置触发随机指纹，概率：Chrome 50%，Safari 25%，iOS ≈16.7%（1/6），Firefox ≈8.3%（1/12）
        const _effectiveFP = _rawFP === "random"
            ? (() => {
                const rand = Math.random();
                if (rand < 0.50) return "chrome";
                if (rand < 0.75) return "safari";
                if (rand < 11/12) return "iOS";
                return "firefox";
              })()
            : _rawFP;

        if (_effectiveFP === "none") {
            console.log("ℹ️ TLS 指纹注入因配置无效已降级为 'none'，跳过");
        } else {
            if (_rawFP === "random") console.log(`💡 本次加载已从 random 解析为: ${_effectiveFP}`);
            const _skipKw = [], _skipRe = [];
            for (const raw of FINGERPRINT_SKIP) {
                if (typeof raw !== "string" || !raw) continue;
                if (/\p{Unified_Ideograph}/u.test(raw)) _skipKw.push(raw.toLowerCase());
                else _skipRe.push(new RegExp(`(^|[-_\\s（）()\\[\\]./])${raw.replace(/[-\\^$*+?.()|[\]{}]/g, '\\$&')}([-_\\s（）()\\[\\]./]|$)`, 'i'));
            }
            let inj = 0, skip = 0, exist = 0;
            config.proxies = config.proxies.map(p => {
                if (typeof p !== 'object' || !p) return p;
                if (Object.prototype.hasOwnProperty.call(p, 'client-fingerprint')) { exist++; return p; }
                const name = (p.name || "").toLowerCase();
                if (_skipKw.some(k => name.includes(k)) || _skipRe.some(r => r.test(p.name || ""))) { skip++; return p; }
                inj++;
                return { ...p, 'client-fingerprint': _effectiveFP };
            });
            console.log(`✅ TLS 指纹注入完成: 新增 ${inj}，跳过 ${skip}，已有 ${exist}； 指纹: ${_effectiveFP}`);
        }
    }

    // ═══════════════ 1. 识别代理策略组 ═══════════════
    let proxyGroupName = null;
    const EXCLUDED_NAMES = new Set(["DIRECT","REJECT","REJECT-DROP","COMPATIBLE","DEFAULT","MATCH","PASS"]);
    const FALLBACK_NAMES = new Set(["GLOBAL"]);
    const EXCLUDED_CN_RE = /^(?:全(?:部|网|球)|所有|默认)$|(?:直连|拒绝)/;
    const FALLBACK_CN_RE = /^全局$/;
    const VALID_PROXY_TYPES = new Set(["select","url-test","fallback","load-balance","smart"]);
    const NONROUTABLE_TYPES = new Set(["relay","url-latency-benchmark"]);

    // 运行时断言：FALLBACK_NAMES 与 EXCLUDED_NAMES 必须互斥
    {
        const _overlap = [...FALLBACK_NAMES].filter(n => EXCLUDED_NAMES.has(n));
        if (_overlap.length) {
            console.error(`❌ 配置断言失败：FALLBACK_NAMES ∩ EXCLUDED_NAMES 非空: ${_overlap.join(", ")}`);
            return config;
        }
    }
    // 运行时断言：FALLBACK_CN_RE 与 EXCLUDED_CN_RE 对"全局"必须互斥
    if (FALLBACK_CN_RE.test("全局") && EXCLUDED_CN_RE.test("全局")) {
        console.error(`❌ 配置断言失败："全局"同时匹配 FALLBACK_CN_RE 和 EXCLUDED_CN_RE`);
        return config;
    }

    const _SANITIZE_RE = /[\u0000-\u001F\u007F\u0085\u00AD\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/gu;
    const sanitizeName = n => (typeof n === "string" && n) ? n.replace(_SANITIZE_RE, '').trim() : "";
    const _isFallback = t => !!(t && (FALLBACK_NAMES.has(t.toUpperCase()) || FALLBACK_CN_RE.test(t)));
    const _isEligible = t => !!(t && (_isFallback(t) || (!EXCLUDED_NAMES.has(t.toUpperCase()) && !EXCLUDED_CN_RE.test(t))));

    if (config["proxy-groups"].length) {
        const _KW_RE = /节点(?:选择)?|手动选择|选节点|proxy|auto|自动|🚀|飞机|机场|线路|订阅|代理|选择/i;
        const prepped = config["proxy-groups"].map(g => {
            const clean = sanitizeName(g?.name);
            return { g, clean, fallback: _isFallback(clean), eligible: _isEligible(clean) };
        });

        // 多级降级识别
        let entry = prepped.find(e => e.eligible && !e.fallback && VALID_PROXY_TYPES.has(e.g?.type) &&
            (_KW_RE.test(e.clean) || (e.g?.["include-all"] === true || e.g?.["include-all"] === "true") || (Array.isArray(e.g?.proxies) && e.g.proxies.length > 3)));
        if (!entry) entry = prepped.find(e => e.eligible && !e.fallback && VALID_PROXY_TYPES.has(e.g?.type) && Array.isArray(e.g?.proxies) && e.g.proxies.length > 0);
        if (!entry) {
            entry = prepped.find(e => e.fallback && VALID_PROXY_TYPES.has(e.g?.type) && Array.isArray(e.g?.proxies) && e.g.proxies.length > 0);
            if (entry) console.warn(`⚠️ 降级使用兜底组 [${entry.g.name}]`);
        }
        if (!entry) {
            entry = prepped.find(e => e.eligible && !NONROUTABLE_TYPES.has(e.g?.type) && Array.isArray(e.g?.proxies) && e.g.proxies.length > 0);
            if (entry) console.warn(`🚨 最终容错选取 [${entry.g.name}]`);
        }

        if (entry?.g?.name) {
            if (entry.g.name !== entry.clean) { console.error(`❌ 代理组含不可见字符`); return config; }
            proxyGroupName = entry.g.name;
            console.log(`${entry.fallback ? "⚠️" : "✅"} 代理组: [${proxyGroupName}] (type: ${entry.g.type ?? "?"})`);
        } else {
            console.error("❌ 无可用代理组，中止注入");
            prepped.forEach(({ g, eligible, fallback }, idx) => {
                const status = !eligible ? "❌" : (fallback ? "⚠️" : "✅");
                console.log(`   ${idx + 1}. ${status} [${g?.name}] (${g?.type ?? "?"}, ${g?.proxies?.length ?? 0} 节点)`);
            });
            return config;
        }
    } else {
        console.error("❌ proxy-groups 为空，中止注入");
        return config;
    }

    // 代理组排除断言与 Token 断言
    {
        const s = sanitizeName(proxyGroupName);
        if (!s || EXCLUDED_NAMES.has(s.toUpperCase()) || EXCLUDED_CN_RE.test(s)) {
            console.error(`❌ 代理组排除断言触发：[${proxyGroupName}]`); return config;
        }
    }
    if (/[,\[\]{}\u0000-\u001F\u007F\u0085\u00AD\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/u.test(proxyGroupName)) {
        console.error(`❌ 代理组名含非法字符`); return config;
    }
    // 防御性校验：确保识别的代理组仍存在于原数组中（理论上因引用一致必然为真），此校验理论上不可达
    if (!config["proxy-groups"].some(g => g?.name === proxyGroupName)) {
        console.error(`❌ 代理组 [${proxyGroupName}] 不存在`); return config;
    }

    // ═══════════════ 2. 数据层 ═══════════════
    const pushSuffix  = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN-SUFFIX,${v},${a}`); });
    const pushDomain  = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN,${v},${a}`); });
    const pushKeyword = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN-KEYWORD,${v},${a}`); });

    // Firefly 专属域名的 TCP 限定规则：仅对 adobeFireflyOnly 中的域名生成 TCP 条件匹配，令这些域名的 UDP/QUIC 不经本层，
    // 交由 udpBlock 的 adobe.io/adobe.com 规则拦截，以 REJECT 快速失败强制回退 TCP。
    const pushFirefly = (d, a, p) => d.forEach(v => {
        if (typeof v === "string" && v) p.push(`AND,((NETWORK,TCP),(DOMAIN-SUFFIX,${v})),${a}`);
    });

    // ── Adobe 共用鉴权端点（包括 Firefly 和 CC） ──
    // 受控于 fireflyUseProxy = ENABLE_FIREFLY && ENABLE_BLOCK 两个开关，Firefly 启用时路由至代理组，Firefly 禁用时以 REJECT 拦截。
    // 此处走 pushSuffix（无协议限定），UDP 流量同样路由至代理组，不经 udpBlock 拦截——与 adobeFireflyOnly 的 TCP 限定行为不同。
    const adobeSharedDeps = [
        "ims-na1.adobelogin.com",                 // 登录令牌刷新
        "adobeid-na1.services.adobe.com",         // Adobe ID 服务
        "auth.services.adobe.com",                // Adobe ID 鉴权，Firefly Token 来源
        "cc-api-cp.adobe.io",                     // CC 权限校验，含 Firefly 订阅验证
        "cc-api-data.adobe.io",                   // CC 生成结果存储
        "lcs-roaming.adobe.io",                   // 离线许可验证 / Firefly 订阅状态同步
        "scdown.adobe.io",                        // 疑似 Firefly 依赖端点（无直接抓包证据；保守放行，误拦截导致功能异常的代价高于误放行风险）
    ];

    // ── Adobe 激活 / 遥测拦截 ──
    const adobeSuffix = [
        "adobestats.io",                          // 统计上报主域
        "activate.adobe.com",                     // 激活核心
        "lmlicenses.wip4.adobe.com",              // 许可证管理服务
        "prod.adobegenuine.com",                  // 正版完整性验证服务
        "na1e.services.adobe.com",                // Genuine 服务备用
        "crs.cr.adobe.com",                       // 许可证检查
        "adobesearch.adobe.io",                   // 搜索遥测
        "p13n.adobe.io",                          // 个性化遥测
        "ic.adobe.io",                            // 洞察收集器
        "lcs-mobile.adobe.io",                    // 新版 CC 移动端授权
        "adobe-dns.adobe.com",                    // Adobe 自有 DNS 服务
        "adobe-dns-2.adobe.com",                  // 同上，备用节点 2
        "adobe-dns-3.adobe.com",                  // 同上，备用节点 3
        "lm.licenses.adobe.com",                  // 许可证管理器
        "genuine.adobe.com",                      // 正版验证
        "oobesaas.adobe.com",                     // SaaS 授权验证服务
        "sstats.adobe.com",                       // 实时统计上报
        "entitlementauthz.adobe.com",             // 授权验证服务
        "assets.entitlement.adobe.com",           // 授权资产校验
        "telemetry.adobe.com",                    // 遥测入口
        "lcs-cops.adobe.io",                      // 云端授权策略端点
        // "adobedtm.com",                        // Adobe DTM 旧版遥测域，可能仍有旧版 CC 存量实例使用
        // "practivate.adobe.com",                   // 预激活服务。该域名可能已失效，待验证
    ];

    const _ADOBE_RAND_RE = "^[A-Za-z0-9]{8,12}\\.adobe\\.io$"; // 匹配随机8~12位字母/数字.adobe.io 子域
    // const _ADOBESTATS_RAND_RE = "^[A-Za-z0-9]{10}\\.adobestats\\.io$"; // 匹配随机10位字母/数字子域
    const adobeRegex = [
        `DOMAIN-REGEX,${_ADOBE_RAND_RE},REJECT`,
        // `DOMAIN-REGEX,${_ADOBESTATS_RAND_RE},REJECT`, // 已被 adobeSuffix 的 "adobestats.io" 覆盖
    ];

    // ── UDP / QUIC 拦截（强制回退 TCP）──
    // ⚠️ UDP 流量在 block 层已被 udpBlock 拦截（REJECT），因此 direct 层的 fonts/color 规则对 UDP 永远不可达；fonts/color 实际只走 TCP DIRECT。
    // 使用 REJECT 而非 REJECT-DROP，目的是让 QUIC 立即失败以加速回退 TCP，避免静默丢弃导致超时等待，拖慢 Firefly 等放行服务的首次连接速度。
    const udpBlock = [
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT",
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT",
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobelogin.com)),REJECT", // 防御性补全：Firefly 禁用时已由 SUFFIX 规则覆盖，Firefly 启用时 UDP 由 allow 层路由至代理组
        // "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT", // SUFFIX 规则的 adobestats.io（无协议条件）已覆盖所有协议，此处冗余
        // `AND,((NETWORK,UDP),(DOMAIN-REGEX,${_ADOBE_RAND_RE})),REJECT`, // 已有遮蔽规则，此处冗余覆盖
    ];

    // ── Adobe 遥测子域（wss 为子域名前缀，非协议标识）──
    const adobeWsDomain = ["wss.adobe.io"];

    // ── Firefly 生成式 AI 专属放行域名 ──
    // 注意：senseicore.adobe.io 与 senseimds.adobe.io 会被 _ADOBE_RAND_RE 规则（随机 8~12 位字母/数字的 adobe.io 子域）命中
    // 当前依赖 allow 层优先，以规避 block 层误匹配，若调整层序需确保这两个域名不被意外拦截。
    const adobeFireflyOnly = [
        "firefly.adobe.com",                      // Firefly 主服务入口
        "firefly.adobe.io",                       // Firefly API（.io 端点）
        "firefly-api.adobe.io",                   // PS 生成式填充调用入口
        "firefly-cliov2.adobe.com",               // Firefly Clio v2 模型接口
        "clio.adobe.io",                          // Clio 生成模型主接口
        "clio-prober.adobe.io",                   // Clio 功能可用性探针
        "clio-assets.adobe.com",                  // Clio 生成结果资源 CDN
        "senseicore.adobe.io",                    // Sensei AI 服务核心
        "senseimds.adobe.io",                     // Sensei 模型分发服务
    ];

    // ── CorelDRAW 全家桶激活拦截 ──
    const corelSuffix = [
        "activation.corel.com",                   // 激活验证入口
        "licensing.corel.com",                    // 许可证服务
        "license1.corel.com",                     // 许可证服务器 1
        "license2.corel.com",                     // 许可证服务器 2
        "mc.corel.com",                           // 会员验证
        "ipm.corel.com",                          // 产品内弹窗消息服务
        "ipm2.corel.com",                         // IPM 备用节点
        "telemetry.corel.com",                    // 统计上报
        "world.corel.com",                        // 消息推送 + 序列号黑名单检查
    ];

    // ── Autodesk (CAD / 3dsMax / Maya) 激活与遥测拦截 ──
    const autodeskSuffix = [
        "adlm.cloud.autodesk.com",               // 许可验证主域
        "adlm-autodesk.com",                     // ADLM 独立许可域
        "licensing-autodesk.com",                // 许可证服务备用域
        "api.entitlements.autodesk.com",         // 授权 API 接口
        "telemetry.autodesk.com",                // 遥测上报
        "usage.autodesk.com",                    // 使用统计上报
        "metric.autodesk.com",                   // 性能指标上报
        "crashreport.autodesk.com",              // 崩溃报告上传
        "dlm.autodesk.com",                      // 下载管理器版本检查
        "adsklicensing.com",                     // 许可服务独立域
        "clic.autodesk.com",                     // 核心授权验证
        "genuine-software.autodesk.com",         // 正版验证服务
        "edge.activity.autodesk.com",            // 活动/行为追踪
        "developer.api.autodesk.com",            // 开发者 API（含许可验证）
        "autodesk.com.edgekey.net",              // Akamai CDN 节点（推断含授权回源；拦截后可能影响下载等服务，但授权验证优先级更高）
        "crp.autodesk.com",                      // 云渲染授权
        "autodesk.flexnetoperations.com",        // FlexNet Operations 许可云平台
    ];
    const autodeskDomain = [
        "ipm-aem.autodesk.com",                  // 弹窗消息（精确匹配）
    ];
    const autodeskKeyword = [
        // "adlm",                                  // 桌面许可证模块关键词。⚠️ 4字符短串，存在极低概率误伤不相关含 adlm 子串的域名
        "telemetry.autodesk",                    // 遥测模块关键词兜底
        "entitlement.autodesk",                  // 授权模块关键词兜底
    ];

    // ── 非官方修改补丁后门 ──
    const BACKDOOR_BASE_DOMAINS = [
        "966v26.com",                            // 后门主域
        "vposy.com",                             // 知名非官方修改补丁作者域名
        "api.pzz.cn",                            // 国内后门回传接口
        // "cc-cdn.com",                         // 【待验证】命名形似 Adobe CC CDN，无抓包证据
    ];
    const backdoorSuffix = [...BACKDOOR_BASE_DOMAINS];
    const backdoorKeyword = ["966v26"];

    // ── IDM / Wondershare 等激活拦截 ──
    const idmSuffix = [
        "registeridm.com",                       // IDM 注册验证域
        // "internetdownloadmanager.com",        // ⚠️ 拦截主域误伤官网，改用下方精确子域
        "secure.internetdownloadmanager.com",    // 序列号验证接口
        "mirror.internetdownloadmanager.com",    // 更新镜像服务器
        "mirror2.internetdownloadmanager.com",   // 更新镜像服务器 2
        "mirror3.internetdownloadmanager.com",   // 更新镜像服务器 3
        "idm-patch.com",                         // 非官方修改补丁域
        "idm-update.com",                        // 非官方更新域
    ];
    const idmKeyword = ["tonec"];               // IDM 开发商品牌名
    const wondershareSuffix = [
        "activation.wondershare.com",             // Wondershare 激活验证入口
        "license.wondershare.com",                // 许可证验证服务
        "wondershare.cc",                         // 海外追踪/统计域
        "wondershare.cn",                         // 国内遥测/统计域
        // "iskysoft.com",                       // ⚠️ 主域即官网，无已知专用验证子域
        // "imyfone.com",                        // ⚠️ 主域即官网，无已知专用验证子域
    ];

    // ── 其他杂项软件授权验证 ──
    const miscSoftwareSuffix = [
        // "bandicam.com",                       // ⚠️ 主域误伤官网，改用下方精确子域
        // "bandisoft.com",                      // ⚠️ 主域误伤官网，改用下方精确子域
        // "xmind.app",                          // ⚠️ 主域误伤官网，改用下方精确子域
        // "xmind.net",                          // ⚠️ 主域误伤官网（XMind 8 下载/插件），改用下方精确子域
        // "listary.com",                        // ⚠️ 主域误伤官网，改用下方精确子域
    ];
    const miscSoftwareDomain = [
        "cert.bandicam.com",                      // Bandicam 正版证书验证
        "ssl.bandisoft.com",                      // Bandizip/Bandicam 授权验证
        "dl.bandisoft.com",                       // 更新下载/版本心跳
        "www.xmind.app",                          // XMind 2020+ 授权验证
        "www.xmind.net",                          // XMind 8 授权验证/更新检查
        "www.xmind.cn",                           // XMind 中文站授权验证
        "dl2.xmind.cn",                           // XMind 8 更新安装包 CDN
        "support.listary.com",                    // Listary 激活/授权验证
        "notifier.rarlab.com",                    // WinRAR 广告弹窗/试用到期通知
        "license.typora.io",                      // Typora 授权验证
        "verify.typora.io",                       // Typora 激活校验
    ];

    // ── 微软 & Office 遥测 ──
    const msTelemSuffix = [
        "telemetry.microsoft.com",               // Windows/Office 遥测主域
        "nexus.officeapps.live.com",             // Office 遥测上报
        "officeclient.microsoft.com",            // Office 客户端统计
        "vortex.data.microsoft.com",             // Windows 错误报告
        "settings-win.data.microsoft.com",       // Windows 诊断数据上报
        "watson.telemetry.microsoft.com",        // Watson 崩溃报告服务
        // 注：当前精确匹配 v10/v20，若微软推出 v30 等新版本需手动添加。但若采用更通用的 DOMAIN-SUFFIX,events.data.microsoft.com 会覆盖未知子域。
        "v10.events.data.microsoft.com",         // Windows 诊断数据 v1.0
        "v20.events.data.microsoft.com",         // Windows 诊断数据 v2.0
    ];

    // ── 广告联盟、遥测、追踪、弹窗、强制更新 ──
    const adsSuffix = [
        // WPS
        "ups.k0s.gk.kingsoft.com",               // WPS 升级推送服务
        "pcfg.wps.cn",                           // WPS 配置/广告下发
        // "wps.com.cn",                            // WPS 保护性域名，未启用
        "wpsgold.wpscdn.cn",                     // WPS 广告资源 CDN
        // "sync.wps.cn",                        // ⚠️ WPS 云文档同步，拦截后云同步失效
        // 海康威视
        "upgrade.hikvision.com",                 // 海康固件升级检查
        "ezdns.hikvision.com",                   // 海康 DDNS 回传
        "cloudmsg.hikvision.com",                // 海康云消息推送
        // 向日葵/ToDesk
        "sunloginlog.oray.com",                  // 向日葵日志上报
        "report.oray.com",                       // 向日葵行为上报
        "log.todesk.com",                        // ToDesk 日志上报
        "report.todesk.com",                     // ToDesk 遥测上报
        // 输入法
        "shurufa.baidu.com",                     // 百度输入法云服务
        "input.baidu.com",                       // 百度输入法联网同步
        // "api.sogoucloud.com",                 // ⚠️ 搜狗输入法云端接口，待验证
        // Bugly
        "bugly.qq.com",                          // 腾讯 Bugly 崩溃上报 SDK
        "bugly.gtimg.com",                       // Bugly 静态资源 CDN
        // 字节系
        "log.snssdk.com",                        // 字节系客户端日志上报
        // "i.snssdk.com",                          // 字节跳动国内 SDK 主接口
        "log.byteoversea.com",                   // 字节跳动海外日志上报
        // 剪映
        "metrics.capcut.com",                    // 剪映遥测上报
        "log.capcut.com",                        // 剪映日志收集
        // QQ音乐/酷狗/酷我/网易云
        // "qqmusic.qq.com",                     // ⚠️ 待验证：可能是功能性主域，暂不拦截
        "stat.music.qq.com",                     // QQ音乐统计上报
        "log.kugou.com",                         // 酷狗日志上报
        "stat.kuwo.cn",                          // 酷我统计上报
        "log.music.163.com",                     // 网易云音乐日志上报
        // 哔哩哔哩
        "data.bilibili.com",                     // B站数据上报
        "api.log.bilibili.com",                  // B站日志接口
        // 小米/MIUI
        "stat.miui.com",                         // 小米统计 SDK
        "data.miui.com",                         // MIUI 数据采集
        "tracking.miui.com",                     // MIUI 行为追踪
        "logservice.miui.com",                   // MIUI 日志服务
        "sdkconfig.ad.xiaomi.com",               // 小米广告 SDK 配置
        // 钉钉/飞书
        "analytics.dingtalk.com",                // 钉钉遥测上报
        "log.feishu.cn",                         // 飞书日志上报
        // 迅雷
        "ad.xunlei.com",                         // 迅雷广告接口
        "etl.xl7.xunlei.com",                    // 迅雷 7 客户端事件遥测
        // 百度网盘
        "update.pan.baidu.com",                  // 百度网盘强制更新
        // 腾讯广告
        "e.qq.com",                              // 腾讯效果广告
        "gdt.qq.com",                            // 广点通广告联盟
        "l.qq.com",                              // 腾讯广告追踪链路
        "toptips.qq.com",                        // QQ 弹窗提示推送
        "minibrowser.qq.com",                    // QQ 内置迷你浏览器广告
        // 阿里/友盟
        "umeng.com",                             // 友盟统计 SDK 主域
        "umengcloud.com",                        // 友盟云端统计
        "alimama.com",                           // 阿里妈妈广告联盟
        "adashbc.ut.alibaba.com",                // 阿里广告投放接口
        "update.aliyun.com",                     // 阿里云客户端强制更新
        // 百度广告
        "pos.baidu.com",                         // 百度联盟广告投放
        "hm.baidu.com",                          // 百度统计打点域
        "cpro.baidu.com",                        // 百度内容推荐广告
        // 字节/穿山甲
        "pangle.io",                             // 穿山甲广告联盟
        "pangolin-sdk-toutiao.com",              // 穿山甲 SDK 上报
        "ad.toutiao.com",                        // 头条广告投放
        // 360
        "ad.360.cn",                             // 360 广告投放
        "adv.360.cn",                            // 360 广告系统备用
        "union.360.cn",                          // 360 广告联盟接入
        "stat.360.cn",                           // 360 统计遥测上报
        "log.360.cn",                            // 360 日志上传
        "push.360.cn",                           // 360 推送通知
        "notice.360.cn",                         // 360 弹窗通知
        "update.360.cn",                         // 360 强制更新推送
        "up.360.cn",                             // 360 升级服务
        "360safe.com",                           // 360 安全云端检测
        "360tp.com",                             // 360 推广/广告追踪
        "360kuai.com",                           // 360 快速通道广告
        "qhres.com",                             // 奇虎资源 CDN
        "qhstatic.com",                          // 奇虎静态资源
        "qhimg.com",                             // 奇虎图片 CDN
        "qhupdate.com",                          // 360 强制更新推送
        // 2345
        "2345.com",                              // 2345 导航/弹窗主域
        "2345.net",                              // 2345 备用域
        "2345p.com",                             // 2345 推广域
        "2345uns.com",                           // 2345 升级推送
        "50yc.com",                              // 2345 旗下游戏推广
        // 驱动人生/精灵
        "160.com",                               // 驱动人生关联广告域
        "updrv.com",                             // 驱动人生更新推送
        "drivergenius.com",                      // 驱动精灵遥测/推广
        // 鲁大师
        "lms.ludashi.com",                       // 鲁大师游戏盒广告
        // 金山毒霸
        "cmcm.com",                              // 猎豹移动广告联盟
        "ijinshan.com",                          // 金山猎豹旗下追踪域
        "duba.com",                              // 金山毒霸广告/弹窗
        // 搜狗
        "inte.sogou.com",                        // 搜狗整合服务遥测
        "theta.sogou.com",                       // 搜狗 A/B 测试上报
        "sogoucdn.com",                          // 搜狗 CDN（广告素材）
        "ie.sogou.com",                          // 搜狗 IE 插件推广
        "metasogou.com",                         // 搜狗元数据追踪
        "get.sogou.com",                         // 搜狗输入法收集并回传输入的数据。拦截后会影响账号同步、词库更新、问题反馈，但语音输入等其他功能可以正常使用
        // Flash/PotPlayer
        "flash.cn",                              // Flash 国内分发域
        "kakaocorp.com",                         // PotPlayer 母公司 Kakao 统计上报
        "p1-pc.daum.net",                        // PotPlayer 侧边栏广告
        "p2-pc.daum.net",                        // PotPlayer 侧边栏广告节点 2
        "p1-pc.pdk.daum.net",                    // PotPlayer 广告 CDN 节点
    ];
    const adDomain = [
        "pinyin.sogou.com",                      // 搜狗拼音输入法弹窗
        "news.sogou.com",                        // 搜狗新闻推送
        "toast.sogou.com",                       // 搜狗弹窗通知
        "timer.sogou.com",                       // 搜狗心跳/定时遥测
        "update.sogou.com",                      // 搜狗强制更新
        "config.sogou.com",                      // 搜狗远程配置下发
        "py.sogou.com",                          // 搜狗拼音云服务
        "snapshot.sogou.com",                    // 搜狗快照追踪
    ];

    // ── Mozilla / Firefox 遥测 ──
    const mozillaSuffix = [
        "telemetry.mozilla.org",                 // Firefox 遥测主域
        "experiments.mozilla.org",               // Firefox 实验性功能遥测
        "healthreport.mozilla.org",              // Firefox 健康报告上报
        "metrics.mozilla.com",                   // 指标统计
        "crash-stats.mozilla.com",               // Mozilla 崩溃报告
        // "detectportal.firefox.com",           // Firefox 网络连接检测，拦截后地址栏报错
    ];

    // ── Google / Chrome 隐私追踪 ──
    const googleTrackSuffix = [
        "google-analytics.com",                  // Google Analytics 主域
        "analytics.google.com",                  // Google Analytics API
        "googletagmanager.com",                  // Google Tag Manager
        "redirector.gvt1.com",                   // Google 更新/扩展下载重定向服务（非纯遥测，拦截可能影响更新）
        "optimizationguide-pa.googleapis.com",   // Chrome 优化提示遥测
    ];
    const googleTrackKeyword = ["safebrowsing.google"]; // Safe Browsing 接口（拦截后失去钓鱼防护）

    // ── YouTube 遥测 ──
    const youtubeSuffix = ["youtube-ui.l.google.com"];   // YouTube CDN 负载均衡域（非纯遥测，拦截可能影响画质自适应）
    const youtubeDomain = ["s.youtube.com"];             // 观看历史 + 遥测上报 + 广告追踪和日志
    const youtubeKeyword = []; // YouTube 内部 API，当前已禁用；启用方式：改为 ['youtubei.googleapis']

    // ── 全球主流广告联盟 ──
    const genericAdSuffix = [
        "doubleclick.net",                       // Google DoubleClick 广告网络
        "scorecardresearch.com",                 // comScore 受众测量
        "adnxs.com",                             // Xandr（AppNexus）程序化广告
        "criteo.com",                            // Criteo 个性化重定向广告
        "taboola.com",                           // Taboola 内容推荐广告
        "outbrain.com",                          // Outbrain 内容推荐广告
        "amazon-adsystem.com",                   // 亚马逊广告系统
        "mc.yandex.ru",                          // Yandex Metrica 用户行为统计
        "mc.yandex.com",                         // Yandex Metrica 备用域
    ];

    // ── 全局关键词兜底（默认关闭）──
    const globalKeyword = ["telemetry", "analytics", "stats", "metrics"];

    // ── 进程规则（需 TUN + 管理员权限）──
    // 注：规则中 REJECT-DROP（静默丢弃）用于让目标进程“感知不到”网络，REJECT（发送 TCP RST）用于让进程快速失败；选择依据是进程对网络超时的敏感度。
    const processBlockRules = [
        // "AND,((NETWORK,UDP),(DST-PORT,443),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP", // 仅 UDP 443
        // "AND,((NETWORK,UDP),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP", // 全部 UDP
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",        // Adobe 正版验证，全部 TCP + 全部 UDP，兜底未知激活域
        "PROCESS-NAME,AdskLicensingService.exe,REJECT-DROP", // Autodesk 许可验证
        "PROCESS-NAME,AdskAccess.exe,REJECT-DROP",           // Autodesk 访问控制
        "PROCESS-NAME,AdskIdentityManager.exe,REJECT-DROP",  // Autodesk 身份认证
        "PROCESS-NAME,CorelDRW.exe,REJECT-DROP",             // CorelDRAW
        // "PROCESS-NAME,AdobeIPCBroker.exe,REJECT-DROP",    // 进程间通信代理，副作用：可能影响 Ps/Ai 启动
        "PROCESS-NAME,360sd.exe,REJECT-DROP",                // 360 杀毒
        "PROCESS-NAME,360tray.exe,REJECT",                   // 360 系统托盘
        "PROCESS-NAME,2345Mini.exe,REJECT",                  // 2345 迷你窗口
        "PROCESS-NAME,2345Helper.exe,REJECT",                // 2345 后台辅助
        "PROCESS-NAME,SogouNews.exe,REJECT",                 // 搜狗新闻弹窗
        "PROCESS-NAME,Ludashi.exe,REJECT",                   // 鲁大师主程序
        "PROCESS-NAME,LDSGameBox.exe,REJECT",                // 鲁大师游戏盒
        "PROCESS-NAME,DTLocker.exe,REJECT",                  // 驱动人生锁屏弹窗
        "PROCESS-NAME,DriverGenius.exe,REJECT",              // 驱动精灵
        // "PROCESS-NAME,Wps.exe,REJECT",                    // ⚠️ 慎用：WPS 主进程，拦截后联网全失效
    ];
    const processProxyRules = [ // 进程代理（空占位）
        // `PROCESS-NAME,Telegram.exe,${proxyGroupName}`,
        // `PROCESS-NAME,Slack.exe,${proxyGroupName}`,
    ];
    const processDirectRules = [
        "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",              // 百度网盘
        "PROCESS-NAME,filezilla.exe,DIRECT",                 // FileZilla
    ];

    // ── 代理规则 ──
    const proxySuffixList = [
        "github.com",                             // GitHub
        "linkedin.com",                           // 领英
        "stock.adobe.com",                        // Adobe Stock（锁区）
        "behance.net",                            // Behance（锁区）
        "behance.adobe.com",                      // Behance Adobe 子域
        "copilot.microsoft.com",                  // Copilot AI
        "services.googleapis.cn",                 // 修复国行设备因使用 services.googleapis.cn 域名导致的 Google Play 下载应用时的「等待中…」问题
        // "openai.com",                             // OpenAI，按需取消注释
        // "gemini.google.com",                      // Gemini（⚠️ 与 google.com 须同策略组，IP 不同可能触发风控）
        // "store.steampowered.com",                 // Steam 商店
        // "steamcommunity.com",                     // Steam 社区
        // "steamstatic.com",                        // Steam 商店静态资源
    ];

    // ── 直连规则 ──
    const directRules = [
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",              // 微软主域
        "DOMAIN-SUFFIX,live.com,DIRECT",                   // 微软账户 / Hotmail
        "DOMAIN-SUFFIX,outlook.com,DIRECT",                // Outlook 邮件服务
        "DOMAIN-SUFFIX,onedrive.com,DIRECT",               // OneDrive 云存储
        "DOMAIN-SUFFIX,skype.com,DIRECT",                  // Skype 通信服务
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",        // Microsoft 365 身份认证
        "DOMAIN-SUFFIX,microsoftonline-p.com,DIRECT",      // Microsoft 365 认证备用域
        "DOMAIN-SUFFIX,msftauth.com,DIRECT",               // 微软统一身份验证
        "DOMAIN-SUFFIX,msftidentity.com,DIRECT",           // 微软身份服务
        "DOMAIN-SUFFIX,passport.net,DIRECT",               // 微软 Passport 认证（旧版）
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",          // Windows Update 更新服务
        "DOMAIN-SUFFIX,microsoftpersonalcontent.com,DIRECT", // 微软个人内容 CDN
        "DOMAIN-SUFFIX,msocsp.com,DIRECT",                 // 微软证书吊销列表 (OCSP)
        "DOMAIN-SUFFIX,msedge.net,DIRECT",                 // Microsoft Edge CDN/更新
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",        // NCSI 连通性探测（拦截后显示「无网络」）
        "DOMAIN-SUFFIX,msftncsi.com,DIRECT",               // NCSI 旧版探测域
        // Adobe 常用业务放行
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",            // Adobe Fonts 字体同步服务
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",            // Adobe Color 配色工具
        "DOMAIN,assets.adobe.com,DIRECT",                  // Adobe 静态资源 CDN（精确匹配以防无关子域被直连）
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",               // Autodesk 官网放行（下载/论坛）
        "DOMAIN-SUFFIX,corel.com,DIRECT",                  // Corel 官网放行
        "AND,((NETWORK,UDP),(DST-PORT,123)),DIRECT",       // NTP 时间同步（仅 TUN 模式有效）
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",           // Steam 根域直连（含下载 CDN 子域，满速）
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",           // Steam 游戏内容分发 CDN（满速下载）
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",            // Steam 联机对战后端
        "DOMAIN-SUFFIX,pixpinapp.com,DIRECT",              // 截图贴图工具
        "DOMAIN-SUFFIX,pixpin.cn,DIRECT",                  // 截图贴图工具
        "DOMAIN-SUFFIX,lanzou.com,DIRECT",                 // 蓝奏云主域
        "DOMAIN-SUFFIX,lanzoui.com,DIRECT",                // 蓝奏云备用域 1
        "DOMAIN-SUFFIX,lanzoux.com,DIRECT",                // 蓝奏云备用域 2
        // 可选扩展区
        "DOMAIN-SUFFIX,masuit.com,DIRECT",                 // 软件分享站 懒得勤快
        "DOMAIN-SUFFIX,masuit.net,DIRECT",                 // 软件分享站 懒得勤快 备用域1
        "DOMAIN-SUFFIX,masuit.org,DIRECT",                 // 软件分享站 懒得勤快 备用域2
        "DOMAIN-SUFFIX,423down.com,DIRECT",                // 知名绿色软件站
        "DOMAIN-SUFFIX,ghxi.com,DIRECT",                   // 果核剥壳（绿色软件站）
        "DOMAIN-SUFFIX,mpyit.com,DIRECT",                  // 殁漂遥软件分享站
        "DOMAIN-SUFFIX,apphot.cc,DIRECT",                  // App热（原心海e站）
        "DOMAIN-SUFFIX,25xianbao.com,DIRECT",              // 卡圈线报
        "DOMAIN-SUFFIX,dir28.com,DIRECT",                  // 羊毛活动
        // "DOMAIN-KEYWORD,amazon,DIRECT",                 // 亚马逊直连（⚠️ 覆盖 AWS，需代理时改用精确规则）
        // "DOMAIN-SUFFIX,tmall.hk,DIRECT",                // 淘宝 .hk 域，如被代理可能影响商品价格加载
    ];

    // ── 激进阻断规则（默认关闭）──
    const aggressiveRules = [
        // "DOMAIN-REGEX,^.+\\.adobe\\.io$,REJECT-DROP",     // ⚠️ 激进：所有 adobe.io 子域（已由 SUFFIX 超集覆盖）
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",                // ⚠️ 激进：adobe.io 裸域+全部子域
        "DOMAIN-SUFFIX,cclibraries-defaults-cdn.adobe.com,REJECT-DROP", // CC Libraries 默认资源 CDN（功能性端点，拦截后默认画笔/色板不可加载）
        // "DOMAIN-SUFFIX,workflowusercontent.com,REJECT-DROP", // 多平台共用域，建议审查后启用
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",              // ⚠️ 激进：Office CDN
        "DOMAIN,geo.adobe.com,REJECT-DROP",                  // ⚠️ 激进：Adobe 地理区域识别
        "DOMAIN,geo2.adobe.com,REJECT-DROP",                 // ⚠️ 激进：Adobe 地理区域识别备用
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",   // ⚠️ 激进：Autodesk 账户登录
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP",         // ⚠️ 激进：IE 内核在线检测 / 旧版 Office 激活
        // "DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP",// ⚠️ 激进：Autodesk 授权端点；被 autodeskKeyword 层规则遮蔽
    ];

    // ═══════════════ 3. 规则组装与注入 ═══════════════
    try {
        const LAYER_ORDER = Object.freeze(["allow","block","process","proxy","aggressive","direct"]);
        const layerPools = { allow:[], block:[], process:[], proxy:[], aggressive:[], direct:[] };
        const _orderSet = new Set(LAYER_ORDER);
        for (const k of LAYER_ORDER) if (!(k in layerPools)) throw new Error(`[Script] LAYER_ORDER 键 '${k}' 不在 layerPools 中`);
        for (const k of Object.keys(layerPools)) if (!_orderSet.has(k)) throw new Error(`[Script] layerPools 键 '${k}' 不在 LAYER_ORDER 中`);
        const pushLayer = (l, r) => {
            if (!(l in layerPools)) throw new Error(`[Script] 未知层 '${l}'，请检查 layerPools 键名`);
            for (const x of r) layerPools[l].push(x);
        };

        if (ENABLE_BLOCK) {
            // 放行模式下注入 allow 层（先于 block 匹配），拦截模式下注入 block 层
            const [act, pool] = fireflyUseProxy ? [proxyGroupName, layerPools.allow] : ["REJECT", layerPools.block];
            pushSuffix(adobeSharedDeps, act, pool);
            pushFirefly(adobeFireflyOnly, act, pool);
            pushSuffix(adobeSuffix, "REJECT", layerPools.block);
            pushLayer("block", adobeRegex);
            pushLayer("block", udpBlock);
            pushDomain(adobeWsDomain, "REJECT", layerPools.block);
            pushSuffix(corelSuffix, "REJECT", layerPools.block);
            pushSuffix(autodeskSuffix, "REJECT", layerPools.block);
            pushDomain(autodeskDomain, "REJECT", layerPools.block);
            pushKeyword(autodeskKeyword, "REJECT", layerPools.block);
            pushSuffix(backdoorSuffix, "REJECT-DROP", layerPools.block);
            pushKeyword(backdoorKeyword, "REJECT-DROP", layerPools.block);
            pushSuffix(idmSuffix, "REJECT", layerPools.block);
            pushKeyword(idmKeyword, "REJECT", layerPools.block);
            pushSuffix(wondershareSuffix, "REJECT", layerPools.block);
            pushSuffix(miscSoftwareSuffix, "REJECT", layerPools.block);
            pushDomain(miscSoftwareDomain, "REJECT", layerPools.block);
            pushSuffix(msTelemSuffix, "REJECT", layerPools.block);
            pushSuffix(adsSuffix, "REJECT", layerPools.block);
            pushDomain(adDomain, "REJECT", layerPools.block);
            pushSuffix(mozillaSuffix, "REJECT", layerPools.block);
            pushSuffix(googleTrackSuffix, "REJECT", layerPools.block);
            pushKeyword(googleTrackKeyword, "REJECT", layerPools.block);
            pushSuffix(youtubeSuffix, "REJECT", layerPools.block);
            pushDomain(youtubeDomain, "REJECT", layerPools.block);
            pushKeyword(youtubeKeyword, "REJECT", layerPools.block); // 与 youtubeKeyword 数组联动，空数组即禁用
            pushSuffix(genericAdSuffix, "REJECT", layerPools.block);
            if (ENABLE_GLOBAL_KEYWORD_BLOCK) pushKeyword(globalKeyword, "REJECT", layerPools.block);
        }
        if (ENABLE_PROCESS_RULE) {
            pushLayer("process", processBlockRules);
            pushLayer("process", processProxyRules);
            pushLayer("process", processDirectRules);
        }
        if (ENABLE_PROXY) pushSuffix(proxySuffixList, proxyGroupName, layerPools.proxy);
        if (ENABLE_AGGRESSIVE) pushLayer("aggressive", aggressiveRules);
        if (ENABLE_DIRECT) pushLayer("direct", directRules);

        const finalPool = [_SENTINEL_START];
        for (const k of LAYER_ORDER) for (const r of layerPools[k]) finalPool.push(r);
        finalPool.push(_SENTINEL_END);
        config.rules = finalPool.concat(config.rules);

        console.log("=".repeat(28));
        console.log("✅ 规则注入成功");
        console.log(`   脚本状态: ✅ 已启用`);
        console.log(`   拦截模块: ${ENABLE_BLOCK ? "✅" : "❌"}`);
        if (ENABLE_FIREFLY) {
            console.log(`   Firefly 放行: ${fireflyUseProxy ? `✅ (allow 层，走 ${proxyGroupName})` : "❌ (ENABLE_BLOCK=false，拦截模块未启用)"}`);
        } else {
            console.log(`   Firefly 放行: ❌`);
        }
        console.log(`   进程规则: ${ENABLE_PROCESS_RULE ? "✅ (需管理员权限+TUN)" : "❌"}`);
        console.log(`   代理规则: ${ENABLE_PROXY ? "✅" : "❌"}`);
        if (ENABLE_AGGRESSIVE) {
            console.warn(`   激进阻断: ⚠️ 已开启`);
            console.warn(`   ⚠️ 激进阻断可能导致以下服务不可用：`);
            console.warn(`      adobe.io（CC 插件/API 端点，Firefly 域名已由 allow 层处理）、accounts.autodesk.com（Autodesk 账户登录）、`);
            console.warn(`      geo.adobe.com / geo2.adobe.com（Adobe 地理区域识别）、`);
            console.warn(`      officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA）`);
        } else {
            console.log(`   激进阻断: ❌`);
        }
        if (ENABLE_GLOBAL_KEYWORD_BLOCK)
            console.warn(`   全局关键词阻断: ⚠️ 已开启 (含: ${globalKeyword.join(", ")})`);
        else
            console.log(`   全局关键词阻断: ❌`);
        console.log(`   直连规则: ${ENABLE_DIRECT ? "✅" : "❌"}`);
        console.log(`   Hosts 覆写: ${ENABLE_HOSTS_OVERRIDE ? "✅ [" + HOSTS_MODE + "]" : "❌"}`);
        console.warn("⚠️ [udpBlock] 所有 UDP 规则依赖域名识别（Fake-IP / Sniffer），ECH 下可能全部失效。");
        console.log(`   ▶ 注入规则条目分层统计:`);
        const _LAYER_LABELS = { allow:"白名单/优先层", block:"拦截层", process:"进程层", proxy:"代理层", aggressive:"激进层", direct:"直连层" };
        for (const k of LAYER_ORDER) {
            console.log(`      - ${_LAYER_LABELS[k]} (${k})  : ${layerPools[k].length} 条`);
        }
        console.log(`   注入规则数: ${finalPool.length} 条（含首尾哨兵）`);
        console.log(`   总规则数: ${config.rules.length} 条`);
        // console.log(`   脚本执行耗时: ${Date.now() - _startTime} ms（含指纹注入，不含 Hosts 覆写）`);
        console.log("=".repeat(28));
    } catch (err) {
        console.error("❌ 规则注入异常，继续执行 Hosts:", err);
    }

    // ═══════════════ 4. Hosts DNS 覆写 ═══════════════
    if (ENABLE_HOSTS_OVERRIDE) {
        try {
            const modeMap = { "ipv4-loopback":"127.0.0.1", "ipv4-blackhole":"0.0.0.0", "dual-loopback":["127.0.0.1","::1"], "dual-blackhole":["0.0.0.0","::"] };
            const target = modeMap[HOSTS_MODE];
            if (!target) throw new Error(`未知 HOSTS_MODE: ${HOSTS_MODE}`);

            const hijackDomains = BACKDOOR_BASE_DOMAINS.map(d => `+.${d}`);
            const customHosts = Object.fromEntries(hijackDomains.map(d => [d, target]));
            const ensureObj = v => (typeof v === "object" && v !== null && !Array.isArray(v)) ? v : {};

            // 注入顶层 hosts（与 dns 状态无关）
            config.hosts = { ...ensureObj(config.hosts), ...customHosts };

            // 检查 dns 对象合法性
            let _dnsValid = false;
            if (config.dns == null) {
                config.dns = {};
            }
            if (typeof config.dns === "object" && !Array.isArray(config.dns)) {
                config.dns.hosts = { ...ensureObj(config.dns.hosts), ...customHosts };
                _dnsValid = true;
            } else {
                console.warn("⚠️ config.dns 类型异常，已写入顶层 hosts，跳过 dns.hosts 注入");
            }

            // 仅当 dns 对象合法时维护 fake-ip-filter
            if (_dnsValid) {
                if (!Array.isArray(config.dns["fake-ip-filter"])) {
                    config.dns["fake-ip-filter"] = [];
                }

                const currentManaged = new Set(BACKDOOR_BASE_DOMAINS.flatMap(d => [`+.${d}`, d, `*.${d}`]).map(s => s.toLowerCase()));
                // 确认订阅中已无这些条目后可安全删除
                const LEGACY_CLEANUP_ENTRIES = ["api.966v26.com","status.966v26.com","+.cc-cdn.com","cc-cdn.com","*.cc-cdn.com"];
                const scriptManaged = new Set([...currentManaged, ...LEGACY_CLEANUP_ENTRIES.map(s => s.toLowerCase())]);

                if (DEBUG_FAKEIPFILTER_CLEANUP) {
                    const redundant = LEGACY_CLEANUP_ENTRIES.filter(e => currentManaged.has(e.toLowerCase()));
                    if (redundant.length) console.warn("⚠️ 历史托管域名中存在仍属当前活跃集合的冗余条目，建议清理:", redundant);
                }

                const existing = new Set(), cleaned = [];
                let cleanedCount = 0;
                for (const e of config.dns["fake-ip-filter"]) {
                    const s = (typeof e === "string" ? e.trim() : "").toLowerCase();
                    if (!s) continue;
                    if (scriptManaged.has(s)) { cleanedCount++; continue; }
                    if (existing.has(s)) continue;
                    existing.add(s); cleaned.push(e);
                }
                const newEntries = hijackDomains.filter(d => !existing.has(d.toLowerCase())).sort();
                config.dns["fake-ip-filter"] = [...cleaned, ...newEntries];

                console.warn("⚠️ Hosts DNS 覆写需在 CVR 开启「启用 DNS」和「使用 Hosts」才生效");
                console.log("💡 脚本无法检测 UI 层开关状态；未开启时仍打印写入完成日志");
                const targetStr = Array.isArray(target) ? target.join(" / ") : target;
                console.log(`🛡️ Hosts DNS 覆写已写入: ${hijackDomains.length} 条，模式: [${HOSTS_MODE}] → ${targetStr}，但需 CVR 开启相关开关才能生效。`);
                console.log(`   fake-ip-filter 清理旧条目: ${cleanedCount} 条，新增注入: ${newEntries.length} 条（订阅原有非脚本条目共 ${existing.size} 条）`);
            } else {
                console.warn("⚠️ config.dns 类型异常，跳过 fake-ip-filter 维护");
            }
        } catch (err) {
            console.error("❌ Hosts DNS 覆写失败:", err);
        }
    }

    console.log(`   脚本执行总耗时: ${Date.now() - _startTime} ms（含指纹和规则注入及 Hosts 覆写）`);

    return config;
}
