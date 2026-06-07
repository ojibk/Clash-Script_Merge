/**
 *   Clash-Script 全局扩展脚本 · 基于哨兵标记的规则幂等清理与注入（Firefly 精确豁免版）
 * 
 *   - 智能识别代理策略组（多级降级）
 *   - 注入拦截/代理/直连/进程规则
 *   - Hosts DNS 覆写（四种模式）
 *   - 哨兵幂等清理（栈重建算法）
 *   - client-fingerprint 注入
 */
function main(config) {
    const _startTime = Date.now();

    // ⚙️ 配置区
    const ENABLE_SCRIPT       = true;            // 总开关
    const ENABLE_BLOCK        = true;            // 拦截模块
    const ENABLE_FIREFLY      = true;            // 精确放行 Adobe Firefly AI（需 ENABLE_BLOCK=true）
    const ENABLE_PROCESS_RULE = true;            // 进程规则（需 TUN + 管理员权限）
    const ENABLE_PROXY        = true;            // 指定域名代理模块
    const ENABLE_AGGRESSIVE   = false;           // 激进阻断（⚠️ 影响官网/插件商店）
    const ENABLE_GLOBAL_KEYWORD_BLOCK = false;   // 关键词全局阻断（⚠️ 极度激进）
    const ENABLE_DIRECT          = true;         // 指定域名直连模块
    const ENABLE_HOSTS_OVERRIDE  = true;         // Hosts DNS 覆写（需 CVR 开启“使用 Hosts”）
    // Hosts 模式：ipv4-loopback / ipv4-blackhole / dual-loopback / dual-blackhole
    const HOSTS_MODE = "ipv4-loopback";
    const ENABLE_MAINTENANCE_CHECKS = false;     // fake-ip-filter 历史集合维护检查
    const ENABLE_CLIENT_FINGERPRINT = true;      // TLS 指纹注入
    const DEFAULT_FINGERPRINT = "chrome";        // chrome/firefox/safari/iOS/android/edge/360/qq/random/none
    const FINGERPRINT_SKIP = [];                 // 指纹注入跳过关键词（含中文用子串匹配）

    const isFireflyActive = ENABLE_FIREFLY && ENABLE_BLOCK;

    // ═════════════ 防御性检查 ═════════════
    if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw new Error("[Script] 收到非法 config，终止执行");
    }
    if (!Array.isArray(config.rules))           config.rules = [];
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];

    if (ENABLE_FIREFLY && !ENABLE_BLOCK) {
        console.warn("⚠️ Firefly 放行需同时启用拦截模块，当前已自动降级");
    }
    if (ENABLE_PROCESS_RULE && config["find-process-mode"] !== "strict" && config["find-process-mode"] !== "always") {
        console.warn(`⚠️ 进程规则要求 find-process-mode 为 strict 或 always，当前可能失效`);
    }

    // ═════════════ 哨兵幂等清理（栈重建，O(N)） ═════════════
    const _SENTINEL_START = "DOMAIN,START-rule-injection-sentinel.invalid,REJECT";
    const _SENTINEL_END   = "DOMAIN,END-rule-injection-sentinel.invalid,REJECT";
    {
        const newRules = [];
        const stack    = [];
        for (const rule of config.rules) {
            if (rule === _SENTINEL_START) {
                stack.push(newRules.length);
                continue;
            }
            if (rule === _SENTINEL_END) {
                if (stack.length > 0) {
                    newRules.length = stack.pop();
                }
                continue;
            }
            newRules.push(rule);
        }
        config.rules = newRules;
    }

    if (!ENABLE_SCRIPT) {
        config.rules = config.rules.filter(r => r !== "DOMAIN,debug-script-disabled.marker.invalid,REJECT");
        config.rules.unshift("DOMAIN,debug-script-disabled.marker.invalid,REJECT");
        return config;
    }

    console.log("=".repeat(28));
    const _now = new Date();
    const _ts = [_now.getHours(), _now.getMinutes(), _now.getSeconds()]
        .map(n => String(n).padStart(2, "0"))
        .join(":");
    console.log(`📊 节点与规则链清洗开始 [${_ts}]`);
    console.log("=".repeat(28));

    // ═════════ client-fingerprint 注入 ═════════
    if (!ENABLE_CLIENT_FINGERPRINT) {
        console.log("ℹ️ TLS 指纹注入已禁用");
    } else if (DEFAULT_FINGERPRINT === "none") {
        console.log("ℹ️ TLS 指纹注入已启用，但默认指纹为 'none'，不执行注入");
    } else if (!Array.isArray(config.proxies)) {
        console.log("ℹ️ config.proxies 不是数组，跳过指纹注入");
    } else {
        const _VALID_FINGERPRINTS = new Set(["chrome", "firefox", "safari", "iOS", "android", "edge", "360", "qq", "random", "none"]);
        const _rawFP = _VALID_FINGERPRINTS.has(DEFAULT_FINGERPRINT)
            ? DEFAULT_FINGERPRINT
            : (console.warn(`⚠️ 无效指纹 "${DEFAULT_FINGERPRINT}"，降级为 "none"`), "none");

        const _effectiveFP = _rawFP === "random"
            ? (() => {
                const rand = Math.random();
                if (rand < 0.50) return "chrome";
                if (rand < 0.75) return "safari";
                if (rand < 0.917) return "iOS";
                return "firefox";
              })()
            : _rawFP;

        if (_effectiveFP === "none") {
            console.log("ℹ️ 指纹注入已降级为 'none'");
        } else {
            if (_rawFP === "random") console.log(`💡 随机指纹解析为: ${_effectiveFP}`);
            const _skipKeywords = [];
            const _skipRegexes  = [];
            for (const raw of FINGERPRINT_SKIP) {
                if (typeof raw !== "string" || !raw) { console.warn("跳过非法 SKIP 条目:", raw); continue; }
                if (/\p{Unified_Ideograph}/u.test(raw)) {
                    _skipKeywords.push(raw.toLowerCase());
                } else {
                    const escaped = raw.replace(/[-\\^$*+?.()|[\]{}]/g, '\\$&');
                    _skipRegexes.push(new RegExp(`(^|[-_\\s（）()\\[\\]./])${escaped}([-_\\s（）()\\[\\]./]|$)`, 'i'));
                }
            }
            let injectedCount = 0, skippedCount = 0, preExistingCount = 0;
            config.proxies = config.proxies.map(p => {
                if (typeof p !== 'object' || p === null) return p;
                if (Object.prototype.hasOwnProperty.call(p, 'client-fingerprint')) { preExistingCount++; return p; }
                const nodeName = p.name || "";
                const nodeNameLower = nodeName.toLowerCase();
                if (_skipKeywords.some(kw => nodeNameLower.includes(kw)) || _skipRegexes.some(regex => regex.test(nodeName))) {
                    skippedCount++; return p;
                }
                injectedCount++;
                return { ...p, 'client-fingerprint': _effectiveFP };
            });
            console.log(`✅ 指纹注入: 新增 ${injectedCount}，跳过 ${skippedCount}，维持 ${preExistingCount} (指纹: ${_effectiveFP})`);
        }
    }

    // ═════════ 1. 智能识别代理策略组 ═════════
    let proxyGroupName = null;
    const EXCLUDED_NAMES = new Set(["DIRECT","REJECT","COMPATIBLE","DEFAULT","MATCH","PASS"].map(s => s.toUpperCase()));
    const FALLBACK_NAMES = new Set(["GLOBAL"].map(s => s.toUpperCase()));
    {
        const _overlap = [...FALLBACK_NAMES].filter(n => EXCLUDED_NAMES.has(n));
        if (_overlap.length > 0) {
            console.error(`❌ FALLBACK ∩ EXCLUDED 非空: ${_overlap.join(", ")}，中止注入`);
            return config;
        }
    }
    const EXCLUDED_CN_RE = /^(?:全(?:部|网|用|球)|所有|默认)$|(?:直连|拒绝)/;
    const FALLBACK_CN_RE = /^全局$/;
    {
        if (FALLBACK_CN_RE.test("全局") && EXCLUDED_CN_RE.test("全局")) {
            console.error("❌ 兜底词互斥违反，中止注入"); return config;
        }
    }
    const VALID_PROXY_TYPES = new Set(["select", "url-test", "fallback", "load-balance", "smart"]);
    const _UNSUITABLE_TYPES = new Set(["relay", "url-latency-benchmark"]);
    const _SANITIZE_RE = /[\u0000-\u001F\u007F\u00AD\u061C\u200B-\u200F\u2028-\u202E\u2060\u2066-\u2069\uFEFF]/gu;
    function sanitizeName(name) {
        if (typeof name !== "string") return "";
        if (!name) return "";
        return name.replace(_SANITIZE_RE, '').trim();
    }
    function _isFallbackGroup(trimmed) {
        if (!trimmed) return false;
        if (FALLBACK_NAMES.has(trimmed.toUpperCase())) return true;
        return FALLBACK_CN_RE.test(trimmed);
    }
    function _isEligibleGroup(trimmed) {
        if (!trimmed) return false;
        if (_isFallbackGroup(trimmed)) return true;
        if (EXCLUDED_NAMES.has(trimmed.toUpperCase())) return false;
        if (EXCLUDED_CN_RE.test(trimmed)) return false;
        return true;
    }

    if (config["proxy-groups"].length > 0) {
        const _KW_RE = /节点(?:选择)?|手动选择|选节点|proxy|auto|自动|🚀|飞机|机场|线路|订阅/i;
        const _groupsPrepped = config["proxy-groups"].map(g => {
            const cleanName = sanitizeName(g?.name);
            return { g, cleanName, isFallback: _isFallbackGroup(cleanName), isEligible: _isEligibleGroup(cleanName) };
        });

        let _mainEntry = _groupsPrepped.find(({ g, cleanName, isFallback, isEligible }) => {
            if (!isEligible || isFallback) return false;
            const typeOk = VALID_PROXY_TYPES.has(g?.type);
            const nameMatch = _KW_RE.test(cleanName);
            const hasMany = Array.isArray(g?.proxies) && g.proxies.length > 3;
            const includeAll = g?.["include-all"] === true || g?.["include-all"] === "true";
            return typeOk && (nameMatch || includeAll || hasMany);
        });
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, cleanName, isFallback, isEligible }) =>
                isEligible && !isFallback &&
                /代理|节点|选择|Proxy/i.test(cleanName) &&
                VALID_PROXY_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 3
            );
        }
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, cleanName, isFallback, isEligible }) =>
                isEligible && !isFallback &&
                VALID_PROXY_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
        }
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, isFallback }) =>
                isFallback &&
                VALID_PROXY_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
            if (_mainEntry) console.warn(`⚠️ 未找到优选组，降级使用兜底组 [${_mainEntry.g.name}]`);
        }
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, isEligible }) =>
                isEligible &&
                !_UNSUITABLE_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
            if (_mainEntry) {
                console.warn("🚨 全部优选失败，触发最终容错选取");
                console.warn(`   选取首个可用组 [${_mainEntry.g.name}] (type: ${_mainEntry.g.type ?? "未知"})`);
            }
        }
        const mainGroup = _mainEntry?.g;
        if (mainGroup?.name) {
            proxyGroupName = mainGroup.name;
            const groupFlag = _mainEntry.isFallback ? "⚠️" : "✅";
            console.log(`${groupFlag} 代理组识别成功: [${proxyGroupName}] (type: ${mainGroup.type ?? "未知"})`);
        } else {
            console.error("❌ 无可用的代理组，中止注入");
            _groupsPrepped.forEach(({ g, isEligible, isFallback }, idx) => {
                const status = !isEligible ? "❌" : (isFallback ? "⚠️" : "✅");
                console.log(`   ${idx+1}. ${status} [${g?.name}] (${g?.type ?? "未知"}, ${g?.proxies?.length ?? 0} 节点)`);
            });
            return config;
        }
    } else {
        console.error("❌ proxy-groups 为空，中止注入");
        return config;
    }

    // 代理组排除断言
    {
        const _sanitizedProxy = sanitizeName(proxyGroupName);
        if (!_sanitizedProxy ||
            EXCLUDED_NAMES.has(_sanitizedProxy.toUpperCase()) ||
            EXCLUDED_CN_RE.test(_sanitizedProxy)) {
            console.error(`❌ 代理组排除断言触发: [${proxyGroupName}]，中止注入`);
            return config;
        }
    }
    // Token 断言
    if (/[,\[\]{}\u0000-\u001F\u007F\u0085\u200B-\u200F\u2060\u2066-\u2069\u2028-\u202E\uFEFF]/u.test(proxyGroupName)) {
        console.error(`❌ Token 断言触发: proxyGroupName 含非法字符，中止注入`);
        return config;
    }
    // 存在性断言
    if (!config["proxy-groups"].some(g => g?.name === proxyGroupName)) {
        console.error(`❌ 代理组 [${proxyGroupName}] 不存在，中止注入`);
        return config;
    }

    // ═════════ 2. 数据层 ═════════
    const pushSuffix  = (domains, action, pool) => domains.forEach(d => {
        if (typeof d === "string" && d.length > 0) pool.push(`DOMAIN-SUFFIX,${d},${action}`);
    });
    const pushDomain  = (domains, action, pool) => domains.forEach(d => {
        if (typeof d === "string" && d.length > 0) pool.push(`DOMAIN,${d},${action}`);
    });
    const pushKeyword = (words,   action, pool) => words.forEach(w => {
        if (typeof w === "string" && w.length > 0) pool.push(`DOMAIN-KEYWORD,${w},${action}`);
    });

    // Adobe 共用鉴权端点（Firefly 依赖，isFireflyActive 决定动作）
    const adobeSharedDeps = [
        "ims-na1.adobelogin.com", "adobeid-na1.services.adobe.com", "auth.services.adobe.com",
        "cc-api-cp.adobe.io", "cc-api-data.adobe.io", "lcs-roaming.adobe.io",
        "scdown.adobe.io"
    ];
    // Adobe 激活/遥测拦截
    const adobeSuffix = [
        "adobestats.io", "activate.adobe.com", "lmlicenses.wip4.adobe.com", "prod.adobegenuine.com",
        "na1e.services.adobe.com", "crs.cr.adobe.com", "cclibraries-defaults-cdn.adobe.com",
        "adobesearch.adobe.io", "p13n.adobe.io", "ic.adobe.io", "lcs-mobile.adobe.io",
        "adobe-dns.adobe.com", "adobe-dns-2.adobe.com", "adobe-dns-3.adobe.com",
        "practivate.adobe.com", "lm.licenses.adobe.com", "genuine.adobe.com",
        "oobesaas.adobe.com", "sstats.adobe.com", "entitlementauthz.adobe.com",
        "assets.entitlement.adobe.com", "telemetry.adobe.com", "lcs-cops.adobe.io"
    ];
    const _ADOBE_RAND_RE_STR      = "^[A-Za-z0-9]{8,12}\\.adobe\\.io$";
    const _ADOBESTATS_RAND_RE_STR = "^[A-Za-z0-9]{10}\\.adobestats\\.io$";
    const adobeRegex = [
        `DOMAIN-REGEX,${_ADOBE_RAND_RE_STR},REJECT`,
        `DOMAIN-REGEX,${_ADOBESTATS_RAND_RE_STR},REJECT`
    ];
    const adobeUdpBlock = [
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT",
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT",
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT",
        `AND,((NETWORK,UDP),(DOMAIN-REGEX,${_ADOBE_RAND_RE_STR})),REJECT`,
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-KEYWORD,adobe)),REJECT"
    ];
    const adobeWsDomain = ["wss.adobe.io"];
    const adobeFireflyOnly = [
        "firefly.adobe.com", "firefly.adobe.io", "firefly-api.adobe.io", "firefly-cliov2.adobe.com",
        "clio.adobe.io", "clio-prober.adobe.io", "clio-assets.adobe.com",
        "senseicore.adobe.io", "senseimds.adobe.io"
    ];
    const corelSuffix = [
        "activation.corel.com", "licensing.corel.com", "license1.corel.com", "license2.corel.com",
        "mc.corel.com", "ipm.corel.com", "ipm2.corel.com", "telemetry.corel.com", "world.corel.com"
    ];
    const autodeskSuffix = [
        "adlm.cloud.autodesk.com", "adlm-autodesk.com", "licensing-autodesk.com",
        "api.entitlements.autodesk.com", "telemetry.autodesk.com", "usage.autodesk.com",
        "metric.autodesk.com", "crashreport.autodesk.com", "dlm.autodesk.com", "adsklicensing.com",
        "clic.autodesk.com", "genuine-software.autodesk.com", "edge.activity.autodesk.com",
        "developer.api.autodesk.com", "autodesk.com.edgekey.net", "crp.autodesk.com",
        "autodesk.flexnetoperations.com"
    ];
    const autodeskDomain = ["ipm-aem.autodesk.com"];
    const autodeskKeyword = ["adlm", "telemetry.autodesk", "entitlement.autodesk"];
    const BACKDOOR_BASE_DOMAINS = ["966v26.com", "vposy.com", "api.pzz.cn"];
    const backdoorSuffix = [...BACKDOOR_BASE_DOMAINS];
    const backdoorKeyword = ["966v26"];
    const idmSuffix = [
        "registeridm.com", "secure.internetdownloadmanager.com", "mirror.internetdownloadmanager.com",
        "mirror2.internetdownloadmanager.com", "mirror3.internetdownloadmanager.com",
        "idm-patch.com", "idm-update.com"
    ];
    const idmKeyword = ["tonec"];
    const wondershareSuffix = [
        "activation.wondershare.com", "license.wondershare.com", "wondershare.cc", "wondershare.cn"
    ];
    const miscSoftwareSuffix = [];
    const miscSoftwareDomain = [
        "cert.bandicam.com", "ssl.bandisoft.com", "dl.bandisoft.com",
        "www.xmind.app", "www.xmind.net", "www.xmind.cn", "dl2.xmind.cn",
        "support.listary.com", "notifier.rarlab.com", "license.typora.io", "verify.typora.io"
    ];
    const msTelemSuffix = [
        "telemetry.microsoft.com", "v20.events.data.microsoft.com", "v10.events.data.microsoft.com",
        "nexus.officeapps.live.com", "officeclient.microsoft.com", "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com"
    ];
    const cnAdSuffix = [
        "ups.k0s.gk.kingsoft.com", "pcfg.wps.cn", "wps.com.cn", "wpsgold.wpscdn.cn",
        "upgrade.hikvision.com", "ezdns.hikvision.com", "cloudmsg.hikvision.com",
        "sunloginlog.oray.com", "report.oray.com", "log.todesk.com", "report.todesk.com",
        "shurufa.baidu.com", "input.baidu.com", "bugly.qq.com", "bugly.gtimg.com",
        "log.snssdk.com", "i.snssdk.com", "log.byteoversea.com", "metrics.capcut.com",
        "log.capcut.com", "stat.music.qq.com", "log.kugou.com", "stat.kuwo.cn",
        "log.music.163.com", "data.bilibili.com", "api.log.bilibili.com",
        "stat.miui.com", "data.miui.com", "tracking.miui.com", "logservice.miui.com",
        "sdkconfig.ad.xiaomi.com", "analytics.dingtalk.com", "log.feishu.cn",
        "ad.xunlei.com", "etl.xl7.xunlei.com", "update.pan.baidu.com",
        "e.qq.com", "gdt.qq.com", "l.qq.com", "toptips.qq.com", "minibrowser.qq.com",
        "umeng.com", "umengcloud.com", "alimama.com", "adashbc.ut.alibaba.com", "update.aliyun.com",
        "pos.baidu.com", "hm.baidu.com", "cpro.baidu.com",
        "pangle.io", "pangolin-sdk-toutiao.com", "ad.toutiao.com",
        "ad.360.cn", "adv.360.cn", "union.360.cn", "stat.360.cn", "log.360.cn",
        "push.360.cn", "notice.360.cn", "update.360.cn", "up.360.cn", "360safe.com",
        "360tp.com", "360kuai.com", "qhres.com", "qhstatic.com", "qhimg.com", "qhupdate.com",
        "2345.com", "2345.net", "2345p.com", "2345uns.com", "50yc.com",
        "160.com", "updrv.com", "drivergenius.com", "lms.ludashi.com",
        "cmcm.com", "ijinshan.com", "duba.com",
        "inte.sogou.com", "theta.sogou.com", "sogoucdn.com", "ie.sogou.com", "metasogou.com",
        "flash.cn", "kakaocorp.com", "p1-pc.daum.net", "p2-pc.daum.net", "p1-pc.pdk.daum.net"
    ];
    const cnAdDomain = [
        "pinyin.sogou.com", "news.sogou.com", "toast.sogou.com", "timer.sogou.com",
        "update.sogou.com", "config.sogou.com", "py.sogou.com", "snapshot.sogou.com"
    ];
    const mozillaSuffix = [
        "telemetry.mozilla.org", "experiments.mozilla.org", "healthreport.mozilla.org",
        "metrics.mozilla.com", "crash-stats.mozilla.com"
    ];
    const googleTrackSuffix = [
        "google-analytics.com", "analytics.google.com", "googletagmanager.com",
        "redirector.gvt1.com", "optimizationguide-pa.googleapis.com"
    ];
    const googleTrackKeyword = ["safebrowsing.google"];
    const youtubeSuffix  = ["youtube-ui.l.google.com"];
    const youtubeDomain  = ["s.youtube.com"];
    const youtubeKeyword = [];
    const genericAdSuffix = [
        "doubleclick.net", "scorecardresearch.com", "adnxs.com", "criteo.com",
        "taboola.com", "outbrain.com", "amazon-adsystem.com", "mc.yandex.ru", "mc.yandex.com"
    ];
    const globalKeyword = ["telemetry", "analytics", "stats", "metrics"];

    const processBlockRules = [
        "AND,((NETWORK,UDP),(DST-PORT,443),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP",
        "AND,((NETWORK,UDP),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP",
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",
        "PROCESS-NAME,AdskLicensingService.exe,REJECT-DROP",
        "PROCESS-NAME,AdskAccess.exe,REJECT-DROP",
        "PROCESS-NAME,AdskIdentityManager.exe,REJECT-DROP",
        "PROCESS-NAME,CorelDRW.exe,REJECT-DROP",
        "PROCESS-NAME,360sd.exe,REJECT-DROP",
        "PROCESS-NAME,360tray.exe,REJECT",
        "PROCESS-NAME,2345Mini.exe,REJECT",
        "PROCESS-NAME,2345Helper.exe,REJECT",
        "PROCESS-NAME,SogouNews.exe,REJECT",
        "PROCESS-NAME,Ludashi.exe,REJECT",
        "PROCESS-NAME,LDSGameBox.exe,REJECT",
        "PROCESS-NAME,DTLocker.exe,REJECT",
        "PROCESS-NAME,DriverGenius.exe,REJECT"
    ];
    const processProxyRules = [];
    const processDirectRules = [
        "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",
        "PROCESS-NAME,filezilla.exe,DIRECT"
    ];

    const proxySuffixList = [
        "github.com", "copilot.microsoft.com", "linkedin.com",
        "store.steampowered.com", "steamcommunity.com", "steamstatic.com"
    ];

    const directRules = [
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,live.com,DIRECT",
        "DOMAIN-SUFFIX,outlook.com,DIRECT",
        "DOMAIN-SUFFIX,onedrive.com,DIRECT",
        "DOMAIN-SUFFIX,skype.com,DIRECT",
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",
        "DOMAIN-SUFFIX,microsoftonline-p.com,DIRECT",
        "DOMAIN-SUFFIX,msftauth.com,DIRECT",
        "DOMAIN-SUFFIX,msftidentity.com,DIRECT",
        "DOMAIN-SUFFIX,passport.net,DIRECT",
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",
        "DOMAIN-SUFFIX,microsoftpersonalcontent.com,DIRECT",
        "DOMAIN-SUFFIX,msocsp.com,DIRECT",
        "DOMAIN-SUFFIX,msedge.net,DIRECT",
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
        "DOMAIN-SUFFIX,msftncsi.com,DIRECT",
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",
        "DOMAIN-SUFFIX,stock.adobe.com,DIRECT",
        "DOMAIN-SUFFIX,behance.net,DIRECT",
        "DOMAIN-SUFFIX,behance.adobe.com,DIRECT",
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",
        "DOMAIN,assets.adobe.com,DIRECT",
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",
        "DOMAIN-SUFFIX,corel.com,DIRECT",
        "AND,((NETWORK,UDP),(DST-PORT,123)),DIRECT",
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",
        "DOMAIN-SUFFIX,pixpinapp.com,DIRECT",
        "DOMAIN-SUFFIX,pixpin.cn,DIRECT",
        "DOMAIN-SUFFIX,lanzou.com,DIRECT",
        "DOMAIN-SUFFIX,lanzoui.com,DIRECT",
        "DOMAIN-SUFFIX,lanzoux.com,DIRECT",
        "DOMAIN-SUFFIX,masuit.com,DIRECT",
        "DOMAIN-SUFFIX,masuit.net,DIRECT",
        "DOMAIN-SUFFIX,masuit.org,DIRECT",
        "DOMAIN-SUFFIX,423down.com,DIRECT",
        "DOMAIN-SUFFIX,ghxi.com,DIRECT",
        "DOMAIN-SUFFIX,mpyit.com,DIRECT",
        "DOMAIN-SUFFIX,apphot.cc,DIRECT",
        "DOMAIN-SUFFIX,25xianbao.com,DIRECT",
        "DOMAIN-SUFFIX,dir28.com,DIRECT"
    ];

    const aggressiveRules = [
        "DOMAIN-REGEX,^.+\\.adobe\\.io$,REJECT-DROP",
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",
        "DOMAIN-SUFFIX,adsk.com,REJECT-DROP",
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",
        "DOMAIN,geo.adobe.com,REJECT-DROP",
        "DOMAIN,geo2.adobe.com,REJECT-DROP",
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",
        "DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP",
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP"
    ];

    // ═════════ 3. 规则组装与注入 ═════════
    try {
        const LAYER_ORDER = Object.freeze(["allow", "block", "process", "proxy", "aggressive", "direct"]);
        const layerPools = { allow: [], block: [], process: [], proxy: [], aggressive: [], direct: [] };
        const pushLayer = (layer, rules) => {
            if (!(layer in layerPools)) throw new Error(`未知层 '${layer}'`);
            for (const r of rules) layerPools[layer].push(r);
        };

        if (ENABLE_BLOCK) {
            const [_fireflyAction, _fireflyPool] = isFireflyActive
                ? [proxyGroupName, layerPools.allow]
                : ["REJECT", layerPools.block];
            pushSuffix(adobeSharedDeps, _fireflyAction, _fireflyPool);
            pushSuffix(adobeFireflyOnly, _fireflyAction, _fireflyPool);
            pushSuffix(adobeSuffix, "REJECT", layerPools.block);
            pushLayer("block", adobeRegex);
            pushLayer("block", adobeUdpBlock);
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
            pushSuffix(cnAdSuffix, "REJECT", layerPools.block);
            pushDomain(cnAdDomain, "REJECT", layerPools.block);
            pushSuffix(mozillaSuffix, "REJECT", layerPools.block);
            pushSuffix(googleTrackSuffix, "REJECT", layerPools.block);
            pushKeyword(googleTrackKeyword, "REJECT", layerPools.block);
            pushSuffix(youtubeSuffix, "REJECT", layerPools.block);
            pushDomain(youtubeDomain, "REJECT", layerPools.block);
            pushKeyword(youtubeKeyword, "REJECT", layerPools.block);
            pushSuffix(genericAdSuffix, "REJECT", layerPools.block);
            if (ENABLE_GLOBAL_KEYWORD_BLOCK) {
                pushKeyword(globalKeyword, "REJECT", layerPools.block);
            }
        }

        if (ENABLE_PROCESS_RULE) {
            pushLayer("process", processBlockRules);
            pushLayer("process", processProxyRules);
            pushLayer("process", processDirectRules);
        }

        if (ENABLE_PROXY) {
            pushSuffix(proxySuffixList, proxyGroupName, layerPools.proxy);
        }

        if (ENABLE_AGGRESSIVE) {
            pushLayer("aggressive", aggressiveRules);
        }

        if (ENABLE_DIRECT) {
            pushLayer("direct", directRules);
        }

        // 双向一致性检查
        const _orderSet = new Set(LAYER_ORDER);
        for (const k of LAYER_ORDER) {
            if (!(k in layerPools)) throw new Error(`LAYER_ORDER 键 '${k}' 缺失`);
        }
        for (const k of Object.keys(layerPools)) {
            if (!_orderSet.has(k)) throw new Error(`layerPools 键 '${k}' 未列入 LAYER_ORDER`);
        }

        const finalPool = [_SENTINEL_START];
        for (const key of LAYER_ORDER) {
            for (const r of layerPools[key]) finalPool.push(r);
        }
        finalPool.push(_SENTINEL_END);
        config.rules = finalPool.concat(config.rules);

        console.log("=".repeat(28));
        console.log("✅ 规则注入成功");
        console.log(`   脚本状态: ✅ 已启用`);
        console.log(`   拦截模块:   ${ENABLE_BLOCK ? "✅" : "❌"}`);
        if (ENABLE_FIREFLY) {
            console.log(`   Firefly 放行: ${isFireflyActive ? "✅（已注入 allow 层）" : "❌（已自动降级）"}`);
        } else {
            console.log(`   Firefly 放行: ❌`);
        }
        console.log(`   进程规则:   ${ENABLE_PROCESS_RULE ? "✅" : "❌"}`);
        console.log(`   代理规则:   ${ENABLE_PROXY ? "✅" : "❌"}`);
        console.log(`   激进模式:   ${ENABLE_AGGRESSIVE ? "⚠️ 已开启" : "❌"}`);
        if (ENABLE_AGGRESSIVE) {
            console.warn("   ⚠️ 激进模式已开启，可能导致官网/插件商店/登录等功能异常");
        }
        console.log(`   直连规则:   ${ENABLE_DIRECT ? "✅" : "❌"}`);
        console.log(`   Hosts 覆写:  ${ENABLE_HOSTS_OVERRIDE ? "✅ [" + HOSTS_MODE + "]" : "❌"}`);
        console.log(`   ▶ 分层统计: allow ${layerPools.allow.length} | block ${layerPools.block.length} | process ${layerPools.process.length} | proxy ${layerPools.proxy.length} | aggressive ${layerPools.aggressive.length} | direct ${layerPools.direct.length}`);
        console.log(`   注入规则数: ${finalPool.length} 条（含哨兵），总规则数: ${config.rules.length}`);
        console.log(`   脚本耗时: ${Date.now() - _startTime} ms`);
        console.log("=".repeat(28));
    } catch (err) {
        console.error("❌ 规则注入阶段异常，继续尝试 Hosts 覆写:", err);
    }

    // ═════════ 4. Hosts DNS 覆写 ═════════
    if (ENABLE_HOSTS_OVERRIDE) {
        try {
            const modeMap = {
                "ipv4-loopback":  "127.0.0.1",
                "ipv4-blackhole": "0.0.0.0",
                "dual-loopback":  ["127.0.0.1", "::1"],
                "dual-blackhole": ["0.0.0.0", "::"]
            };
            const target = modeMap[HOSTS_MODE];
            if (!target) throw new Error(`未知 HOSTS_MODE: "${HOSTS_MODE}"`);

            const hijackDomains = BACKDOOR_BASE_DOMAINS.flatMap(d => [`+.${d}`]);
            const customHosts = Object.fromEntries(hijackDomains.map(d => [d, target]));

            const ensureHostsObj = val =>
                (typeof val === "object" && val !== null && !Array.isArray(val)) ? val : {};

            config.hosts = { ...ensureHostsObj(config.hosts), ...customHosts };

            if (config.dns == null) {
                config.dns = {};
            } else if (typeof config.dns !== "object" || Array.isArray(config.dns)) {
                console.warn("⚠️ config.dns 类型异常，已写入顶层 hosts，跳过 dns.hosts 注入");
                return config;
            }
            config.dns.hosts = { ...ensureHostsObj(config.dns.hosts), ...customHosts };

            if (!Array.isArray(config.dns["fake-ip-filter"])) {
                config.dns["fake-ip-filter"] = [];
            }
            const _CURRENT_MANAGED = new Set(
                BACKDOOR_BASE_DOMAINS.flatMap(d => [`+.${d}`, d, `*.${d}`]).map(s => s.toLowerCase())
            );
            const _HISTORICAL_MANAGED = new Set([
                "api.966v26.com", "status.966v26.com",
                "+.cc-cdn.com", "cc-cdn.com", "*.cc-cdn.com"
            ].map(s => s.toLowerCase()));
            const _SCRIPT_MANAGED_HIJACK = new Set([..._CURRENT_MANAGED, ..._HISTORICAL_MANAGED]);
            if (ENABLE_MAINTENANCE_CHECKS) {
                const _redundantHistorical = [..._HISTORICAL_MANAGED].filter(entry => _CURRENT_MANAGED.has(entry));
                if (_redundantHistorical.length > 0) {
                    console.warn("⚠️ fake-ip-filter 历史集合含当前活跃条目:", _redundantHistorical);
                }
            }
            const existingSet = new Set();
            const cleanExisting = [];
            let cleanedCount = 0;
            for (const entry of config.dns["fake-ip-filter"]) {
                const s = typeof entry === "string" ? entry.trim() : "";
                const sl = s.toLowerCase();
                if (!s) continue;
                if (_SCRIPT_MANAGED_HIJACK.has(sl)) { cleanedCount++; continue; }
                if (existingSet.has(sl)) continue;
                existingSet.add(sl);
                cleanExisting.push(s);
            }
            const newEntries = hijackDomains.filter(d => !existingSet.has(d.toLowerCase())).sort();
            config.dns["fake-ip-filter"] = [...cleanExisting, ...newEntries];

            console.warn("⚠️ Hosts DNS 覆写已注入，但需确保 CVR 开启“启用 DNS”和“使用 Hosts”才能生效");
            console.log(`🛡️ Hosts 覆写: ${hijackDomains.length} 条，模式 [${HOSTS_MODE}]；fake-ip-filter 清理 ${cleanedCount} 条，新增 ${newEntries.length} 条`);
        } catch (err) {
            console.error("❌ Hosts DNS 覆写注入失败:", err);
        }
    }

    return config;
}