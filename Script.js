/**
 *   Clash-Script 全局扩展脚本 · 基于哨兵标记的规则幂等清理与注入（Firefly 精确豁免版）v260607
 * 
 * ══════════════════════════ ░░ 脚本自述 ░░ ══════════════════════════
 *
 *   Script.js 路径（Windows）：
 *     %APPDATA%\io.github.clash-verge-rev.clash-verge-rev\profiles
 *     C:\Users\Administrator\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles
 *
 *   默认模式：拦截优先 + Firefly 精确例外放行
 *     - ENABLE_FIREFLY = true：精确放行 Firefly AI 请求，保留其他 Adobe 遥测/激活域名的拦截行为。
 *     - Firefly 依赖端点必要妥协：auth / cc-api / lcs 等端点因 Firefly 功能依赖而一并放行；
 *       最后防线为 AdobeGCClient.exe → REJECT-DROP（需 ENABLE_PROCESS_RULE=true + TUN 模式 + 管理员权限），另还需配置文件的 find-process-mode 参数启用获取进程信息。
 *       注意：Creative Cloud.exe / CCXProcess.exe / CoreSync.exe 等进程同样访问这些端点，
 *       进程规则仅覆盖 AdobeGCClient.exe，其余进程因依赖链考量予以必要豁免（原因见正文 Firefly 必要妥协，详见 adobeSharedDeps 注释及设计取舍）。
 *     - 适用场景：需要使用 Photoshop 生成式填充、Firefly 等 Adobe AI 功能。
 *
 * ══════════════════════════ ░░ 功能概览 ░░ ══════════════════════════
 *
 *   - 智能识别代理策略组（多级降级策略：优选组（三轮：关键词→正则→类型）→ 兜底组 → 容错选取 → 全部失败则中止注入）
 *   - 注入拦截规则（Adobe / Corel / Autodesk 等软件的激活域名与遥测域名）
 *   - 代理与直连规则
 *   - 进程规则（需管理员权限 + TUN 模式，即 Mihomo 创建虚拟网卡接管全部流量）
 *   - 激进阻断模块（默认关闭，需谨慎开启）
 *   - Hosts 级 DNS 覆写（四种映射子模式：黑洞型与欺骗型，由 HOSTS_MODE 选择）
 *   - 基于哨兵标记的幂等性（即无论执行多少次，结果相同）规则清理与注入（哨兵索引截断法，O(N) 时间 / O(N) 空间，单次遍历，防止每次重新加载订阅时本脚本注入的规则块被重复追加）
 *   - 异常降级保护，详细运行日志
 *
 * ══════════════════════════ ░░ 使用说明 ░░ ══════════════════════════
 *
 *   1. 调整顶部配置区的功能开关（true / false）
 *   2. 在对应数组中增删域名即可，无需修改下方逻辑
 *   3. 保存后在 Clash Verge Rev 中重新加载配置文件即可生效，无需重启
 */

function main(config) {
    
    const _startTime = Date.now();               // 计时起点

    // ⚙️ ══════════════════════ 配置区（按需调整） ══════════════════════
    // 所有 ENABLE_* 开关语义统一：true = 启用  false = 禁用。
    // 修改后在 Clash Verge Rev（CVR，即本脚本所在的 Clash 图形前端）中重新加载订阅即可生效，无需重启。

    // true  = 完全启用脚本功能。
    // false = 禁用规则注入，但仍返回含调试标记的修改版配置（向规则头部写入一条使用 .invalid 保留域的调试标记规则，非原样返回），详见下方 ENABLE_SCRIPT 分支说明。
    //         即不注入功能性规则，实际网络路由等同于未加载脚本；只是规则列表中保留一条可见的调试标记供外部识别脚本禁用状态。
    const ENABLE_SCRIPT       = true;

    // ──── 以下开关分别对应各注入层，但声明顺序与注入顺序解耦，注入顺序由 LAYER_ORDER 唯一决定（三处例外见括号说明）
    //      顺序：allow > block > process > proxy > aggressive > direct
    //      · ENABLE_BLOCK 与 ENABLE_FIREFLY 相邻声明便于阅读（两者分属 block/allow 层，语义紧密关联）
    //      · ENABLE_GLOBAL_KEYWORD_BLOCK 属 block 层子开关，因说明篇幅较长集中声明于配置区末尾
    //      · ENABLE_SCRIPT、ENABLE_HOSTS_OVERRIDE 独立于此六层结构之外
    const ENABLE_BLOCK        = true;            // 拦截模块（规则优先级高，仅次于 allow 层，isFireflyActive=true 时 Firefly 放行先于拦截命中，见 LAYER_ORDER）
                                                 // 关闭拦截模块还意味着 Firefly 放行规则也不注入。流量既无 REJECT 也无代理覆盖，被进程规则或 MATCH 兜底策略接管。
    const ENABLE_FIREFLY      = true;            // 精确放行 Adobe Firefly AI 生成式请求。启用放行规则需（ENABLE_BLOCK=true）对应拦截层以供豁免。
                                                 // Firefly 放行依赖：isFireflyActive（由ENABLE_FIREFLY && ENABLE_BLOCK派生）=> 放行层走 proxyGroupName，
                                                 // 识别失败则中止注入。必要妥协：auth/cc-api 等鉴权端点同时放行。
                                                 // 安全底线：AdobeGCClient.exe 进程规则（需 TUN + 管理员权限）。
    const ENABLE_PROCESS_RULE = true;            // 进程规则模块（需 TUN 模式 + 管理员权限；另还需配置文件的 find-process-mode 参数启用获取进程信息）。
    const ENABLE_PROXY        = true;            // 指定域名走代理模块
    const ENABLE_AGGRESSIVE   = false;           // 激进阻断模块（⚠️ 谨慎启用，可能影响官网/插件商店访问）
                                                 // ⚠️ 受影响范围：Adobe 插件市场/字体、Autodesk 官网/登录/授权、Office 更新/模板、ActiveX/旧版 OA 系统
                                                 // aggressiveRules 必须在 directRules 之前注入，否则父域 DIRECT 规则会优先匹配，子域 REJECT-DROP 将失效。
    const ENABLE_GLOBAL_KEYWORD_BLOCK = false;   // 关键词全局阻断（⚠️ 极度激进，会误杀大量合法 CDN/第三方服务）
                                                 // 命名说明：该开关命名为三段式（ENABLE / GLOBAL_KEYWORD / BLOCK），与同文件其他开关声明的两段式命名不对称；
                                                 //   原因：命名中的 GLOBAL 表示该开关控制的是全局关键词匹配行为，区别于 BLOCK 控制拦截模块。两者语义层次不同。
    const ENABLE_DIRECT          = true;         // 指定域名直连模块
    const ENABLE_HOSTS_OVERRIDE  = true;         // Hosts DNS 覆写模块（四种映射子模式：黑洞型与欺骗型，由 HOSTS_MODE 选择）
    // ❗ 生效前提：CVR › DNS 覆写，必须同时开启「启用 DNS」和「使用 Hosts」。两个开关缺一不可，脚本无法感知 UI 层开关状态；
    //    未开启时本模块失效（脚本仍打印成功日志，但 Hosts 覆写不生效）。
    // ℹ️ 依赖约束：ENABLE_SCRIPT=false 时此模块被跳过（脚本提前返回，Hosts 注入不执行）；如需关闭规则注入同时保留 Hosts 覆写，应保持 ENABLE_SCRIPT=true 并关闭各子模块开关。
    // 💡 推荐使用 "ipv4-loopback"（当前默认值）：返回 127.0.0.1，产生 ECONNREFUSED（回环模拟拦截），
    //    应用兼容性通常最好；ipv4-blackhole 阻断速度最快，但可能被部分应用归类为断网状态。
    //
    // Hosts 模式选项：ipv4-loopback(127.0.0.1) / ipv4-blackhole(0.0.0.0) / dual-loopback(127.0.0.1+::1) / dual-blackhole(0.0.0.0+::)
    // 命名说明：ipv4- 前缀标识 IPv4 单栈；dual- 前缀标识 IPv4+IPv6 双栈；
    //            loopback 为回环模拟拦截（DNS 返回回环地址，TCP 因本地无监听而 ECONNREFUSED，更温和）；
    //            blackhole 为黑洞拦截（DNS 返回不可路由地址，OS 地址校验即失败）。四个名称完全对称。
    //
    // 各模式连接失败类型（来源：Mihomo wiki + OS 网络栈行为）：
    //   ipv4-loopback  → 127.0.0.1          → 本地 TCP 栈返回 RST（无监听端口），应用层收到 ECONNREFUSED，回环模拟拦截，更温和
    //   ipv4-blackhole → 0.0.0.0            → 具体错误码因 OS 而异：无论哪种错误码，TCP SYN 都不会发出，阻断速度最快。但部分应用可能将此错误误判为断网状态
    //   dual-loopback  → 127.0.0.1 + ::1    → 同 ipv4-loopback，IPv4/IPv6 双栈回环模拟拦截
    //   dual-blackhole → 0.0.0.0 + ::       → 同 ipv4-blackhole，IPv4/IPv6 双栈黑洞拦截（慎用：连接至 :: 时的 OS 层行为因平台而异，可能导致应用异常）
    //
    // 双栈黑洞模式（dual-blackhole）因 IPv6 的 :: 行为更激进，存在非预期的连接错误或应用异常；ipv4-blackhole 单栈版风险较低。
    const HOSTS_MODE = "ipv4-loopback";
    //
    const ENABLE_MAINTENANCE_CHECKS = false;   // 开启后，验证 _HISTORICAL_MANAGED 中是否存在仍属于当前活跃集合的冗余条目（用于 fake-ip-filter 维护期排查）。
    //
    // ──── ✅ 节点级 client-fingerprint 注入开关，TLS 客户端指纹模拟预设 ────
    // 模拟指定客户端的 TLS 握手特征，以增强抗检测能力。实际效果依赖目标站点策略，不保证绕过指纹检测或消除触发验证码。
    // - true:  为所有未设置 fingerprint 的节点注入默认指纹
    // - false: 完全跳过指纹注入，保留节点原始配置
    // ℹ️ 两种方式可阻止指纹注入：
    //    1. 设置 ENABLE_CLIENT_FINGERPRINT = false → 模块完全关闭，日志显示“已禁用”
    //    2. 设置 DEFAULT_FINGERPRINT = "none"   → 模块运行但跳过注入，日志显示“已启用但 none”
    //    两者最终效果相同（节点无 client-fingerprint 字段），可根据需要选择。
    const ENABLE_CLIENT_FINGERPRINT = true;
    // 默认指纹，仅在 ENABLE_CLIENT_FINGERPRINT 为 true 时生效。可选值: chrome / firefox / safari / iOS / android / edge / 360 / qq / random / none
    // 💡 random：启动时从指纹库（按 Cloudflare Radar 数据概率）生成一个浏览器指纹并固定使用，非每连接随机切换。概率：Chrome 50%，Safari 25%，iOS 16.7%，Firefox 8.3%
    const DEFAULT_FINGERPRINT = "chrome";
    // 指纹注入关键词跳过名单：名称中包含这些关键词的节点，即使没有指纹也不会被注入。用途：保护特殊节点（如专用 IP 节点、特定落地机）不被意外修改指纹。
    // ⚠️ 跳过关键词列表：含中文字符（CJK 中日韩统一表意文字）的子串匹配（includes），和纯英文 ASCII 的词边界正则匹配。
    const FINGERPRINT_SKIP = [];  // 赋值示例：["原生", "game",]。应避免可能包含在其他词组中的关键词（如 "香港" 会匹配 "非香港直连"）

    // ──── 典型配置组合参考（按需参照调整上方开关值；此处为说明性文字，无需操作）────
    //
    // 【默认推荐】拦截 + Firefly 放行 + 代理 + 直连 + Hosts DNS 覆写（激进模式关闭）
    //   ENABLE_BLOCK=true  ENABLE_FIREFLY=true  ENABLE_PROCESS_RULE=true
    //   ENABLE_PROXY=true  ENABLE_DIRECT=true   ENABLE_HOSTS_OVERRIDE=true
    //   ENABLE_AGGRESSIVE=false   HOSTS_MODE="ipv4-loopback"
    //
    // 【纯拦截模式】只拦截，不注入代理/直连规则，适合规则轻量化场景。
    //   ENABLE_BLOCK=true  ENABLE_FIREFLY=false  ENABLE_PROCESS_RULE=false
    //   ENABLE_PROXY=false ENABLE_DIRECT=false   ENABLE_HOSTS_OVERRIDE=true
    //   ENABLE_AGGRESSIVE=false
    //
    // 【激进模式】在默认推荐基础上额外开启激进阻断，彻底封堵 adobe.io / adsk.com 等。
    //   ⚠️ 激进模式会影响官网/插件商店访问，开启前请仔细阅读 ENABLE_AGGRESSIVE 注释
    //   ENABLE_AGGRESSIVE=true   （其余开关与默认推荐相同）
    //
    // 【仅调试/禁用脚本】停用规则注入，保留调试标记，方便对比前后差异。
    //   ENABLE_SCRIPT=false   （其余开关无效）
    // ⚠️ 极端组合：ENABLE_AGGRESSIVE=true 且 ENABLE_BLOCK=false 时，激进规则将单独注入（无 allow/block 层配合），
    //   可能仅保留少量 REJECT-DROP 规则而缺少必要的放行或拦截规则，非预期使用，不推荐。

    // ──── Firefly 派生开关：isFireflyActive 是 Firefly 放行规则是否被注入的唯一决策变量 ────
    // 派生值，仅由 ENABLE_FIREFLY && ENABLE_BLOCK 决定，不可反向修改上游开关。
    // 设计逻辑：只有同时开启拦截模块（ENABLE_BLOCK）和 Firefly 开关（ENABLE_FIREFLY），Firefly 放行规则才真正生效，有拦截层才有"豁免"的意义。
    // 所有 Firefly 相关代码逻辑均使用此变量，而非原始 ENABLE_FIREFLY，
    // 防止用户因 ENABLE_FIREFLY=true 而误以为 Firefly 已放行（ENABLE_BLOCK=false 时 isFireflyActive 自动降级为 false，放行规则不注入）
    const isFireflyActive = ENABLE_FIREFLY && ENABLE_BLOCK;

    // ══════════════════════ 防御性检查 ══════════════════════

    if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw new Error("[Script] main() 收到非法 config（null / 数组 / 非对象类型），终止执行以保护内核加载安全");
    }
    if (!Array.isArray(config.rules))           config.rules = [];
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];

    // 功能依赖检查：isFireflyActive 已将 ENABLE_FIREFLY 与 ENABLE_BLOCK 的依赖关系封装，此 warn 仅供调试，对运行逻辑无影响。
    if (ENABLE_FIREFLY && !ENABLE_BLOCK) {
        console.warn("⚠️ 警告：Firefly 放行需同时启用拦截模块（ENABLE_BLOCK=true），当前 ENABLE_BLOCK=false，Firefly 豁免不生效");
    }
    if (ENABLE_PROCESS_RULE && config["find-process-mode"] !== "strict" && config["find-process-mode"] !== "always") {
        console.warn(`⚠️ 进程规则要求 find-process-mode 为 strict 或 always，当前为 [${config["find-process-mode"] ?? "（未设置）"}]，进程规则将静默失效`);
    }

    // ══════════════════════ ENABLE_SCRIPT 分支 ══════════════════════
    // ──── 前置执行：基于哨兵标记的幂等性规则清理与注入（哨兵索引截断，O(N) 单次遍历，处理任意数量堆叠）────
    // 先清理上次遗留标记，再插入新标记，防止多次切换后堆叠。
    // 哨兵标记（sentinel）：成对包裹本脚本注入的规则区间，供幂等清理时精确定位注入范围。此处在 ENABLE_SCRIPT 判断之前执行，
    // 即使 ENABLE_SCRIPT=false 时也清理旧哨兵，确保注入操作的幂等性：无论脚本执行多少次，结果相同，防多次切换后旧规则残留堆叠。
    //
    // ⚠️ 哨兵格式设计：哨兵必须是合法的 Clash 三段式规则（TYPE,VALUE,POLICY）且格式固定，
    //    清理算法依赖精确等值（===）匹配；若确需修改哨兵格式，须同步更新清理逻辑。null/undefined 也不会意外匹配哨兵字符串，严格等值天然防御。
    // 💡 TLD 选型：使用 RFC 6761 明确保留的 .invalid（无效域），而非 .local（RFC 6762 mDNS 保留域）。
    //    local 在部分系统级 mDNS 配置下可能触发 DNS 多播查询；invalid 作为保留域，标准 DNS 实现不应对其解析，产生额外 DNS 流量的风险极低，更为安全。
    const _SENTINEL_START = "DOMAIN,START-rule-injection-sentinel.invalid,REJECT";
    const _SENTINEL_END   = "DOMAIN,END-rule-injection-sentinel.invalid,REJECT";
    {
        // 哨兵索引截断：单次遍历，O(N) 时间，O(N) 空间。
        const newRules = [];
        const stack    = [];
        let _orphanEndCount = 0; // 循环之前声明变量
        for (const rule of config.rules) {
            if (rule === _SENTINEL_START) {
                stack.push(newRules.length);
                continue;
            }
            if (rule === _SENTINEL_END) {
                if (stack.length > 0) {
                    newRules.length = stack.pop(); // O(1) 截断，等效 splice 但无线性拷贝开销
                } else {
                    // 孤立 END：计数但忽略，防止旧异常残留
                    _orphanEndCount = (_orphanEndCount || 0) + 1;
                }
                continue;
            }
            newRules.push(rule);
        }
        if (stack.length > 0) {
            console.warn(`⚠️ 发现 ${stack.length} 个未闭合的哨兵块（旧注入规则可能残留），已保留后续规则`);
        }
        if (_orphanEndCount > 0) {
            console.warn(`⚠️ 发现 ${_orphanEndCount} 个孤立哨兵 END（上次注入可能异常中断），已忽略`);
        }
        config.rules = newRules;
    }

    if (!ENABLE_SCRIPT) {
        // ⚠️ 注意：ENABLE_SCRIPT=false 是「带调试标记的受控禁用」，不是零修改的原样返回。此分支仍会执行两个操作：
        //      (1) 清除上次遗留的 debug-script-disabled 标记（防标记重复追加）
        //      (2) 在规则头部插入新的 debug-script-disabled 标记（供外部识别脚本禁用状态）
        //    因此返回的 config 与订阅原始状态有微小差异（多一条标记规则）。如需零修改直接返回（Passthrough 直通模式），将此 if 分支体改为 return config; 即可。
        //    如需保留 Hosts DNS 覆写但关闭规则注入，请保持 ENABLE_SCRIPT=true，并将 ENABLE_BLOCK / ENABLE_PROXY / ENABLE_DIRECT 等各子模块开关设为 false。
        //    此处用 filter 而非哨兵索引截断，因调试标记为单条平铺，无嵌套清理需求；使用 !== 等值匹配（与哨兵清理策略一致），避免宽泛子串误删合法规则。
        config.rules = config.rules.filter(r => r !== "DOMAIN,debug-script-disabled.marker.invalid,REJECT");
        config.rules.unshift("DOMAIN,debug-script-disabled.marker.invalid,REJECT");
        return config;
    }

    console.log("=".repeat(28));
    // 当前实现手动 padStart 拼接，格式固定为 HH:MM:SS（本地时区），跨引擎跨区域设置格式一致（时间值仍为本地时区）。
    const _now  = new Date();  // 当前时间（用于格式化日志时间戳）
    const _ts = [_now.getHours(), _now.getMinutes(), _now.getSeconds()]
        .map(n => String(n).padStart(2, "0"))
        .join(":");
    console.log(`📊 节点与规则链注入开始 [${_ts}]`);
    console.log("=".repeat(28));

    // ═══════════════ client-fingerprint 注入逻辑 ═══════════════
    if (!ENABLE_CLIENT_FINGERPRINT) {
        console.log("ℹ️ TLS 指纹注入已禁用 (ENABLE_CLIENT_FINGERPRINT = false)。");
    } else if (DEFAULT_FINGERPRINT === "none") {
        console.log("ℹ️ TLS 指纹注入已启用，但默认指纹为 'none'，不执行注入。");
    } else if (!Array.isArray(config.proxies)) {
        console.log("ℹ️ TLS 指纹注入已启用，但 config.proxies 不是数组（订阅可能仅含 proxy-providers），跳过注入。");
    } else {
        // 合法指纹白名单；无效值通过 _effectiveFP 降级为 "none"（无注入），"none" 本身由上层早出口处理
        const _VALID_FINGERPRINTS = new Set([
            "chrome", "firefox", "safari", "iOS", "android", "edge", "360", "qq", "random", "none"
        ]);
        // 无效值降级为 "none"，避免 const 重复赋值问题
        let _rawFP;
        if (_VALID_FINGERPRINTS.has(DEFAULT_FINGERPRINT)) {
            _rawFP = DEFAULT_FINGERPRINT;
        } else {
            console.warn(`⚠️ 无效指纹 "${DEFAULT_FINGERPRINT}"，降级为 "none"`);
            _rawFP = "none";
        }

        // 解析 random 指纹：按概率随机选取一个具体指纹，并固定使用（非每连接随机）
        const _effectiveFP = _rawFP === "random"
            ? (() => {
                const rand = Math.random();
                // 概率分布：Chrome 50%，Safari 25%，iOS 16.7%，Firefox 8.3%
                if (rand < 0.50) return "chrome";
                if (rand < 0.75) return "safari";
                if (rand < 11/12) return "iOS"; // 11/12 ≈ 0.91666
                return "firefox";
            })()
            : _rawFP;

        if (_effectiveFP === "none") {
            console.log("ℹ️ TLS 指纹注入已启用，但因默认指纹配置无效已降级为 'none'，不执行注入。");
        } else {
            // ── 以下为有效指纹的正常注入逻辑 ──
            if (_rawFP === "random") {
                console.log(`💡 已从 random 解析为固定指纹: ${_effectiveFP}`);
            }
            // 预处理 SKIP 名单：按 CJK（中日韩字符集）/ASCII（基础字符集）分轨，CJK 关键词直接子串匹配，ASCII 关键词预编译边界正则
            const _skipKeywords = [];  // 含 CJK 字符的关键词，走 includes()
            const _skipRegexes  = [];  // 纯 ASCII 关键词，走边界正则
            for (const raw of FINGERPRINT_SKIP) {
                if (typeof raw !== "string" || !raw) {
                    console.warn(`[Script] FINGERPRINT_SKIP 中的非法条目已跳过:`, raw);
                    continue;
                }
                const hasCJK = /\p{Unified_Ideograph}/u.test(raw);
                if (hasCJK) {
                    // CJK 关键词使用子串匹配，统一转为小写以保证大小写不敏感
                    _skipKeywords.push(raw.toLowerCase());
                } else {
                    // ASCII 关键词直接使用原始大小写构建边界正则（正则 'i' 标志负责忽略大小写）
                    const escaped = raw.replace(/[-\\^$*+?.()|[\]{}]/g, '\\$&');
                    _skipRegexes.push(new RegExp(`(^|[-_\\s（）()\\[\\]./])${escaped}([-_\\s（）()\\[\\]./]|$)`, 'i'));
                }
            }

            let injectedCount = 0;
            let skippedCount = 0;
            let preExistingCount = 0;

            config.proxies = config.proxies.map(p => {
                if (typeof p !== 'object' || p === null) return p; // 类型守卫：类型以外的对象，不处理
                // 1. 尊重节点已有配置：字段存在即保留（包括 null、false、""）
                //    ⚠️ 变更 DEFAULT_FINGERPRINT 不会更新已有该字段的节点；如需强制覆盖，须先从订阅 YAML 删除节点的 client-fingerprint 字段后重新加载。
                if (Object.prototype.hasOwnProperty.call(p, 'client-fingerprint')) {
                    preExistingCount++;
                    return p;
                }

                // 2. 检查 SKIP 名单：CJK（中日韩字符集）关键词用子串匹配，ASCII 关键词用边界正则
                const nodeName = p.name || "";
                const nodeNameLower = nodeName.toLowerCase();
                const isSkipped = _skipKeywords.some(kw => nodeNameLower.includes(kw))
                            || _skipRegexes.some(regex => regex.test(nodeName));

                if (isSkipped) {
                    skippedCount++;
                    return p;
                }

                // 3. 注入有效指纹
                injectedCount++;
                return { ...p, 'client-fingerprint': _effectiveFP };
            });

            console.log(`✅ TLS 指纹注入完成: 新增注入 ${injectedCount} 个，`
                    + `跳过（SKIP）${skippedCount} 个，`
                    + `维持既有指纹 ${preExistingCount} 个。(指纹: ${_effectiveFP})`);
        }
    }
    // ────────────────────────────────────────────────

    // ════════════════ 1. 智能识别代理策略组 ════════════════
    //
    // 逻辑：多级降级，兼容大多数订阅格式。无可用组时终止注入，防止 Mihomo 内核因策略组不存在而启动失败（见容错选取策略及代理组排除断言）。

    let proxyGroupName = null; // 初始为 null，强制要求下游所有赋值路径全覆盖；任何未赋值路径均会触发代理组排除断言安全拦截。
    // 注意：当前路径：null 不到达断言（识别失败已 return config）；防御路径（仅在未来分支遗漏赋值时触发）：sanitizeName(null) →""→ 断言拦截；
    //   所有真实执行路径均会在策略链结束前显式赋值（成功时为 mainGroup.name）；识别失败时直接 return config。
    // 若将来新增分支遗漏赋值，sanitizeName(null) 返回 ""，断言 !_sanitizedProxy 为 true 并安全拦截。
    // 💡 当前实现中识别成功时 proxyGroupName 必定被赋值为组名；若将来新增代码分支，须确保也对其显式赋值，否则 null 会到达代理组排除断言并触发安全兜底（中止注入）。
    // 💡 出口控制说明：识别逻辑通过 EXCLUDED_NAMES 明确排除了绝大多数不适合的出口；极端情况下（全部策略均失败）代码直接 return config，使网络回退至订阅原始规则。

    // 策略组分三类：
    //   排除组（EXCLUDED）：绝对不能用作代理出口，会导致代理规则失效（流量不经过任何代理节点）
    //   兜底组（FALLBACK）：可用但不优先，无更好选项时才降级使用（GLOBAL/全局 等）
    //   优选组（Eligible）：正常可用且优先选择的代理组。
    const EXCLUDED_NAMES = new Set([
        "DIRECT",
        "REJECT",
        "COMPATIBLE",  // Clash Premium 兼容模式保留关键字，Mihomo 不使用此类型；保留以防订阅包含 Clash Premium 格式策略组导致误选
        "DEFAULT",     // Mihomo 内部保留词，用于 Fallback 策略默认出口表达，防御性排除
        "MATCH",       // Mihomo 内置动作关键字（兜底策略）；正常订阅格式下极不可能出现同名代理组，保留以防万一订阅中存在同名代理组时被错误选为出口
        "PASS",        // 防止将 Mihomo 的 PASS（透传）策略错误选为代理出口
    ].map(s => s.toUpperCase()));
    const FALLBACK_NAMES = new Set(["GLOBAL"]);  // 兜底组：前三轮优选策略全部失败时，第四轮降级才触发
    // ❗ 运行时配置断言：FALLBACK_NAMES ∩ EXCLUDED_NAMES 必须为空集。
    //    若修改 FALLBACK_NAMES 或 EXCLUDED_NAMES，务必确保两者互斥。
    //    若 "REJECT" 等被误加入 FALLBACK_NAMES，_isEligibleGroup 中的提前 return true 会旁路 EXCLUDED_NAMES 检查，使排除词被错误视为合法兜底组。
    // ⚠️ 触发则说明常量集被误修改：改用 return config 而非 throw，保证用户网络不中断（回退至订阅原始规则），错误仍通过 console.error 明确输出。
    {
        const _overlap = [...FALLBACK_NAMES].filter(n => EXCLUDED_NAMES.has(n));
        if (_overlap.length > 0) {
            console.error(`❌ 配置断言失败：FALLBACK_NAMES ∩ EXCLUDED_NAMES 非空: ${_overlap.join(", ")}`);
            console.error(`   此约束被违反将导致 REJECT 等排除词被误选为代理出口，脚本中止注入`);
            return config;
        }
    }

    // 中文排除组正则（两段结构，这是有意设计，请勿合并为统一锚定写法）：
    //   前半段：^...$  精确匹配（加 ^$ 两端锚定），覆盖"全部/全网/全用/全球/所有/默认"等独立词。
    //      → 避免「所有节点」「全局代理」等合法组名被误伤
    //      → 「全用」：含义为"全部用途"，见于部分订阅的「全用途代理」组名；此类组名语义模糊，可能配置为 DIRECT 直连出口，也可能是真实代理出口，为保守起见一律排除；
    //         保留的代价极低（精确词 $ 锚定，不会误伤含「全用」的复合组名如「全用节点」）
    //   后半段：无位置锚定，子串匹配，覆盖「直连国内」「全局直连」「拒绝广告」等任意位置变体。
    //      → 「拒绝垃圾流量」含「拒绝」，保守排除：含「拒绝」的组名通常指向 REJECT 出口，用作路由出口将导致流量被拒绝。命名模糊时仍保守排除以防路由失效。
    //   ⚠️ "全局"已从此正则移出，由独立的 FALLBACK_CN_RE 负责识别（原因见下方 FALLBACK_CN_RE 及 _isEligibleGroup 防回归说明）。
    //   ⚠️ 已知局限：后半段无位置锚点，采用子串匹配。若代理组命名为「非直连节点」、「不拒绝广告」等包含否定前缀的复合词，会因包含「直连」或「拒绝」子串而被错误排除。
    //   ⚠️ 「默认节点」等含「默认」的复合词组名不触发（精确词加 $ 锚定为设计取舍）此类指向 DIRECT 的订阅极为罕见；此取舍可最大化保障通用订阅的兼容性。
    //   ⚠️ 极端边界（两字排除）：组名恰为「全球」（仅两字，无修饰词）时被精确匹配排除（^全球$），无警告日志，注入将进入容错路径或触发代理组排除断言中止。
    //      含「全球」的复合词（如「全球节点」）因含「节点」关键词，可进入优选策略正常被选中。
    //   ℹ️ 针对极端特例的避坑指南，若订阅唯一组名恰为「全球」，有两种解法：
    //      1. 直接在订阅转换前端或本地 Profile 覆写层将该代理组重命名（推荐，零代码侵入）；
    //      2. 在 EXCLUDED_CN_RE 中移除 "全球" 的匹配项，并将 FALLBACK_CN_RE 改为 /^(?:全局|全球)$/（同时更新 FALLBACK_NAMES ∩ EXCLUDED_NAMES 断言的测试词列表）。
    //  
    const EXCLUDED_CN_RE = /^(?:全(?:部|网|用|球)|所有|默认)$|(?:直连|拒绝)/;

    // 中文兜底组：「全局」对应 FALLBACK_NAMES 中的 GLOBAL，语义与行为均对称。
    // ⚠️ 防回归：“全局”已被独立至 FALLBACK_CN_RE，不可移入 EXCLUDED_CN_RE，否则兜底路径失效。
    const FALLBACK_CN_RE = /^全局$/;
    // ❗ 运行时配置断言：FALLBACK_CN_RE 与 EXCLUDED_CN_RE 对兜底关键词"全局"的覆盖必须互斥。
    {
        const _testWord = "全局";
        if (FALLBACK_CN_RE.test(_testWord) && EXCLUDED_CN_RE.test(_testWord)) {
            console.error(`❌ 配置断言失败："${_testWord}" 同时匹配 FALLBACK_CN_RE 和 EXCLUDED_CN_RE`);
            console.error(`   互斥约束被违反：兜底选取将被排除断言拦截，净效果为零，脚本中止注入`);
            return config;
        }
    }

    // 合法代理出口类型白名单（统一引用源：关键词优选/正则优选/类型优选各轮均引用此常量，新增类型只需改此处）。
    // ⚠️ 最终容错策略（第五轮）改用 _UNSUITABLE_TYPES 黑名单方式，不引用此常量；
    //    在现有已知类型集合内，两者从正反两侧描述同一批被排除类型（relay / url-latency-benchmark）；
    //    未知新增类型不在两集合中，由第五轮容错策略（_UNSUITABLE_TYPES 黑名单）处理。修改任一处须同步检查另一处。
    // load-balance 为动态路由策略，与 url-test 同级，具备合法出口语义，纳入白名单。
    // 被排除的类型（在此两个 Set 中均体现为排除）：
    //   relay：固定节点链路转发，强制指定出口，无用户可切换的节点选择语义。
    //   url-latency-benchmark：测速专用工具，以延迟评测为目的，不应作为流量出口组。
    //   smart：Mihomo v1.18+ 正式稳定类型，自适应出口选择，具备合法出口语义，已纳入白名单。旧版对 smart 行为不保证，若遇路由异常可回退：将 smart 从本 Set 移除。
    //   load-balance 已纳入 VALID_PROXY_TYPES（动态路由，具备合法出口语义），不再排除。
    //   注意：此处保留最低限度的类型语义过滤，而非彻底放开，因为彻底放开会导致 relay 等固定链路被选中，流量走预设链路而非用户期望的可切换代理，行为与预期不符。
    const VALID_PROXY_TYPES = new Set(["select", "url-test", "fallback", "load-balance", "smart"]);
    // ⚠️ 互补视图：与 VALID_PROXY_TYPES 正反两面描述同一批被排除类型，修改任一处须同步检查另一处。
    // 当前排除：relay（固定链路）/ url-latency-benchmark（测速工具）。smart 已从本 Set 移除并纳入 VALID_PROXY_TYPES。
    const _UNSUITABLE_TYPES = new Set(["relay", "url-latency-benchmark"]);

    // sanitizeName：统一不可见字符与 Bidi 控制符清理逻辑（完整字符集即 _SANITIZE_RE 定义，覆盖所有 C0 控制字符及常见不可见字符），防止视觉欺骗攻击与比较失配。
    // @param {string} name - 原始组名，函数内部负责清洗；调用方无需预先清洗，传入原始字符串即可。
    // @returns {string} 清洗后的组名（已移除不可见控制符并 trim）；非字符串输入返回空字符串。
    // ⚠️ g 是功能必要条件：需要清除字符串中所有不可见字符，而非仅首次命中。
    // ⚠️ u 标志（Unicode 模式）：确保字符类 [] 按完整 Unicode 码点解析，避免代理对被拆分匹配，语义更严谨；
    //    当前覆盖范围仅含 BMP 内字符（U+0000–U+FEFF），不加 u 在现有代码路径下无实际 bug，
    //    但加 u 是最佳实践，便于将来扩展覆盖范围时无需回头补加。
    const _SANITIZE_RE = /[\u0000-\u001F\u007F\u0085\u00AD\u061C\u200B-\u200F\u2028-\u202E\u2060\u2066-\u2069\uFEFF]/gu;
    function sanitizeName(name) {
        if (typeof name !== "string") return "";
        if (!name) return "";  // 短路返回，省去对空字符串的无意义正则调用
        // ⚠️ 若将来改用 exec()/test() 代替 replace()，须在调用前手动重置 lastIndex=0（g 标志正则有状态）；String.replace() 内部自动重置 lastIndex，此处无需显式重置。
        return name.replace(_SANITIZE_RE, '').trim();
    }

    // _isFallbackGroup / _isEligibleGroup：内部判定函数，直接接受已清洗的组名字符串（由调用方保证已通过 sanitizeName 处理）。
    // 所有调用者均使用预计算的 cleanName，无需在此二次清洗。
    // ⚠️ 调用顺序约束：_isEligibleGroup 中 _isFallbackGroup 必须先于 EXCLUDED_NAMES / EXCLUDED_CN_RE 检查执行，
    //    兜底组（GLOBAL/全局）须通过 _isEligibleGroup 初步关卡才能在第四轮降级路径中被选中；此顺序确保在互斥约束被意外违反时兜底路径仍有额外一层保障。
    // ⚠️ 集合互斥约束：FALLBACK_NAMES 中的值不应与 EXCLUDED_NAMES 重叠，若将 "REJECT" 等误加入 FALLBACK_NAMES，提前 return true 将旁路 EXCLUDED_NAMES 检查。
    //    上方运行时断言（FALLBACK_NAMES ∩ EXCLUDED_NAMES）从启动时保证此约束。
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
        // 预编译静态关键词正则（替代原 KEYWORDS 数组 + some/includes 多次子串搜索）：
        // /i 标志覆盖 ASCII 大小写变体（proxy/Proxy/PROXY/auto/AUTO 等），
        // 无需手动枚举多份硬编码字符串。中文字符与 emoji（🚀）在 /i 下无副作用，正常匹配。
        // ⚠️ /i 修复了原实现仅能匹配大写 AUTO 的遗漏（proxy/Proxy/auto-select 等混合大小写组名均无法命中），
        //    现覆盖 ASCII 大小写所有变体，为正确行为；含 auto 的组名（如 auto-select）是合法的代理出口。
        // ⚠️ g 标志：_KW_RE 不含 g 标志，RegExp.test() 无 g 时不修改 lastIndex，完全无状态，
        //    在 _groupsPrepped.find() 中多次调用 .test() 行为一致，无需担心状态污染。
        //    🚀（U+1F680）为 BMP 外字符，无 u 标志时作代理对匹配，现代 V8 引擎行为正确；若需严格 Unicode 语义可加 u 标志（/…/iu），当前不加亦无实际问题。
        // 不含 "global"（GLOBAL 由 FALLBACK_NAMES 单独处理），不含 "默认"（已被 EXCLUDED_CN_RE 覆盖，关键词层无需重复）。
        const _KW_RE = /节点(?:选择)?|手动选择|选节点|proxy|auto|自动|🚀|飞机|机场|线路|订阅|代理|选择/i;

        // 预计算所有组的 cleanName，避免各轮 find 各自对同一组名重复调用 sanitizeName。
        // 对含 100+ 代理组的大型订阅，最坏情况下五轮各遍历一次，sanitizeName（_SANITIZE_RE.replace）被执行 1×N 次 sanitize + 5×N 次正则测试；
        // 预计算降为 1×N，后续各轮直接引用 cleanName。
        const _groupsPrepped = config["proxy-groups"].map(g => {
            const cleanName  = sanitizeName(g?.name);
            const isFallback = _isFallbackGroup(cleanName);
            const isEligible = _isEligibleGroup(cleanName);
            return { g, cleanName, isFallback, isEligible };
        });

        // [优选·关键词] 关键词 / include-all / 多节点三路并联匹配（最优先，覆盖最广）
        // 各轮 find 统一返回完整条目 { g, cleanName }，由 _mainEntry 持有；不再拆解出 .g 后回头再次线性搜索 cleanName（双重 find 模式已消除）。
        let _mainEntry = _groupsPrepped.find(({ g, cleanName, isFallback, isEligible }) => {
            if (!isEligible || isFallback) return false;
            const typeOk    = VALID_PROXY_TYPES.has(g?.type);
            const nameMatch = _KW_RE.test(cleanName);
            const hasMany   = Array.isArray(g?.proxies) && g.proxies.length > 3;
            // length > 3（即 ≥ 4）：排除 proxies 数组近乎为空的极简占位组，如：["节点1","节点2","节点3"]（length=3，被排除），
            // ["节点1","节点2","节点3","节点4"]（length=4，通过），优先选入条目数量充足的组。
            // ⚠️ 注意：proxies 数组可包含三类条目：底层节点名称、其他策略组名称、内置代理名称（DIRECT / REJECT）；
            //   length > 3 衡量的是三类条目的总数，不等于底层节点计数。
            //   已知局限：全部条目均为策略组引用（无底层节点）时，阈值仍可成立，但被选中的组仍能正常委托子组路由，实际影响极小；后续多轮兜底进一步覆盖此场景。
            const includeAll = g?.["include-all"] === true || g?.["include-all"] === "true";
            // includeAll 仅接受 boolean true 或字符串 "true"（严格等值）；数字 1 / 其他 truthy 值不触发（有意严格，避免意外匹配）。
            return typeOk && (nameMatch || includeAll || hasMany);
        });

        // [优选·类型] 类型约束（放宽数量，任意合法出口类型）
        // 增加 Array.isArray + length > 0 约束，防止选中空 proxies 的 select 组。
        //   各策略数量约束对比：关键词/正则策略要求 length > 3，本策略与兜底降级策略均要求 length > 0；
        //   本策略放宽数量约束（> 0 而非 > 3）以扩大覆盖范围，避免漏选小型节点池。
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, cleanName, isFallback, isEligible }) =>
                isEligible && !isFallback &&
                VALID_PROXY_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
        }

        // [兜底降级] 降级选取（GLOBAL/"全局" 等，优选策略全部失败时才触发）
        // ⚠️ 不能直接取首个元素，订阅第一个组可能是 DIRECT，导致本脚本注入的代理规则失效（流量直连）
        // 保留类型过滤（与前三轮优选策略一致），防止选中固定链路（relay）和测速专用（url-latency-benchmark）；smart 已纳入 VALID_PROXY_TYPES，可被选中。
        if (!_mainEntry) {
            _mainEntry = _groupsPrepped.find(({ g, isFallback }) =>
                isFallback &&
                VALID_PROXY_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
            if (_mainEntry) {
                console.warn(`⚠️ 未找到优选代理组，降级使用兜底组 [${_mainEntry.g.name}]`);
            }
        }

        // [最终容错选取] 安全兜底（全部前置策略失败时的最后屏障）────────────────
        // 优选层策略（关键词/正则/类型）与兜底层降级策略全部失效时进入此分支。
        // 目的：在显式 return config 中止注入之前，尽力寻找可用组。
        // 策略：仅排除出口语义不适合的类型（relay / url-latency-benchmark），其他类型均允许；smart 已移入 VALID_PROXY_TYPES，此处不再排除。
        //   为减少用户干预成本，在无理想出口组时优先选取次优组而非中止注入；用户若发现路由异常，可通过添加关键词或调整组名来引导识别。
        //   注：load-balance 已纳入 VALID_PROXY_TYPES，不在 _UNSUITABLE_TYPES 排除列表中。
        if (!_mainEntry) {
            // [最终容错选取] 排除语义不适合做代理出口的类型（而非全部放开）
            // relay：固定节点链路转发，无节点选择语义，用户无法在其界面切换节点。
            // url-latency-benchmark：测速专用工具，以延迟评测为目的，不应作为流量出口组。smart 已移入 VALID_PROXY_TYPES，Mihomo v1.18+ 已稳定，不再列为不适用类型。
            _mainEntry = _groupsPrepped.find(({ g, isEligible }) =>
                isEligible &&
                !_UNSUITABLE_TYPES.has(g?.type) &&
                Array.isArray(g?.proxies) && g.proxies.length > 0
            );
            if (_mainEntry) {
                console.warn(`🚨 严重警告：关键词/正则/类型优选 + 兜底组降级全部失败，触发最终容错选取`);
                console.warn(`   已排除固定链路（relay）/ 测速专用（url-latency-benchmark）；smart 已纳入白名单，可被选中；`
                + `选取首个可用组 [${_mainEntry.g.name}] (type: ${_mainEntry.g.type ?? "未知"})`);
                console.warn(`   建议检查订阅结构是否符合关键词列表`);
            }
        }

        // _mainEntry 持有完整条目 { g, cleanName }，无需第二次线性搜索。
        const mainGroup = _mainEntry?.g;

        if (mainGroup?.name) {
            const rawGroupName = mainGroup.name;
            const cleanGroupName = _mainEntry.cleanName;

            // 若原始名含不可见字符，直接拒绝该组，保证后续规则安全
            if (rawGroupName !== cleanGroupName) {
                console.error(`❌ 代理组 [${rawGroupName}] 含不可见控制字符，拒绝使用以保证规则安全`);
                return config;
            }

            proxyGroupName = rawGroupName;   // 全程使用原始名称（Clash 内核所需）
            const groupFlag = _mainEntry.isFallback ? "⚠️" : "✅";
            console.log(`${groupFlag} 代理组识别成功: [${proxyGroupName}] (type: ${mainGroup.type ?? "未知"})`); // ⚠️=兜底组，✅=优选组
        } else {
            // 容错选取策略也失败：订阅中无任何可注入的代理出口组（全被排除或类型不适）。
            // 直接返回 config，完整降级为订阅原始规则，防止 Mihomo 内核因找不到策略组而崩溃。
            console.error("❌ 致命：订阅中没有任何可用的代理组，中止规则注入");
            console.error("   网络将走订阅原始规则，不注入任何自定义规则，防止 Mihomo 内核启动失败");
            console.log(`   已扫描的代理组:`);
            // _groupsPrepped 已预计算 cleanName，错误路径同样零额外 sanitizeName 调用
            _groupsPrepped.forEach(({ g, isEligible, isFallback }, idx) => {
                const status = !isEligible ? "❌" : (isFallback ? "⚠️" : "✅");
                const count = g?.proxies?.length ?? 0;
                console.log(`   ${idx + 1}. ${status} [${g?.name}] (${g?.type ?? "未知"}, ${count} 节点)`);
            });
            return config;
        }
    } else {
        // 此 else 仅在 proxy-groups 为空（length === 0）时执行。
        // 注意：即使 if 块内五轮策略全部失败，也不会到达此处，if/else 的判断条件是 proxy-groups.length，而非策略是否成功。
        // 直接返回 config，中止规则注入，防止 Mihomo 内核因找不到策略组而崩溃，使网络回退至订阅原始规则。
        console.error("❌ 致命：proxy-groups 为空，中止规则注入");
        console.error("   网络将走订阅原始规则，不注入任何自定义规则，防止 Mihomo 内核启动失败");
        return config;
    }

    // 💡 Mihomo 规则语法中策略组名直接使用原始名称，空格 / emoji 均无需引号。引号包裹反而会让内核把引号字符视为组名的一部分，导致 proxy not found 报错。

    // ❗ 代理组排除断言：防止 proxyGroupName 解析为排除出口导致拦截规则静默失效。
    // 覆盖全部排除名：DIRECT / REJECT / COMPATIBLE / DEFAULT / MATCH / PASS 及中文等价排除词。
    // 注：失败路径（全部策略失败 / proxy-groups 为空）均已在上方显式 return config，正常执行到此处时 proxyGroupName 必然是识别成功的合法组名；
    //     此断言作为防御纵深，防止将来新增代码路径绕过显式返回，或选组逻辑被重构后假设不再成立。
    // 注：兜底组已被剥离出排除正则，确保在优选降级触发时，它能顺利通过代理组排除断言而不被误杀。
    {
        const _sanitizedProxy = sanitizeName(proxyGroupName);
        if (!_sanitizedProxy ||
            EXCLUDED_NAMES.has(_sanitizedProxy.toUpperCase()) ||
            EXCLUDED_CN_RE.test(_sanitizedProxy)) {
            console.error(`❌ 代理组排除断言触发：proxyGroupName 解析为排除出口 [${proxyGroupName}]`);
            console.error(`   注入出口目标解析为排除项，allow/proxy 层路由将失效，脚本中止注入以保护配置安全边界`);
            return config;
        }
    }

    // ❗ 规则字段注入安全断言：proxyGroupName（原始值）不得含破坏 Clash 规则语法或 YAML 结构的字符。
    // 💡【设计意图：容错识别 vs 安全注入分离】
    //   sanitizeName 在"识别阶段"清洗组名，目的是宽容匹配，以兼容因编辑器或复制粘贴意外引入不可见控制符的代理组（如名称带 BOM 的组）。
    //   用户设置该组的本意是合法代理出口，不应因组名中意外混入的不可见字符导致识别阶段漏选。此断言在"注入阶段"对原始值实施一票否决，Mihomo 内核按原始名称匹配策略组，
    //   注入只能使用原始名；若原始名含控制符，会破坏 Clash 规则行语法，危及整个规则文件解析。
    //   清洗阶段（宽容匹配）确保控制符不导致漏选；注入阶段（严格校验）对原始值执行词法断言，防止语法破坏与注入攻击。
    // proxyGroupName 存储原始值（mainGroup.name），sanitizeName 的清洗结果不用于此处。清洗结果仅用于排除词汇匹配，注入时仍使用原始值。
    // 四类拒绝维度（不同攻击向量）。注：_SANITIZE_RE 与此断言存在字符集重叠，但两者作用层次不同（清洗识别副本 vs 拒绝注入原始值），目的不重叠，非冗余。
    // 💡 两层覆盖范围的完整差异说明见 _SANITIZE_RE 注释（权威定义源）；
    //    本断言为注入层权威说明：覆盖 Clash/YAML 语法破坏字符和 Bidi 控制符。u 标志确保按完整 Unicode 码点解析，与 _SANITIZE_RE 保持一致，便于将来扩展。
    if (/[,\[\]{}\u0000-\u001F\u007F\u0085\u200B-\u200F\u2060\u2066-\u2069\u2028-\u202E\uFEFF]/u.test(proxyGroupName)) {
        console.error(`❌ Token 断言触发：proxyGroupName [${JSON.stringify(proxyGroupName)}] 含非法字符`);
        console.error(`   逗号截断规则语义；方括号/花括号（[ ] { }）破坏 YAML 序列/映射语法；` 
        +`C0 控制字符（U+0000–U+001F，含 \\t/\\n/\\r）及 NEL（U+0085）破坏 Clash 规则语法；`
        +`以及零宽度字符 / Bidi 控制符（含 BOM）——均可导致内核规则解析异常或视觉欺骗，脚本中止注入`);
        return config; 
    }

    // ✅ 执行到此处时，proxy-groups 非空且 proxyGroupName 已赋值（空或识别失败均已 return config），此断言针对"选组逻辑重构后 proxyGroupName 与实际数组意外失配"的防御场景。
    // 正常执行路径下 proxyGroupName = mainGroup.name，必然存在于数组中；此断言针对的是选组逻辑被重构或调用方变更后该假设不再成立的情形，属防御纵深而非冗余。
    //
    // 💡 比较策略：使用原始名称精确匹配（g?.name === proxyGroupName），而非双侧 sanitizeName。
    //    理由：
    //    (1) Mihomo 内核按原始名称精确匹配策略组，存在性断言应当模拟 Mihomo 的匹配行为。
    //    (2) proxyGroupName = mainGroup.name，mainGroup 本身即从数组中取得，直接等价必然命中，双侧 sanitize 不提供任何额外防护。
    const groupExists = config["proxy-groups"].some(g => g?.name === proxyGroupName);
    if (!groupExists) {
        console.error(`❌ 存在性断言触发：代理组 [${proxyGroupName}] 在当前配置中不存在`);
        console.error(`   注入此组名会导致 Mihomo 内核启动失败，脚本中止注入`);
        return config;
    }

    // 💡 哨兵为合法三段式规则（见 _SENTINEL_START / _SENTINEL_END 声明）；纯注释字符串（如 "# START"）会导致内核加载失败。

    // ════════════ 2. 数据层（域名列表 + 注入辅助工具，在此维护） ════════════
    //
    // 规则构造辅助函数：逐项将域名 / 关键词转换为 Clash 规则字符串并追加到目标数组。
    // ⚠️ 调用方须确保数组元素均为字符串；非字符串元素（null / undefined / 数字）会被模板字符串静默转换，
    //    生成格式合法但语义非法的规则（如 DOMAIN-SUFFIX,null,REJECT），Mihomo 不报错但该规则永远不会命中。
    //    当前所有调用方均使用字符串字面量数组，无此风险；若将来从外部数据源动态填充，须在调用前校验元素类型。

    // ⚠️ 类型守卫：过滤非字符串或空元素，防止 null/undefined/数字被模板字符串静默转换为
    //    DOMAIN-SUFFIX,null,REJECT 等语义非法规则（Mihomo 不报错但规则永远不命中）。
    //    当前所有调用方均使用字符串字面量数组，守卫仅为将来动态数据源预防。
    const pushSuffix  = (domains, action, pool) => domains.forEach(d => {
        if (typeof d === "string" && d.length > 0) pool.push(`DOMAIN-SUFFIX,${d},${action}`);
        else console.warn(`[Script] pushSuffix: 非法条目已跳过`, d);
    });
    const pushDomain  = (domains, action, pool) => domains.forEach(d => {
        if (typeof d === "string" && d.length > 0) pool.push(`DOMAIN,${d},${action}`);
        else console.warn(`[Script] pushDomain: 非法条目已跳过`, d);
    });
    const pushKeyword = (words,   action, pool) => words.forEach(w => {
        if (typeof w === "string" && w.length > 0) pool.push(`DOMAIN-KEYWORD,${w},${action}`);
        else console.warn(`[Script] pushKeyword: 非法条目已跳过`, w);
    });

    // ──── Adobe Firefly 依赖端点集（统一引用源：所有用到该集合的地方均引用此数组，修改时无需同步多处）────
    // adobeFireflyOnly 独立成数组（而非并入 adobeSuffix），是因为两者路由动作不同：
    // adobeFireflyOnly 在 isFireflyActive=true 时走代理（allow 层），adobeSuffix 始终走 REJECT（block 层）；合并会丢失路由区分能力。
    //
    // 路由动作由 isFireflyActive 决定：
    //   isFireflyActive=true  → pushSuffix(adobeSharedDeps, proxyGroupName, layerPools.allow) → 走代理
    //   isFireflyActive=false → pushSuffix(adobeSharedDeps, "REJECT",       layerPools.block) → 走拦截
    //   两条分支覆盖相同域名集合，行为对称，单一维护点，修改只需改此数组。
    // adobe 相关变量命名：
    //   adobeFireflyOnly：Firefly AI 生成式专属（clio, firefly-api 等）
    //   adobeSharedDeps：共用鉴权端点，Firefly 和其他 Adobe 功能（同时被用于 CC 激活验证）共同依赖的鉴权/授权端点
    //
    // ⚠️【Firefly 依赖链放行】auth.services.adobe.com / cc-api-cp.adobe.io 同时承载 CC 正版验证心跳。
    //   isFireflyActive=true 时放行后，以下进程的鉴权请求均走代理，而进程规则仅覆盖 AdobeGCClient.exe：
    //     AdobeGCClient.exe  ← 由 processBlockRules REJECT-DROP（静默丢包，见下方说明）兜底（已覆盖）
    //     Creative Cloud.exe ← CC 桌面客户端含授权心跳（基于依赖链考量的必要豁免：心跳放行不触发重验证，TUN 进程规则本身不可靠）
    //     CCXProcess.exe     ← CC 扩展宿主进程（同 Creative Cloud.exe，必要豁免）
    //     CoreSync.exe       ← CC 同步守护进程（同上）
    //   取舍依据：非官方激活环境中，补丁修改了 AdobeGCClient.exe 的本地验证逻辑（本地返回激活成功，无需真实网络应答）；
    //   本脚本在此基础上阻断其出站连接，作为额外网络层防线，防止激活状态回报和设备信息上传。
    //   其余进程的心跳即便放行也不会触发重新验证。进程规则本身需管理员+TUN，不可靠。
    //
    // ⚠️【QUIC（RFC 9000；基于 UDP 的安全传输协议，内嵌 TLS 1.3）豁免机制】Firefly 相关 .adobe.io 域名在 udpBlock 之前注入（first-match），
    //   其 UDP 流量先命中 allow 层走代理，udpBlock 的 adobe.io 通配不再执行。
    //   → 豁免效果由注入顺序自动保证（allow 层先于 udpBlock 入 pool，先命中即生效），无需额外处理。
    //   ⚠️ 前提：此豁免仅在 Mihomo 能识别 SNI 或存在 Fake-IP 映射时成立。
    //      ECH（Encrypted Client Hello，将 SNI 加密）会使 Sniffer 失效，但影响范围取决于寻址路径：
    //      · 路径A（Fake-IP + TUN，CVR 默认配置路径）：域名已由 DNS 映射阶段记录，ECH 不影响豁免效果，
    //        allow 层 DOMAIN-SUFFIX 正常命中，Firefly QUIC 流量正常走代理。
    //      · 路径B（应用绕过 Mihomo DNS，使用 DoH / DoT 或硬编码 IP）：无 Fake-IP 映射，
    //        Sniffer 又被 ECH 阻断，allow 层与 udpBlock 的域名规则同时失效，
    //        Firefly QUIC 流量不受规则层干预，滑落至 MATCH（详见 udpBlock 末尾说明）。
    const adobeSharedDeps = [
        // ──── 已确认条目（抓包或官方资料可支撑）────
        "ims-na1.adobelogin.com",                 // 登录令牌刷新（已确认）
        "adobeid-na1.services.adobe.com",         // Adobe ID 服务（已确认）
        "auth.services.adobe.com",                // Adobe ID 鉴权，Firefly Token 来源（已确认）
        "cc-api-cp.adobe.io",                     // CC 权限校验，含 Firefly 订阅验证（已确认）
        "cc-api-data.adobe.io",                   // CC 生成结果存储（已确认）
        "lcs-roaming.adobe.io",                   // 授权漫游，Firefly 订阅状态同步（已确认）

        // ──── 待抓包确认条目（基于行为和命名推断，非官方文档支撑）────
        // ⚠️ 设计取舍：优先可用性（Firefly 正常运行），而非最小权限拦截原则。以下域名尚无公开抓包资料确认其确切功能，但 Firefly 在实测中依赖这些端点，故默认放行。
        //    若追求最严格的拦截策略，可手动将其移至 adobeSuffix（改为 REJECT）并重新测试 Firefly 功能是否正常，确认后再决定是否从本数组移除。
        "scdown.adobe.io",                        // 【推断·放行风险低、漏拦截风险可接受】基于行为推断，未经抓包验证；Firefly 在实测中依赖此端点（即使功能定义不明）
        // lcs-cops.adobe.io 已移出：注释原文承认"若此域实为 CC 激活验证端点，isFireflyActive=true 时将被错误放行，激活拦截防线出现缺口"。
        // 为消除该缺口，改为固定注入 adobeSuffix（始终 REJECT），待抓包确认其为 Firefly 专属后可移回此数组。
    ];

    // 🚫 ─────────────────────── Adobe 激活 / 遥测核心拦截 ───────────────────────
    // 💡 关于 REJECT vs REJECT-DROP（Mihomo 的两种拒绝策略）：
    //    REJECT      发送 TCP RST（TCP 侧）/ ICMP Port Unreachable（UDP 侧），软件快速感知失败（通常切换离线模式或放弃重试），启动无卡顿，推荐用于遥测/授权域名。
    //    REJECT-DROP 静默丢包，不回应任何数据包（TCP 和 UDP 均适用），
    //                TCP 侧：软件 Socket 陷入 SYN_SENT 直至系统 TCP 超时；
    //                UDP 侧：数据包被无声丢弃，软件等待响应直至应用层超时；
    //      超时时长为估算值（非固定值），应用层 Socket 阻塞约 15–30s（含 TCP 重传轮次），实际取决于操作系统 TCP 重传配置（Windows 10 默认 TcpMaxSynRetransmissions=2，
    //      SYN 重传总时长约 21s；Windows 11 默认值已调整，实际超时可能有所不同）。仅用于非官方修改补丁后门（backdoorSuffix/backdoorKeyword）和进程规则，
    //      以此拖延被拦截进程感知失败的时间（Socket 等待超时而非立即失败），阻碍恶意程序快速识别阻断并切换备用通信方式/域名，降低其自适应速度。
    //
    // adobeSharedDeps 条目已移出（路由动作由 isFireflyActive 决定），此处为非 Firefly 依赖的拦截域名。
    const adobeSuffix = [
        "adobestats.io",                          // 统计上报主域
        "activate.adobe.com",                     // 激活核心
        "lmlicenses.wip4.adobe.com",              // Adobe 许可证管理服务（wip4 疑似集群标识，功能已抓包确认）
        "prod.adobegenuine.com",                  // Genuine Integrity Service（正版完整性验证服务）
        "na1e.services.adobe.com",                // Genuine 服务备用
        // "adobedtm.com",                           // Adobe DTM 旧版遥测域（DTM 已于 2021 年停止维护，新版 CC 不再依赖此域），可能仍有旧版 CC 存量实例使用
        "crs.cr.adobe.com",                       // License check（许可证检查）
        "cclibraries-defaults-cdn.adobe.com",     // CC Libraries 默认资源 CDN（内容分发网络），拦截后会导致跨 CC 应用的共享资源库无法加载默认资源，影响正版用户。
        "adobesearch.adobe.io",                   // 搜索遥测
        "p13n.adobe.io",                          // 个性化遥测（p13n = personalization 字符数缩写）
        "ic.adobe.io",                            // Insight Collector（洞察收集器）
        "lcs-mobile.adobe.io",                    // 新版 CC 移动端授权
        "adobe-dns.adobe.com",                    // Adobe 自有 DNS 服务（拦截后可减少软件绕过系统 DNS、向自有解析器查询激活/遥测 IP 的可能性，降低 hosts 层拦截被旁路的概率）
        "adobe-dns-2.adobe.com",                  // Adobe 自有 DNS 备用节点 2（同上）
        "adobe-dns-3.adobe.com",                  // Adobe 自有 DNS 备用节点 3（同上）
        "practivate.adobe.com",                   // 预激活服务
        "lm.licenses.adobe.com",                  // License Manager（许可证管理器）
        "genuine.adobe.com",                      // 正版验证
        "oobesaas.adobe.com",                     // Adobe SaaS 授权验证服务（oobesaas 为 Adobe 内部命名，与 Windows OOBE 无关；阻断后抑制授权弹窗）
                                                   // 注：ffc-static-cdn.oobesaas.adobe.com 已被此 SUFFIX 完整覆盖，无需单独列出
        "sstats.adobe.com",                       // 实时统计上报（新版 CC 框架）
        "entitlementauthz.adobe.com",             // 授权（Authorization）验证服务（authz 为 authorization 缩写，2025 年新增）
        "assets.entitlement.adobe.com",           // 授权资产校验（2025 年新增）
        "telemetry.adobe.com",                    // Adobe 遥测的另一入口，在部分 CC 版本抓包中出现
        "lcs-cops.adobe.io",                      // 云端授权策略端点（待抓包确认 Firefly 专属性）。原位于 adobeSharedDeps（isFireflyActive=true 时走代理），
                                                  // 因存在激活拦截缺口风险，改为固定 REJECT。若抓包确认其仅服务 Firefly 而非 CC 激活验证，可将其移回 adobeSharedDeps。
    ];

    // ──── 随机子域正则（统一引用源），adobeRegex 与 udpBlock 均引用此变量，禁止各自硬编码，修改只需改此处 ────
    // 注：实际遥测子域通常为小写十六进制字符（0-9a-f），正则使用全字母数字范围（A-Za-z0-9）为稳妥覆盖，不影响正确性。
    // ⚠️ ^$ 锚定不可移除：Go regexp.MatchString 为子串匹配，若移除锚定，
    //    "abcdefgh.adobe.io.evil.com" 也会命中（子串 abcdefgh.adobe.io 满足 {8,12} 模式），
    //    导致非 adobe.io 域名被错误拦截（过拦截误伤 false positive），而非 adobe.io 的流量无辜受殃。
    // 注意：adobestats.io 已在 adobeSuffix 以 DOMAIN-SUFFIX 全覆盖（含所有子域），
    // 本 REGEX 在实际注入顺序下被前置 SUFFIX 规则遮蔽，功能冗余但无害；保留的意义仅为正则规则集的完整性表达。
    const _ADOBE_RAND_RE_STR      = "^[A-Za-z0-9]{8,12}\\.adobe\\.io$";      // adobe.io 随机子域（8-12位）
    const _ADOBESTATS_RAND_RE_STR = "^[A-Za-z0-9]{10}\\.adobestats\\.io$";   // adobestats.io 随机子域（社区记录为固定10位，若实测发现其他长度，请调整此正则）

    // 正则：拦截随机子域（遥测特征：8-12 位随机字符）改用 REJECT（非 REJECT-DROP）：
    // 遥测随机子域无"拖延感知"的必要，此类域名不存在切换备用域名的自适应逻辑，
    // REJECT 让软件快速感知失败（通常切换离线模式或放弃重试），避免 15–30s 超时卡顿影响 PS 启动体验。
    const adobeRegex = [
        `DOMAIN-REGEX,${_ADOBE_RAND_RE_STR},REJECT`,
        // ⚠️ senseicore（10位）/ senseimds（9位）也满足 _ADOBE_RAND_RE_STR，但均为具名服务域名而非随机遥测子域。
        //    · isFireflyActive=true：adobeFireflyOnly 精确 SUFFIX 先命中 allow 层，此正则对两者无效（已豁免）。
        //    · isFireflyActive=false：两者将被此 REGEX 命中并 REJECT（立即返回失败），
        //      用户表现为 PS Neural Filters / Select Subject 等依赖 Sensei 的 AI 功能立即报错，而非卡死 15–30s，改 REJECT 后用户可快速判断为网络拦截而非软件 bug。
        //      ❗【待抓包确认】若确认 senseicore/senseimds 同时服务非 Firefly 的 PS AI 功能，
        //      建议将其显式加入 adobeFireflyOnly（精确放行走代理）或 adobeSuffix（以精确 DOMAIN-SUFFIX 替代当前 REGEX 覆盖，动作不变仍为 REJECT）
        `DOMAIN-REGEX,${_ADOBESTATS_RAND_RE_STR},REJECT`,
    ];

    // QUIC（RFC 9000；基于 UDP 的安全传输协议，内嵌 TLS 1.3）/ UDP 拦截：强制 Adobe 应用放弃 QUIC（HTTP/3），降级至 TCP（HTTP/1.1 或 HTTP/2）再被域名规则捕获
    // ❗ 生效前提：仅 TUN 模式。UDP 拦截规则在系统代理模式下完全无效。
    // ⚠️ DOMAIN-SUFFIX / DOMAIN-REGEX / DOMAIN-KEYWORD 类规则依赖 Mihomo 能获取域名信息：
    //    Mihomo 通过 DNS 解析映射（已走 Mihomo DNS 的流量）或 Sniffer（嗅探 QUIC 握手 SNI）识别域名；
    //    纯 IP 形式的 UDP/QUIC 流量无域名信息可供匹配，DOMAIN 类规则对其无效。
    // ⚠️ PROCESS-NAME 规则不依赖 SNI 嗅探（通过系统 Socket 直接获取进程信息），在路径B（应用绕过 Mihomo DNS 且开启 ECH，DOMAIN 类规则全部失效）下，
    //    是唯一有效的域名无关进程级拦截手段；路径A（Fake-IP 正常）下 DOMAIN 规则已生效，PROCESS-NAME 为附加纵深而非唯一防线。
    //
    // 改用 REJECT（非 REJECT-DROP）：UDP 阻断目的仅是强制 TCP fallback，无需"拖延感知"效果。
    // REJECT 发送 ICMP Port Unreachable，应用立即感知 QUIC 不可达并 fallback 至 TCP，比 REJECT-DROP 的 15–30s 超时 fallback 快得多，用户体验更好。
    //
    // ⚠️【directRules 中 adobe.com 子域的 UDP 路径说明】
    //    fonts.adobe.com / color.adobe.com 等在 directRules 中配置为 DIRECT。
    //    其 UDP（QUIC）流量先命中 AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT（下方第三条），
    //    收到 ICMP 后应用立即 fallback 至 TCP，TCP 连接再命中 directRules 的 DOMAIN-SUFFIX,DIRECT。
    //    整体路径：UDP→REJECT（立即） → TCP fallback → DIRECT。无延迟，行为符合预期。
    //
    // AND 条件书写顺序按代价从低到高排列（设计意图：期望内核能够尽早排除低代价条件后跳过高代价求值）：
    // NETWORK（读包头）→ DST-PORT（整数比较）→ DOMAIN-*（依赖 SNI 嗅探）实际求值顺序依赖 Mihomo 内核实现，此处为书写规范而非内核行为保证。
    const udpBlock = [
        // ⚠️ 以下各条均依赖 Mihomo DNS 映射或 Sniffer SNI 嗅探才能识别域名；
        //    纯 IP 形式 QUIC 流量或路径B（绕过 Mihomo DNS 且开启 ECH）下，DOMAIN 类规则对此无效（见末尾说明）
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT",           // 阻断 adobe.io 所有 UDP 流量（含 QUIC/443），强制回退 TCP
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT",      // 阻断统计域所有 UDP 流量（含 QUIC/443）
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT",          // 阻断 adobe.com 所有 UDP 流量（含 QUIC/443）
        `AND,((NETWORK,UDP),(DOMAIN-REGEX,${_ADOBE_RAND_RE_STR})),REJECT`, // 阻断随机子域 QUIC（遥测特征，8-12位，引用 _ADOBE_RAND_RE_STR 统一引用源）
        // ⚠️ 转义链路：JS 字符串 "\\." → 字符串值 "\." → Mihomo Go regexp 接收 \. → 匹配字面点。
        //    AND 规则内嵌 DOMAIN-REGEX 的括号解析基于 Mihomo v1.15+ 实测；旧版可能静默忽略整条 AND 规则，
        //    此时 udpBlock 其余精确条目（DOMAIN-SUFFIX）仍有效，此条失效不影响整体覆盖。
        // "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-KEYWORD,adobe)),REJECT", // 兜底：UDP + 443端口 + adobe 关键词，覆盖未列举子域
        // ⚠️ 可靠性存疑：纯 UDP 流量无 TLS SNI 时，DOMAIN-KEYWORD 可能无域名信息可供匹配，
        //    Mihomo 需开启 Sniffer（dns.sniffer）解析 QUIC 握手 SNI 才能识别域名；
        //    实际生效取决于 Mihomo 版本，不可作为唯一防线，上方精确规则为主要覆盖。
        //
        // ⚠️【ECH 架构级边界——仅适用于绕过 Mihomo DNS 的场景。详见 adobeSharedDeps 注释中的路径A/B 分析】
    ];

    // Adobe WebSocket 遥测（2025 年新增：以 WSS（WebSocket Secure）建立持久 TCP 长连接上传遥测；
    //   WSS 握手阶段走标准 HTTP Upgrade 请求，升级后转为全双工 WebSocket 持久连接，
    //   与常规 HTTP 轮询/REST 调用模式不同；udpBlock 仅覆盖 UDP，此 TCP 路径须单独注入 DOMAIN 规则拦截）
    // ⚠️ 使用 DOMAIN 精确匹配（而非 DOMAIN-SUFFIX）：WSS 走 TCP，而 udpBlock 仅覆盖 UDP，无法拦截此类流量；
    //    目前仅有此一个已知端点，无多级子域的抓包证据，保守使用精确匹配，等待后续抓包资料支持后再评估是否扩展。
    const adobeWsDomain = [                // 如后续抓包发现更多 WSS 端点，在此数组补充
        "wss.adobe.io",                    // 前缀 wss 推断为 WebSocket Secure 遥测端点，待抓包确认（新版 CC 框架）。wss 仅 3 字符，不满足随机子域长度正则，必须显式列出
    ];

    // 🔓 ─────────────── Firefly 生成式 AI 专属放行域名（不含 adobeSharedDeps）───────────────
    // 原则：精确放行 Firefly AI 请求，保留其余激活/遥测域名的拦截。
    //
    // 【域名分类】
    // Firefly 依赖端点集：已统一到 adobeSharedDeps（统一引用源），此处仅含 Firefly/Clio/Sensei 专属 AI 域名。
    // 用于 Adobe AI 生成式填充，需在拦截层中优先放行，走代理以确保可用性：
    //   firefly.adobe.com / firefly.adobe.io / firefly-api.adobe.io /
    //   firefly-cliov2.adobe.com / clio.adobe.io / clio-prober.adobe.io /
    //   clio-assets.adobe.com / senseicore.adobe.io / senseimds.adobe.io
    //
    // ⚠️【必要妥协】adobeSharedDeps 同时承载 CC 正版验证心跳，
    //           放行后激活拦截的最终防线为 PROCESS-NAME,AdobeGCClient.exe → REJECT-DROP（需 ENABLE_PROCESS_RULE=true + TUN 模式 + 管理员权限，进程规则本身不可靠）。
    //           其余未覆盖进程详见 adobeSharedDeps 注释中的 Firefly 依赖链放行。
    // 关于 udpBlock 与 Firefly .adobe.io 域名的 QUIC 豁免机制：
    //   最终规则池展开顺序（由 LAYER_ORDER 决定，allow → block，与 push 调用书写顺序无关）：
    //   allow 层规则先于 udpBlock 入 pool（LAYER_ORDER: allow > block）；Firefly 域名的 UDP 流量先命中 allow 层走代理；
    //   udpBlock 的 adobe.io 通配不再参与匹配；前提：Mihomo 能识别 SNI 或存在 Fake-IP 映射（见路径A/B分析）。
    //   Mihomo first-match（首条命中生效）：Firefly 域名的 UDP 流量先命中 allow 层走代理，udpBlock 的 AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)) 不再执行。
    //   → 豁免效果由注入顺序自动保证（allow 层先于 udpBlock 入 pool，先命中即生效），无需额外处理。⚠️ 前提：此豁免仅在 Mihomo 能识别 SNI 或存在 Fake-IP 映射时成立。
    //   ⚠️ ECH 路径分析同上，详见 adobeSharedDeps 注释。
    const adobeFireflyOnly = [
        // Firefly AI 核心。
        "firefly.adobe.com",                      // Firefly 主服务入口
        "firefly.adobe.io",                       // Firefly API（.io 端点）
        "firefly-api.adobe.io",                   // PS 生成式填充调用入口
        "firefly-cliov2.adobe.com",               // Firefly Clio v2 模型接口
        // Clio 生成模型。
        "clio.adobe.io",                          // Clio 生成模型主接口
        "clio-prober.adobe.io",                   // Clio 功能可用性探针
        "clio-assets.adobe.com",                  // Clio 生成结果资源 CDN（内容分发网络）
        // Sensei AI 平台。
        "senseicore.adobe.io",                    // Sensei AI 服务核心
        "senseimds.adobe.io",                     // Sensei 模型分发服务（MDS = Model Distribution Service）
    ];

    // ─────────────────────── CorelDRAW 全家桶激活拦截 ───────────────────────
    // ⚠️ 不拦截整个 corel.com，否则官网无法访问（见 directRules）
    const corelSuffix = [
        "activation.corel.com",                   // 激活验证入口
        "licensing.corel.com",                    // 许可证服务
        "license1.corel.com",                     // 许可证服务器 1
        "license2.corel.com",                     // 许可证服务器 2
        "mc.corel.com",                           // 会员验证
        "ipm.corel.com",                          // In-Product Messaging（产品内弹窗消息）服务
        "ipm2.corel.com",                         // IPM 备用节点
        "telemetry.corel.com",                    // 统计上报
        "world.corel.com",                        // 消息推送 + 序列号黑名单检查
    ];

    // ───────────── Autodesk (CAD / 3dsMax / Maya) 激活与遥测拦截 ─────────────
    const autodeskSuffix = [
        "adlm.cloud.autodesk.com",               // 许可验证主域（最重要，ADLM = Autodesk Desktop Licensing Module）
        "adlm-autodesk.com",                     // ADLM 独立许可域
        "licensing-autodesk.com",                // 许可证服务备用域
        "api.entitlements.autodesk.com",         // 授权 API 接口
        "telemetry.autodesk.com",                // 遥测上报
        "usage.autodesk.com",                    // 使用统计上报
        "metric.autodesk.com",                   // 性能指标上报
        "crashreport.autodesk.com",              // 崩溃报告上传
        "dlm.autodesk.com",                      // Download Manager（下载管理器）版本检查
        "adsklicensing.com",                     // Autodesk 许可服务独立域
        "clic.autodesk.com",                     // 核心授权验证（CLIC 推测为 Cloud LICensing 缩写，无官方资料确认）
        "genuine-software.autodesk.com",         // 正版验证服务
        "edge.activity.autodesk.com",            // 活动/行为追踪
        "developer.api.autodesk.com",            // 开发者 API（含许可验证）
        "autodesk.com.edgekey.net",              // Akamai CDN 节点（授权验证回源；同时承载官网静态资源和更新下载，如官网访问异常，可注释此条并改用进程规则兜底）
        "crp.autodesk.com",                      // 云渲染授权（CRP = Cloud Rendering Platform）
        "autodesk.flexnetoperations.com",        // Revenera FlexNet Operations 许可云平台（Autodesk 租户子域，第三方托管）
    ];
    // Autodesk 精确域名匹配（防误伤子域，不用 SUFFIX）。
    const autodeskDomain = [
        "ipm-aem.autodesk.com",                  // 弹窗消息（精确匹配，防误伤子域）
    ];
    // DOMAIN-KEYWORD 杀伤力较强，仅针对 Autodesk 特有模块关键词。
    //
    // ──────────── BLOCK vs AGGRESSIVE 重叠说明（设计意图，禁止清理）────────────
    // 与 aggressiveRules 中同名条目为纵深防御，无副作用，勿删。
    // ─────────────────────────────────────────────────────────────
    const autodeskKeyword = [
        "adlm",                                  // Autodesk Desktop Licensing Module（桌面许可证模块）
                                                 // ⚠️ 因 SUFFIX 规则注入顺序在 KEYWORD 之前（pushSuffix 先调用），first-match 语义下 SUFFIX 先命中。
                                                 //    KEYWORD "adlm" 额外覆盖 autodesk 体系外含 adlm 子串的第三方域名；已知此类域名不存在，属防御性冗余，可接受。
        "telemetry.autodesk",                    // Autodesk 遥测模块关键词兜底
        "entitlement.autodesk",                  // Autodesk 授权模块关键词兜底（见上方 BLOCK vs AGGRESSIVE 说明注释块）
    ];

    // ─────────────── 第三方非官方修改补丁后门（高危，强烈建议保留）───────────────
    // 这些域名会回传设备信息，甚至下发新的远程控制指令。
    const BACKDOOR_BASE_DOMAINS = [
        "966v26.com",                            // 非官方修改补丁后门主域（回传设备信息）
        "vposy.com",                             // 知名非官方修改补丁作者域名（Adobe/Office）
        "api.pzz.cn",                            // 国内非官方修改补丁回传接口
        // "cc-cdn.com",                            // 【待观测】命名形似 Adobe CC CDN，无抓包证据，保守纳入；可信度低于前三条。若误命中合法 CDN，会导致启动卡顿
    ];
    const backdoorSuffix = [...BACKDOOR_BASE_DOMAINS];
    // 关键词兜底：覆盖 966v26.net / cdn.966v26.org 等非 .com TLD（顶级域名，Top-Level Domain）变种，REJECT-DROP 策略与 backdoorSuffix 一致。
    // ⚠️ 误命中风险评估："966v26" 为高特异性域名特征字符串（抓包来源），在已知合法域名中无任何同名子串，实际误命中概率极低。
    //    若将来发现误命中（如某 CDN 域名恰好含此子串），可将 REJECT-DROP 改为 REJECT 降低影响面；但鉴于字符串高度随机性，此情形极不可能发生，当前策略可接受。
    const backdoorKeyword = ["966v26"];

    // ──────────── IDM / Bandicam / Wondershare 等其他软件激活拦截 ────────────
    const idmSuffix = [
        "registeridm.com",                       // IDM 注册验证域
        // "internetdownloadmanager.com",        // ⚠️ 已注释：拦截主域误伤官网，改用下方精确子域
        "secure.internetdownloadmanager.com",    // 序列号验证接口
        "mirror.internetdownloadmanager.com",    // 更新镜像服务器
        "mirror2.internetdownloadmanager.com",   // 更新镜像服务器
        "mirror3.internetdownloadmanager.com",   // 更新镜像服务器
        "idm-patch.com",                         // IDM 非官方修改补丁域（安全风险）
        "idm-update.com",                        // IDM 非官方更新域（安全风险）
    ];
    const idmKeyword = [
        "tonec",          // IDM 开发商 Tonec Inc. 的品牌名，覆盖 tonec.com 等序列号验证相关子域。
    ];

    const wondershareSuffix = [
        "activation.wondershare.com",             // Wondershare 激活验证入口
        "license.wondershare.com",                // 许可证验证服务
        "wondershare.cc",                         // Wondershare 海外追踪/统计域
        "wondershare.cn",                         // Wondershare 国内遥测/统计域
        // "iskysoft.com",  // ⚠️ 已注释：主域即官网，无已知专用验证子域，拦截主域将导致官网无法访问。如有抓包确认的验证子域，请替换为精确条目。
        // "imyfone.com",   // ⚠️ 已注释：同上，主域即官网，无已知专用验证子域。
    ];

    // 所有注释条目均因误伤官网而改用精确 DOMAIN 匹配，已移至 miscSoftwareDomain。
    const miscSoftwareSuffix = [
        // "bandicam.com",    // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "bandisoft.com",   // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "xmind.app",       // ⚠️ 已注释：主域误伤官网（含正版用户同步/分享功能），改用下方精确子域
        // "xmind.net",       // ⚠️ 已注释：主域误伤官网（XMind 8 下载/插件），改用下方精确子域
        // "listary.com",     // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // ⚠️ typora.io 是官网主域，直接拦截会导致插件/主题无法下载。精确拦截授权验证子域，放行主站：typora.io / store.typora.io
    ];
    const miscSoftwareDomain = [
        // ──────────────────────── Bandisoft 家族 ────────────────────────
        "cert.bandicam.com",    // Bandicam 正版证书/激活验证核心
        "ssl.bandisoft.com",    // Bandizip/Bandicam 全家桶授权验证核心
        "dl.bandisoft.com",     // 更新下载/版本心跳（不影响离线使用；如需更新可临时放开）

        // ───────────────────────────── XMind ─────────────────────────────
        // 来源：多份抓包记录及 hosts 屏蔽教程（CSDN / 博客园 / 52pojie）
        // XMind 2020+（Electron）与 XMind 8（Java）均通过以下域名验证授权：
        "www.xmind.app",        // XMind 2020+ 授权验证主接口（Electron 版）
        "www.xmind.net",        // XMind 8 授权验证接口（Java 版）/ 更新检查
        "www.xmind.cn",         // XMind 中文站授权验证 / 国内更新检查
        "dl2.xmind.cn",         // XMind 8 更新安装包下载 CDN（版本检查由 www.xmind.net 触发，此域仅承载安装包分发）
        // ⚠️ 扩展提醒：如需追加其他 XMind 子域，请注意 api.xmind.net / api.xmind.app 等 API 端点可能承载功能性请求（而非仅授权验证），拦截前应抓包确认，避免影响正常使用。

        // ──────────────────────────── Listary ────────────────────────────
        // 来源：社区抓包记录（非官方文档），support 子域为目前唯一有记录的联网端点。其他子域名（api.listary.com 等）无公开资料，不添加以免误判。
        "support.listary.com",  // 激活/授权验证接口（精确匹配，防误伤主站）

        // ──────────────────────── WinRAR (RARLAB) ────────────────────────
        // 来源：CVE-2021-35052 安全报告；Wireshark/Burp 抓包记录；rarlab.com 官网。
        "notifier.rarlab.com",  // 广告弹窗 / 试用到期通知页面。CVE-2021-35052：该域曾被中间人攻击利用执行任意代码。屏蔽同时消除安全风险 + 关闭广告弹窗。

        // ──────────────────────────── Typora ────────────────────────────
        "license.typora.io",    // Typora 授权验证接口
        "verify.typora.io",     // Typora 激活校验
    ];

    // ────────────────── 微软 & Office 遥测（不影响正常使用）──────────────────
    // 微软遥测改用 REJECT（立即返回 RST，避免 TCP 重传开销）。
    const msTelemSuffix = [
        "telemetry.microsoft.com",               // Windows/Office 遥测主域
        "v20.events.data.microsoft.com",         // Windows 诊断数据 v2.0
        "v10.events.data.microsoft.com",         // Windows 诊断数据 v1.0
        "nexus.officeapps.live.com",             // Office 遥测上报
        "officeclient.microsoft.com",            // Office 客户端统计
        "vortex.data.microsoft.com",             // Windows 错误报告
        "settings-win.data.microsoft.com",       // Windows 诊断数据上报端点（非设置同步；settings-win 为历史命名，实为诊断遥测）
        "watson.telemetry.microsoft.com",        // Watson 崩溃报告服务
    ];

    // ────────────────────────── 广告联盟、遥测、追踪、弹窗、强制更新──────────────────────────
    const adsSuffix = [
        // WPS
        "ups.k0s.gk.kingsoft.com",               // WPS 升级推送服务
        "pcfg.wps.cn",                           // WPS 配置/广告下发
        "wps.com.cn",                            // WPS 备用主域（.com.cn 为金山注册的备用主域）
                                                 // ⚠️ 全域 SUFFIX 拦截（含所有子域）；无抓包资料确认其子域仅含遥测端点，拦截后可能影响账号类或功能类子域。
                                                 //    若发现登录异常，可改用精确子域 DOMAIN 匹配（与 360.cn 的保守策略一致：主域放行，仅拦截已确认的遥测子域）
        "wpsgold.wpscdn.cn",                     // WPS 广告资源 CDN（内容分发网络）
        // "sync.wps.cn",                        // ⚠️ 已注释：WPS 云文档同步，拦截后云同步失效
        // 海康威视（仅精确子域，主域不拦截）
        // ⚠️ 若使用海康摄像头/NVR/DVR 设备，建议注释以下三条：
        //   upgrade.hikvision.com  拦截后设备无法检测固件更新。
        //   ezdns.hikvision.com    拦截后 DDNS（Dynamic DNS，动态域名解析）功能失效，远程访问中断。
        //   cloudmsg.hikvision.com 拦截后萤石云/APP 推送通知失效。
        "upgrade.hikvision.com",                 // 海康固件升级检查（可触发静默下载）
        "ezdns.hikvision.com",                   // 海康 DDNS（动态域名解析）回传（拦截后远程访问中断）
        "cloudmsg.hikvision.com",                // 海康云消息推送
        // 向日葵远程（仅遥测子域，oray.com 主域不宜拦截）
        "sunloginlog.oray.com",                  // 向日葵日志上报
        "report.oray.com",                       // 向日葵行为上报
        // ToDesk 远程。
        "log.todesk.com",                        // ToDesk 日志上报
        "report.todesk.com",                     // ToDesk 遥测上报
        // 百度输入法。
        "shurufa.baidu.com",                     // 百度输入法云服务
        "input.baidu.com",                       // 百度输入法联网同步
        // 搜狗输入法（精确子域补充，主域 sogou.com 不拦截）
        // "api.sogoucloud.com",                 // ⚠️ 已注释：搜狗输入法云端接口，域名拼写无公开抓包资料确认，待验证后启用
        // 腾讯 Bugly 崩溃上报 SDK（Software Development Kit，软件开发工具包；大量国产软件集成，含设备指纹）
        "bugly.qq.com",                          // 腾讯 Bugly 崩溃上报 SDK
        "bugly.gtimg.com",                       // 腾讯 Bugly 管理后台使用的静态资源 CDN
        // 字节跳动系（抖音/剪映/头条/西瓜共用）
        "log.snssdk.com",                        // 字节系客户端日志上报（头条/西瓜等）
        "i.snssdk.com",                          // 字节跳动国内 SDK 主接口域（⚠️ 非单纯遥测：含账号认证、功能 API 等，拦截后可能导致字节系 APP 功能性断连，非仅屏蔽上报）
        "log.byteoversea.com",                   // 字节跳动海外日志上报（抖音/剪映共用）
        // 剪映专业版（CapCut）
        "metrics.capcut.com",                    // 剪映遥测上报
        "log.capcut.com",                        // 剪映日志收集
        // QQ音乐。
        // "qqmusic.qq.com",                     // ⚠️ 待验证：命名无遥测特征前缀，可能是功能性主域，抓包确认前暂不拦截
        "stat.music.qq.com",                     // QQ音乐统计上报
        // 酷狗音乐。
        "log.kugou.com",                         // 酷狗日志上报
        // 酷我音乐。
        "stat.kuwo.cn",                          // 酷我统计上报
        // 网易云音乐桌面版。
        "log.music.163.com",                     // 网易云音乐日志上报
        // 哔哩哔哩桌面客户端。
        "data.bilibili.com",                     // B站数据上报
        "api.log.bilibili.com",                  // B站日志接口
        // 小米 / MIUI（手机系统域名，PC 端不会主动请求；若代理手机热点流量则生效。可根据使用场景注释掉此块）
        "stat.miui.com",                         // 小米统计 SDK
        "data.miui.com",                         // MIUI 数据采集
        "tracking.miui.com",                     // MIUI 行为追踪
        "logservice.miui.com",                   // MIUI 日志服务
        "sdkconfig.ad.xiaomi.com",               // 小米广告 SDK（软件开发工具包）配置下发
        // 钉钉。
        "analytics.dingtalk.com",                // 钉钉遥测上报
        // 飞书。
        "log.feishu.cn",                         // 飞书日志上报
        // 迅雷。
        "ad.xunlei.com",                         // 迅雷广告接口
        "etl.xl7.xunlei.com",                    // 迅雷 7（xl7）客户端事件遥测上报
        // 百度网盘。
        "update.pan.baidu.com",                  // 百度网盘强制更新
        // 腾讯广告。
        "e.qq.com",                              // 腾讯效果广告
        "gdt.qq.com",                            // 广点通广告联盟
        "l.qq.com",                              // 腾讯广告追踪链路
        "toptips.qq.com",                        // QQ 弹窗提示推送
        "minibrowser.qq.com",                    // QQ 内置迷你浏览器广告
        // 阿里 / 友盟。
        // ⚠️【副作用】umeng.com 为大量国内正规 App 集成的友盟 SDK（统计分析）和友盟推送共用此主域，
        //    拦截后可能导致大量国产 App 的推送通知和统计初始化同时失效，影响面较宽。若发现特定软件启动异常，可考虑临时豁免此条（注释掉该行并重载订阅）。
        "umeng.com",                             // 友盟统计 SDK 主域（⚠️ 副作用：部分正规 App 依赖此域初始化，见上方说明）
        "umengcloud.com",                        // 友盟云端统计
        "alimama.com",                           // 阿里妈妈广告联盟
        "adashbc.ut.alibaba.com",                // 阿里广告投放接口
        "update.aliyun.com",                     // 阿里云客户端强制更新
        // 百度广告。
        "pos.baidu.com",                         // 百度联盟广告投放
        "hm.baidu.com",                          // 百度统计打点域（hm 为历史缩写，服务整个百度统计分析系统）
        "cpro.baidu.com",                        // 百度内容推荐广告
        // 字节 / 穿山甲。
        "pangle.io",                             // 穿山甲广告联盟（字节跳动）
        "pangolin-sdk-toutiao.com",              // 穿山甲 SDK 上报域
        "ad.toutiao.com",                        // 头条广告投放接口
        // 360（主域 360.cn 不拦截，精确拦截广告/弹窗/遥测/推广子域）
        // ⚠️ 直接拦截 360.cn 主域会屏蔽官网/下载中心/所有子域，改用以下精确条目
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
        "qhres.com",                             // 奇虎资源 CDN（广告素材）
        "qhstatic.com",                          // 奇虎静态资源（广告框架）
        "qhimg.com",                             // 奇虎图片 CDN（广告图片）
        "qhupdate.com",                          // 360 强制更新推送
        // 2345 全家桶。
        "2345.com",                              // 2345 导航/弹窗主域
        "2345.net",                              // 2345 备用域
        "2345p.com",                             // 2345 推广域
        "2345uns.com",                           // 2345 升级推送
        "50yc.com",                              // 2345 旗下游戏推广
        // 驱动精灵等。
        "160.com",                               // 驱动人生关联广告域
        "updrv.com",                             // 驱动人生更新推送
        "drivergenius.com",                      // 驱动精灵遥测/推广
        // 鲁大师（主域已注释，保留子域精确拦截：游戏盒跑分后的广告全家桶）
        // "ludashi.com",                        // ⚠️ 注释主域：避免误伤官网，使用子域精确拦截
        "lms.ludashi.com",                       // 鲁大师游戏盒跑分后的广告全家桶
        // 金山毒霸。
        "cmcm.com",                              // 猎豹移动广告联盟
        "ijinshan.com",                          // 金山猎豹旗下追踪域
        "duba.com",                              // 金山毒霸广告/弹窗
        // 搜狗（精确子域见 cnAdDomain）
        "inte.sogou.com",                        // 搜狗整合服务遥测
        "theta.sogou.com",                       // 搜狗 A/B 测试上报
        "sogoucdn.com",                          // 搜狗 CDN（广告素材）
        "ie.sogou.com",                          // 搜狗 IE 插件推广
        "metasogou.com",                         // 搜狗元数据追踪
        // Flash（已停服）
        "flash.cn",                              // Adobe Flash 国内分发域（已停服，防止残留弹窗）
        // PotPlayer（主域已注释，保留子域精确拦截侧边栏广告）
        // "daum.net",                           // ⚠️ 注释主域：韩国最大门户，拦截影响搜索/新闻/邮件
        "kakaocorp.com",                         // 关联公司统计上报
        "p1-pc.daum.net",                        // 精准拦截侧边栏广告
        "p2-pc.daum.net",                        // PotPlayer 侧边栏广告节点 2
        "p1-pc.pdk.daum.net",                    // PotPlayer 广告 CDN 节点
    ];
    const cnAdDomain = [
        // 搜狗精确域名（避免误伤 sogou.com 整体）
        "pinyin.sogou.com",                      // 搜狗拼音输入法弹窗
        "news.sogou.com",                        // 搜狗新闻推送
        "toast.sogou.com",                       // 搜狗 Toast（弹出通知）弹窗通知
        "timer.sogou.com",                       // 搜狗心跳 / 定时遥测上报（基于 timer 前缀推断）
        "update.sogou.com",                      // 搜狗强制更新
        "config.sogou.com",                      // 搜狗远程配置下发
        "py.sogou.com",                          // 搜狗拼音云服务
        "snapshot.sogou.com",                    // 搜狗快照追踪
    ];

    // ─────── Mozilla / Firefox 遥测（REJECT 立即终止连接，减少浏览器重试） ───────
    const mozillaSuffix = [
        "telemetry.mozilla.org",                 // Firefox 遥测主域
        "experiments.mozilla.org",               // Firefox 实验性功能遥测
        "healthreport.mozilla.org",              // Firefox 健康报告上报
        "metrics.mozilla.com",                   // 指标统计
        "crash-stats.mozilla.com",               // Mozilla Crash Reporter 崩溃报告
        // ⚠️ 副作用：拦截后 Firefox 地址栏持续显示「网络连接可能受限」警告，对用户有明显可感知的负面体验（该请求本身无意义，但与遥测不同，拦截会影响 UI 显示）。
        //    如能接受上述副作用，可取消以下注释以屏蔽此探测请求：
        // "detectportal.firefox.com",           // Firefox 网络连接检测（该探测本身无业务价值），但拦截后 Firefox 地址栏持续报"网络连接可能受限"
    ];

    // ────────────────────── Google / Chrome 隐私追踪 ──────────────────────
    const googleTrackSuffix = [
        "google-analytics.com",                  // Google Analytics（谷歌统计分析）主域。⚠️ 拦截后可能影响依赖 GA tracking 的网站无法统计访问数据
        "analytics.google.com",                  // Google Analytics API
        "googletagmanager.com",                  // Google Tag Manager（标签管理器）。⚠️ GTM 是大量正规电商/新闻网站的标准基础设施，拦截后可能导致网页异常
        // ⚠️ gvt1.com 是 Google 的 CDN（内容分发网络）主域，Chrome 扩展下载 / 字体 / 浏览器更新均走此域，直接拦截会导致扩展商店异常、字体加载失败、Chrome 无法更新。
        // 精确拦截已知遥测子域，放行其余 CDN 流量。
        "redirector.gvt1.com",                   // Chrome 遥测重定向节点
        "optimizationguide-pa.googleapis.com",   // Chrome 优化提示遥测
    ];
    // ⚠️【副作用】SafeBrowsing（安全浏览）API 是 Chrome/Chromium 用于检测钓鱼网站、恶意软件分发页面的安全机制。
    //    拦截后 Chrome 将无法实时获取恶意网站列表，用户访问钓鱼/恶意页面时不再弹出红色安全警告。若安全性优先于隐私，可考虑将此关键词从拦截列表中移除。
    // ❗ SafeBrowsing 对多数用户而言是安全机制而非隐私威胁，误伤风险明显。如需禁用将下行数组清空即可。
    const googleTrackKeyword = ["safebrowsing.google"]; // 安全浏览接口；含隐私影响：向 Google 上报访问 URL 哈希。⚠️ 拦截后 Chrome 失去钓鱼/恶意网站检测防护，见上方说明

    // ──────────────────── YouTube 遥测（不影响正常播放）────────────────────
    // 使用 REJECT（立即 RST）而非 REJECT-DROP：播放器立即放弃重试，避免请求超时导致卡顿。
    const youtubeSuffix  = ["youtube-ui.l.google.com"];     // YouTube UI 遥测域
    // ⚠️ s.youtube.com 同时承载观看历史，如需保留历史记录请注释下方这行。
    const youtubeDomain  = ["s.youtube.com"];               // 观看历史 + 遥测上报（⚠️ 拦截后观看历史失效）
    // ⚠️ youtubei.googleapis.com 不仅是遥测：/youtubei/v1/player 是播放器视频元数据 API，
    //    拦截后可能导致码率切换、字幕加载、下一集预加载出现异常，不仅限于隐私影响。评估副作用后再决定是否保留此关键词规则。
    const youtubeKeyword = []; // YouTube 内部 API（含遥测及播放器元数据）。💡 当前已禁用（空数组）；启用方式：改为 ['youtubei.googleapis']。

    // ──────────────── 全球主流广告联盟（REJECT 立即终止连接） ────────────────
    const genericAdSuffix = [
        "doubleclick.net",                       // Google DoubleClick 广告网络
        "scorecardresearch.com",                 // comScore 受众测量
        "adnxs.com",                             // Xandr（AppNexus）程序化广告
        "criteo.com",                            // Criteo 个性化重定向广告（全球主流电商广告网络）
        "taboola.com",                           // Taboola 内容推荐广告（各大新闻站底部"猜你喜欢"）
        "outbrain.com",                          // Outbrain 内容推荐广告（同上，竞品）
        "amazon-adsystem.com",                   // 亚马逊广告系统
        "mc.yandex.ru",                          // Yandex Metrica 用户行为统计（东欧/俄语站点广泛使用，部分中文站亦有接入）
        "mc.yandex.com",                         // Yandex Metrica 备用域
    ];

    // ─────── 关键词兜底（⚠️ 默认关闭：误伤面较大，随着互联网基础设施演进，这些关键词已严重泛化）───────
    // telemetry/analytics/stats/metrics 已出现在大量合法 CDN 和第三方服务域名中。例：video-stats.video.google.com / metrics.cloudflare.com / cdn.telemetry-static.com
    // 如需启用，建议仅保留最精确的词并放到所有具体规则之后。启用：将顶部配置区 ENABLE_GLOBAL_KEYWORD_BLOCK 改为 true；
    // 关闭时（ENABLE_GLOBAL_KEYWORD_BLOCK=false）：此数组始终声明，但注入层由 if (ENABLE_GLOBAL_KEYWORD_BLOCK) 门控，不写入任何条目到 layerPools，行为等同于未调用。
    const globalKeyword = ["telemetry", "analytics", "stats", "metrics"];

    // ───────────────────────────── 进程规则 ─────────────────────────────
    // ⚠️ Windows 需要管理员权限 + TUN 模式（Mihomo 创建虚拟网卡接管全部流量）或 Service 模式，系统代理模式无效
    //    TUN 模式：Mihomo 创建虚拟网卡，所有流量经虚拟网卡路由后由 Mihomo 处理；
    //    Service 模式：Mihomo 以系统服务身份运行（免 UAC 弹窗，可开机自启）；在同时启用 TUN 的前提下，进程规则生效效果与手动启动 TUN 模式相同，区别仅在权限获取方式。
    //    进程规则在两种模式下均有效，二者区别在于启动方式而非流量捕获机制。进程名必须与任务管理器「详细信息」完全一致，含 .exe 后缀。
    //    ⚠️ Windows 进程名大小写不敏感；macOS / Linux 严格区分大小写，务必核对精确名称。
    // ⚠️ macOS / Linux：以下规则全部失效——进程名不含 .exe 后缀且严格区分大小写；
    //    如需在 macOS / Linux 上使用进程规则，须通过 ps 命令核对实际进程名（如 AdobeGCClient），并自行在此处添加对应条目。
    // ⚠️ PROCESS-NAME 规则直接通过系统 Socket 获取进程信息，不依赖 SNI 嗅探，在路径B（应用绕过 Mihomo DNS 且开启 ECH，DOMAIN 类规则全部失效）下，
    //    是唯一有效的域名无关进程级拦截手段（路径A 下 DOMAIN 规则仍生效，此为附加纵深）。
    const processBlockRules = [ // 进程拦截
        // ──── 软件鉴权与遥测类：方案 REJECT-DROP（让软件超时等待，不快速切换备用链路）────
        // AND 条件书写顺序按代价从低到高排列，设计意图：期望尽早排除低代价条件（依赖内核实现）后跳过高代价求值：
        // NETWORK（读包头）→ DST-PORT（整数比较）→ PROCESS-NAME（查系统进程表）。实际求值顺序依赖 Mihomo 内核实现，此处为书写规范而非内核行为保证。
        // first-match 语义下：
        //   QUIC 443 规则是全 UDP 和全流量规则的子集；三条动作完全相同（全部 REJECT-DROP），功能上等价于只保留全流量规则。QUIC 443 / 普通 UDP / TCP 分别命中不同规则，
        //   便于按流量类型排查；保留 QUIC 443 / 全 UDP 两条仅为明确表达流量类型覆盖意图，非功能必要。若追求极简，可移除前两条，仅保留全流量规则，但会损失流量类型的日志区分度。
        "AND,((NETWORK,UDP),(DST-PORT,443),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP", // 端口条件可能加快匹配（内核短路求值）
        "AND,((NETWORK,UDP),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP",
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",        // Adobe 正版验证（最重要）
        "PROCESS-NAME,AdskLicensingService.exe,REJECT-DROP", // Autodesk 许可验证
        "PROCESS-NAME,AdskAccess.exe,REJECT-DROP",           // Autodesk 访问控制服务
        "PROCESS-NAME,AdskIdentityManager.exe,REJECT-DROP",  // Autodesk 身份认证管理器
        // 适用 CorelDRAW 2017+（进程名 CorelDRW.exe，非 CorelDRAW.exe；2017 以前版本进程结构不同，请通过任务管理器核对）
        // ⚠️ 部分请求经 msedgewebview2.exe 发出（系统共享进程，不可拦截），已由 corelSuffix 域名层覆盖。
        "PROCESS-NAME,CorelDRW.exe,REJECT-DROP",
        // "PROCESS-NAME,AdobeIPCBroker.exe,REJECT-DROP",    // 进程间通信代理，CC 各组件通过此进程转发激活验证请求，在 CC 2023+ 版本中承担部分鉴权通信，基于架构推断而非抓包
        //   误伤风险：拦截可能导致 Photoshop / Illustrator 等 CC 应用启动失败或功能异常。若确认 AdobeIPCBroker.exe 存在激活验证流量，可取消注释以启用拦截。
        
        // ──── 恶意软件类：方案多数使用 REJECT（快速拒绝，用户感知更好，不卡死软件）────
        "PROCESS-NAME,360sd.exe,REJECT-DROP",                // 360 杀毒主进程，可能导致 360 反复弹窗报告"网络异常"，改用 REJECT-DROP 让 360 静默超时反而更好
        "PROCESS-NAME,360tray.exe,REJECT",                   // 360 系统托盘弹窗进程
        "PROCESS-NAME,2345Mini.exe,REJECT",                  // 2345 迷你窗口/弹窗进程
        "PROCESS-NAME,2345Helper.exe,REJECT",                // 2345 后台辅助进程
        "PROCESS-NAME,SogouNews.exe,REJECT",                 // 搜狗新闻弹窗
        "PROCESS-NAME,Ludashi.exe,REJECT",                   // 鲁大师主程序
        "PROCESS-NAME,LDSGameBox.exe,REJECT",                // 鲁大师游戏盒
        "PROCESS-NAME,DTLocker.exe,REJECT",                  // 驱动人生锁屏弹窗
        "PROCESS-NAME,DriverGenius.exe,REJECT",              // 驱动精灵。⚠️ 慎用：拦截后驱动下载功能失效（进程无法联网），驱动更新将中断
        // "PROCESS-NAME,Wps.exe,REJECT",                    // WPS 办公软件。⚠️ 慎用：WPS 主进程，拦截后全部联网功能失效（包括文档云同步）
    ];

    const processProxyRules = [ // 进程代理（当前为空占位，示例见下方）
        // 示例：修改进程名后取消注释即可——策略组名由脚本自动填入（proxyGroupName），
        // 依赖前提：proxyGroupName 已通过代理组排除断言、Token 断言与存在性断言，此处取值为合法代理出口组名。
        // 注意：以上三道断言（代理组识别阶段执行，代码位置见下方 proxy-group 识别逻辑）与 ENABLE_PROXY 无关，即使 ENABLE_PROXY=false，proxyGroupName 仍有效；
        //   此处取消注释后进程代理规则由 ENABLE_PROCESS_RULE 独立控制，ENABLE_PROXY=false 不影响其注入。
        // `PROCESS-NAME,Telegram.exe,${proxyGroupName}`,
        // `PROCESS-NAME,Slack.exe,${proxyGroupName}`,
    ];
    const processDirectRules = [ // 进程直连
        "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",              // 强制直连，提升下载速度。适用于 v7.0+ 版本，旧版进程名为 BaiduYunGuanjia.exe
        "PROCESS-NAME,filezilla.exe,DIRECT",                 // FTP 数据通道使用随机端口，强制 DIRECT 以规避 FTP 通过代理可能引起的端口映射和速度问题
    ];

    // ────────────────────────────── 代理规则 ──────────────────────────────
    const proxySuffixList = [
        "github.com",                         // 代码托管平台，防御性规则：当外部覆写配置引用的代理规则集下载失败（规则集条目为空）时，让该域走代理确保连通性
        "linkedin.com",                       // 领英职场社交网络
        "stock.adobe.com",                    // Adobe Stock 图库，因锁区需代理
        "behance.net",                        // Behance 设计作品展示平台，因锁区需代理
        "behance.adobe.com",                  // Behance Adobe 子域，因锁区需代理
        "copilot.microsoft.com",              // Copilot AI 助手，注意：directRules 中 microsoft.com 的 SUFFIX 会匹配此域，优先级由 LAYER_ORDER 顺序保证 proxy > direct
        // "openai.com",                      // OpenAI，按需取消注释
        // ⚠️ Google 风控警告：Gemini 检测出口 IP 漂移，google.com 与 gemini.google.com 必须命中同一策略组，否则可能触发 403 或账号异常 
        // "gemini.google.com",               // Gemini，按需取消注释（⚠️ 见上方 Google 风控警告：google.com 必须与 gemini.google.com 命中同一策略组）
        // ────────── Steam 分流：商店走代理，下载走直连 ──────────
        // store / community / static 是国内受干扰的前端域，可以直连，也可以走代理提升访问体验。
        // steampowered.com 根域含 content1~9 下载 CDN（内容分发网络）子域，保留直连保证下载速度。
        // "store.steampowered.com",             // Steam 商店页面，可以直连
        // "steamcommunity.com",                 // Steam 社区 / 创意工坊 / 市场，可以直连
        // "steamstatic.com",                    // Steam 商店静态资源（封面/截图）
    ];

    // ────────────────────────────── 直连规则 ──────────────────────────────
    const directRules = [
        // Microsoft 全家桶直连（防止更新/登录/OneDrive 卡死）
        // 针对 microsoft.com 域而言，SUFFIX 已完整覆盖，KEYWORD 匹配范围过宽且有误判风险（会匹配 microsoft.com 以外含 microsoft 关键词的域名），故不使用
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",              // 微软主域（含 *.microsoft.com 及更深多级子域）
        "DOMAIN-SUFFIX,live.com,DIRECT",                   // 微软账户 / Hotmail
        "DOMAIN-SUFFIX,outlook.com,DIRECT",                // Outlook 邮件服务
        "DOMAIN-SUFFIX,onedrive.com,DIRECT",               // OneDrive 云存储
        "DOMAIN-SUFFIX,skype.com,DIRECT",                  // Skype 通信服务
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",        // Microsoft 365 身份认证
        "DOMAIN-SUFFIX,microsoftonline-p.com,DIRECT",      // Microsoft 365 认证备用域
        "DOMAIN-SUFFIX,msftauth.com,DIRECT",               // 微软统一身份验证
        "DOMAIN-SUFFIX,msftidentity.com,DIRECT",           // 微软身份服务
        "DOMAIN-SUFFIX,passport.net,DIRECT",               // 微软 Passport 认证（旧版）
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",          // Windows Update 更新服务主域
        "DOMAIN-SUFFIX,microsoftpersonalcontent.com,DIRECT", // 微软个人内容 CDN
        "DOMAIN-SUFFIX,msocsp.com,DIRECT",                 // 微软证书吊销列表（OCSP = Online Certificate Status Protocol，在线证书状态协议）
        "DOMAIN-SUFFIX,msedge.net,DIRECT",                 // Microsoft Edge CDN（内容分发网络）/ 更新
        // NCSI（Network Connectivity Status Indicator，网络连通性状态指示器，Windows 右下角网络图标依赖此服务）
        // DOMAIN-SUFFIX 同时覆盖 ipv6.msftconnecttest.com 等所有子域变体。
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",        // NCSI 连通性探测（拦截后 Windows 右下角显示「无网络」）
        "DOMAIN-SUFFIX,msftncsi.com,DIRECT",               // NCSI 旧版探测域
        // Adobe 常用业务放行（字体/图库/作品展示）
        // ⚠️【UDP 路径说明】以下 adobe.com 子域的 QUIC/UDP 流量先命中 udpBlock 的 AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT，
        //    收到 ICMP 后立即 fallback 至 TCP；TCP 连接再命中此处 DIRECT 规则，整体无延迟，行为符合预期。
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",            // Adobe Fonts 字体同步服务
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",            // Adobe Color 配色工具
        "DOMAIN,assets.adobe.com,DIRECT",                  // Adobe 静态资源 CDN（内容分发网络），精确匹配以防过度放行（若实测需要子域可改 DOMAIN-SUFFIX）
        // 官网放行
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",               // Autodesk 官网放行（下载/论坛；账户端点 accounts.autodesk.com 在激进模式下被前置 REJECT-DROP 覆盖）
        "DOMAIN-SUFFIX,corel.com,DIRECT",                  // 父域放行（主域即官网，精确子域拦截见 corelSuffix）
        // 常用直连
        // "DST-PORT,123,DIRECT",                 // ⚠️ 旧版 Mihomo 兼容写法，同时匹配 TCP/UDP；NTP（Network Time Protocol，网络时间协议）仅使用 UDP 123
        "AND,((NETWORK,UDP),(DST-PORT,123)),DIRECT",  // 精确匹配端口 & UDP 协议。NTP 时间同步强制直连（仅 TUN 模式有效）
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",  // Steam 根域直连（含 content1~9 下载 CDN 子域，保证满速）
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",  // Steam 游戏内容分发 CDN（满速下载）
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",   // Steam 联机对战后端
        "DOMAIN-SUFFIX,pixpinapp.com,DIRECT",     // 截图贴图工具
        "DOMAIN-SUFFIX,pixpin.cn,DIRECT",         // 截图贴图工具
        "DOMAIN-SUFFIX,lanzou.com,DIRECT",        // 蓝奏云主域
        "DOMAIN-SUFFIX,lanzoui.com,DIRECT",       // 蓝奏云备用域 1
        "DOMAIN-SUFFIX,lanzoux.com,DIRECT",       // 蓝奏云备用域 2
        // 可选扩展区
        "DOMAIN-SUFFIX,masuit.com,DIRECT",        // 软件分享站 懒得勤快
        "DOMAIN-SUFFIX,masuit.net,DIRECT",        // 软件分享站 懒得勤快 备用域1
        "DOMAIN-SUFFIX,masuit.org,DIRECT",        // 软件分享站 懒得勤快 备用域2
        "DOMAIN-SUFFIX,423down.com,DIRECT",       // 知名绿色软件站
        "DOMAIN-SUFFIX,ghxi.com,DIRECT",          // 果核剥壳（绿色软件站）
        "DOMAIN-SUFFIX,mpyit.com,DIRECT",         // 殁漂遥软件分享站
        "DOMAIN-SUFFIX,apphot.cc,DIRECT",         // App热（原心海e站）
        "DOMAIN-SUFFIX,25xianbao.com,DIRECT",     // 卡圈线报
        "DOMAIN-SUFFIX,dir28.com,DIRECT",         // 羊毛活动
        // "DOMAIN-KEYWORD,amazon,DIRECT",        // 亚马逊直连（⚠️ 覆盖所有含 amazon 的域名，含 AWS；若 AWS 服务需代理，改用精确 DOMAIN-SUFFIX 规则或外部规则集合）
                                                  // ⚠️ 冲突依赖 LAYER_ORDER：block 层先于 direct 层命中，否则 amazon-adsystem.com 广告域会被此条规则泛匹配误放行。
        // "DOMAIN-SUFFIX,tmall.hk,DIRECT",       // 淘宝 .hk 域，如被代理可能影响商品价格加载
        // 个人扩展区
        // "DOMAIN-SUFFIX,ERP,DIRECT",       // 行业 ERP
        // "DOMAIN-SUFFIX,SCRM,DIRECT",      // 行业 SCRM
        // "DOMAIN-SUFFIX,独立站,DIRECT",     // 小众独立站，直连以确保访问
    ];

    // ────────────── 激进阻断规则（默认关闭，开启前请仔细阅读注释）──────────────
    const aggressiveRules = [
        // SUFFIX 是 REGEX 的严格超集（覆盖关系）：
        //   DOMAIN-SUFFIX,adobe.io → 覆盖裸域 adobe.io + 所有子域（含多级），动作 REJECT-DROP。
        //   DOMAIN-REGEX,^.+\.adobe\.io$ → 仅覆盖子域（至少一字符前缀），不含裸域，为 SUFFIX 的真子集。
        // ⚠️ 功能上 SUFFIX 单独即可覆盖全部情形，REGEX 并非必要；保留 REGEX 的意义：明确表达"拦截所有 adobe.io 子域"的设计意图，
        //    且便于未来独立调整子域与裸域的动作（如：子域 REJECT-DROP、裸域改 REJECT），分层更灵活。
        //    如无上述分层需求，可安全删除 REGEX 而零覆盖损失（SUFFIX 完全兜底）。
        // "DOMAIN-REGEX,^.+\\.adobe\\.io$,REJECT-DROP",        // ⚠️ 激进：所有 adobe.io 子域；覆盖范围已被下方 SUFFIX 包含，保留意图为将来独立调整子域与裸域动作
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",                // ⚠️ 激进：adobe.io 裸域+全部子域（SUFFIX 为 REGEX 的严格超集，此条为功能必要条目）
        // "DOMAIN-SUFFIX,workflowusercontent.com,REJECT-DROP", // 多平台共用域（Zapier/Notion/GitHub Actions 也在用），建议审查实际流量再决定是否启用。
        // ⚠️ 激进：多服务共用内容托管域（Google Cloud Workflows / Colab / AppSheet / Adobe / Zapier / Notion / GitHub Actions 等）；
        //    拦截后所有依赖此域的服务均受影响——Colab 输出渲染、AppSheet 内容、Adobe 工作流等可能同时中断，影响面超出 Adobe 范畴。
        "DOMAIN-SUFFIX,adsk.com,REJECT-DROP",                // ⚠️ 激进：Autodesk 旧版遥测（影响官网/插件商店访问）
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",              // ⚠️ 激进：Office CDN（内容分发网络）关键词规则（影响 Office 更新/模板下载）
        "DOMAIN,geo.adobe.com,REJECT-DROP",                  // ⚠️ 激进：地理区域识别（影响 CC 登录）
        "DOMAIN,geo2.adobe.com,REJECT-DROP",                 // ⚠️ 激进：地理区域识别备用
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",   // ⚠️ 激进：拦截后无法登录 Autodesk 账户
        // ⚠️ 激进：Autodesk 授权端点。
        //    ENABLE_BLOCK=true 时，autodeskKeyword 中的 KEYWORD 规则（"entitlement.autodesk"）因注入顺序更早而先命中，
        //    本 SUFFIX 规则被遮蔽（实质冗余但无害）。ENABLE_BLOCK=false 时本条独立生效，为纵深防御保留，禁止删除。
        //    注意：api.entitlements.autodesk.com 不被上述 KEYWORD 覆盖，已在 autodeskSuffix 独立列出，与本条无重叠（见 autodeskKeyword 注释块）。
        "DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP",
        // IE 遗留检测（拦截后影响 ActiveX 控件 / 旧版 OA 系统，不影响 NCSI）
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP",         // ⚠️ 激进：IE 内核在线检测（影响 ActiveX 控件 / 旧版 OA 系统，不影响 NCSI）
    ];

    // ════════════════ 3. 规则组装与注入 ════════════════

    try {
        // 规则按层级顺序展开。
        // Object.freeze：const 仅防止重新赋值，不防止 push/splice 等原地变异；
        //   freeze 确保 LAYER_ORDER 内容在整个注入过程中绝对不变，防止未来扩展时意外静默失效。
        // ⚠️ 键名一致性约束：LAYER_ORDER 的字符串元素必须与 layerPools 的键名完全一致；
        //   添加新层时须同步在两处修改；仅改其一会触发 LAYER_ORDER 双向一致性断言，中止注入并输出明确错误信息（规则不会静默丢失）。
        // ⚠️ LAYER_ORDER 顺序 = first-match 策略优先级，禁止随意调整，两类典型错误：
        //    危险示例1：将 "aggressive" 移至 "allow" 之前，adobe.io 通配 REJECT-DROP 先于 Firefly 精确放行命中，AI 请求被错误拦截。
        //    危险示例2：将 "direct" 移至 "aggressive" 之前，父域 autodesk.com,DIRECT 先命中，子域 accounts.autodesk.com,REJECT-DROP 等激进规则将永久被父域规则遮蔽。
        //    插入/删除层级时，需在 LAYER_ORDER 和 layerPools 两处同步修改（见上方约束说明）；finalPool 的 for 循环本身无需改动。
        const LAYER_ORDER = Object.freeze(["allow", "block", "process", "proxy", "aggressive", "direct"]);

        // ──── 分层规则容器（优先级由 LAYER_ORDER 数组唯一决定）────
        // 层级固定顺序：allow（放行）> block（拦截）> process（进程）> proxy（代理）> aggressive（激进）> direct（直连）
        // layerPools 对象仅用作具名容器，方便分类追加规则；各数组在运行期间持续被 pushLayer 写入（可变）。
        // 此命名约定（大小写区分）适用于模块级别标识符；函数体内部临时变量的'私有'区分由附录命名准则的下划线前缀体系负责，两套规范不重叠。
        // 优先级完全由 LAYER_ORDER 数组的元素顺序决定（有意不依赖 layerPools 对象键迭代顺序——ES2015+ 已明确规范字符串键按插入顺序迭代，
        // 显式 LAYER_ORDER 数组使优先级意图一目了然，且防止未来新增层时因键位置隐性改变注入顺序）。
        const layerPools = { allow: [], block: [], process: [], proxy: [], aggressive: [], direct: [] };
        // pushLayer：逐项追加，避免 push(...rules) 在规则量超过 V8 参数栈上限（~65536）时抛出 RangeError
        // 此检查面向将来 pushLayer 被动态层名调用的情形；当前所有调用均使用字符串字面量，本行在现有代码路径下不会触发，属前向防御。
        const pushLayer = (layer, rules) => {
            if (!(layer in layerPools)) throw new Error(`[Script] pushLayer: 未知层 '${layer}'，请检查 layerPools 键名与 LAYER_ORDER 是否一致`);
            for (const r of rules) layerPools[layer].push(r);
        };

        if (ENABLE_BLOCK) {
            // ──── Firefly 路由：isFireflyActive 决定 adobeSharedDeps / adobeFireflyOnly 的注入层与动作 ────
            // isFireflyActive=true  → allow 层走代理（first-match 保证先于 adobeSuffix REJECT 命中）
            // isFireflyActive=false → block 层走拦截（ENABLE_BLOCK=true && ENABLE_FIREFLY=false 时此路径生效；
            //   ENABLE_BLOCK=false 时最外层 if 整体跳过，此代码段不执行）
            //
            // ⚠️ isFireflyActive=false 时 adobeFireflyOnly 须显式拦截（不可省略）：
            //    其域名不在 adobeSuffix / adobeRegex 覆盖范围内：
            //      · clio.adobe.io / firefly.adobe.io（位数过短，不满足 {8,12}）
            //      · firefly.adobe.com / clio-assets.adobe.com 等（TLD 为 .com，adobeRegex 仅覆盖 .io）
            //      · firefly-api.adobe.io / clio-prober.adobe.io（含连字符，不满足 [A-Za-z0-9]{8,12}）
            //    若不显式注入，上述端点将落入 MATCH 兜底策略（可能走直连），背离「关闭 ENABLE_FIREFLY = 禁用 Firefly 功能」的设计意图。
            //    （senseicore / senseimds 满足 adobeRegex {8,12} 约束，已被正则兜底；其余条目须此处显式处理。）
            const [_fireflyAction, _fireflyPool] = isFireflyActive
                ? [proxyGroupName, layerPools.allow]
                : ["REJECT",       layerPools.block];
            pushSuffix(adobeSharedDeps, _fireflyAction, _fireflyPool);
            pushSuffix(adobeFireflyOnly, _fireflyAction, _fireflyPool);
            // Adobe（遥测/授权域改用 REJECT，软件快速感知失败（通常切换离线模式或放弃重试），避免启动卡顿）
            pushSuffix(adobeSuffix, "REJECT", layerPools.block);
            pushLayer("block", adobeRegex);
            // ❗ udpBlock 仅 TUN 模式有效，系统代理模式下这些规则不会命中任何 UDP 流量（见 udpBlock 声明处注释）
            pushLayer("block", udpBlock);
            // ⚠️ 运行时提示：DOMAIN-KEYWORD 规则依赖 SNI 或 Fake-IP 映射
            // ⚠️ [udpBlock] 所有 UDP 规则依赖域名识别（Fake-IP / Sniffer），ECH 下可能全部失效。
            // 若应用绕过 Mihomo DNS 且启用 ECH，则此规则可能静默失效。
            // WSS（WebSocket Secure）精确匹配（DOMAIN，原因见 adobeWsDomain 注释）
            pushDomain(adobeWsDomain, "REJECT", layerPools.block);
            // Corel
            pushSuffix(corelSuffix, "REJECT", layerPools.block);
            // Autodesk
            pushSuffix(autodeskSuffix, "REJECT", layerPools.block);
            pushDomain(autodeskDomain, "REJECT", layerPools.block);
            pushKeyword(autodeskKeyword, "REJECT", layerPools.block);
            // 非官方修改补丁后门（保留 REJECT-DROP：拖延被拦截进程感知失败的时间，阻碍恶意程序快速切换备用域名，降低其自适应速度）
            pushSuffix(backdoorSuffix, "REJECT-DROP", layerPools.block);
            pushKeyword(backdoorKeyword, "REJECT-DROP", layerPools.block);
            // IDM / Wondershare / 杂项。
            pushSuffix(idmSuffix, "REJECT", layerPools.block);
            pushKeyword(idmKeyword, "REJECT", layerPools.block);
            pushSuffix(wondershareSuffix, "REJECT", layerPools.block);
            // miscSoftwareSuffix 当前为空（扩展占位）；miscSoftwareDomain 当前非空。
            // pushSuffix/pushDomain 对空数组均为零次迭代（no-op），两处均无需 length 守卫；
            // 统一去除守卫，保持形式对称，便于将来条目变动时无需同步修改防御逻辑。
            pushSuffix(miscSoftwareSuffix, "REJECT", layerPools.block);
            pushDomain(miscSoftwareDomain, "REJECT", layerPools.block);
            // 微软遥测（REJECT 立即终止连接）
            pushSuffix(msTelemSuffix, "REJECT", layerPools.block);
            // 国产广告 / 遥测（REJECT 快速拒绝，广告类无需静默超时）
            pushSuffix(adsSuffix, "REJECT", layerPools.block);
            pushDomain(cnAdDomain, "REJECT", layerPools.block);
            // 浏览器遥测（REJECT 立即终止连接）
            pushSuffix(mozillaSuffix, "REJECT", layerPools.block);
            pushSuffix(googleTrackSuffix, "REJECT", layerPools.block);
            pushKeyword(googleTrackKeyword, "REJECT", layerPools.block);
            // YouTube 遥测（REJECT 立即返回，避免播放器因超时卡顿）
            pushSuffix(youtubeSuffix, "REJECT", layerPools.block);
            pushDomain(youtubeDomain, "REJECT", layerPools.block);
            pushKeyword(youtubeKeyword, "REJECT", layerPools.block); // 该行注释状态必须与被调用的数据层变量对应行一致（两处必须同步）；
                                                                     // 或直接将该变量的数组赋值清空：const youtubeKeyword = []
            // 通用广告联盟
            pushSuffix(genericAdSuffix, "REJECT", layerPools.block);
            if (ENABLE_GLOBAL_KEYWORD_BLOCK) {
                pushKeyword(globalKeyword, "REJECT", layerPools.block);
            }
        }

        if (ENABLE_PROCESS_RULE) {
            // processBlockRules / processProxyRules / processDirectRules 均为同作用域 const 字面量数组，
            // 类型在声明时确定，Array.isArray 对这三个变量必为 true，添加类型检查是冗余代码；
            // pushLayer 内部为 for...of 迭代，对空数组零次迭代（no-op），无需 length 守卫，与 pushSuffix/pushDomain 处理原则一致。
            // ⚠️ process 层内三个子数组的注入顺序（block > proxy > direct）构成 first-match 子优先级：
            //    同一进程名若同时出现在 processBlockRules 和 processProxyRules 中，REJECT/REJECT-DROP 先命中，代理规则被遮蔽。
            pushLayer("process", processBlockRules);
            pushLayer("process", processProxyRules); // 当前为空占位数组（示例已注释），非空时自动注入。
            pushLayer("process", processDirectRules);
        }

        if (ENABLE_PROXY) {
            // action 参数此处传入策略组名（非 DIRECT/REJECT），Mihomo 语法合法。
            pushSuffix(proxySuffixList, proxyGroupName, layerPools.proxy);
        }

        // ⚠️ aggressiveRules 必须在 directRules 之前注入（父域遮蔽问题）：
        //   aggressiveRules 含 DOMAIN-SUFFIX,accounts.autodesk.com /
        //   entitlement.autodesk.com / DOMAIN,ieonline.microsoft.com 等子域规则；
        //   若排在 directRules（含 autodesk.com,DIRECT / microsoft.com,DIRECT）之后，
        //   当 ENABLE_DIRECT=true 时，父域 DIRECT 规则先命中，子域 REJECT-DROP 将被遮蔽，无法生效。
        //
        // ──── BLOCK 与 AGGRESSIVE 重叠域名（此处行为说明）────
        //   entitlement.autodesk.com（SUFFIX）在 aggressiveRules 中；
        //   entitlement.autodesk（KEYWORD）在 ENABLE_BLOCK=true 时由 autodeskKeyword 注入。
        //   两者注入顺序：autodeskKeyword（BLOCK 层）先入 pool，aggressiveRules 后入。
        //   first-match（首条命中）语义下 KEYWORD 规则先命中，SUFFIX 被遮蔽。无额外影响，设计正确。
        //   详见 autodeskKeyword 上方「BLOCK vs AGGRESSIVE 重叠说明」注释。
        if (ENABLE_AGGRESSIVE) {
            pushLayer("aggressive", aggressiveRules);
        }

        if (ENABLE_DIRECT) {
            pushLayer("direct", directRules);
        }

        // 规则池完整性断言：双向一致性检查，验证 LAYER_ORDER 与 layerPools 键名一致性
        const _orderSet = new Set(LAYER_ORDER);
        // 正向检查：LAYER_ORDER → layerPools。说明：当前代码路径下，所有层均通过 pushLayer 写入，其内部已存在相同的键存在性校验，
        // 故此检查在当前实现中不会触发；保留目的在于防范未来直接操作 layerPools 键的重构风险，作为二次保障。
        for (const k of LAYER_ORDER) {
            if (!(k in layerPools))
                throw new Error(`[Script] LAYER_ORDER 键 '${k}' 在 layerPools 中不存在`);
        }
        // 反向检查：layerPools → LAYER_ORDER（防止 layerPools 有键但未列入 LAYER_ORDER 导致规则静默丢弃）
        for (const k of Object.keys(layerPools)) {
            if (!_orderSet.has(k))
                throw new Error(`[Script] layerPools 键 '${k}' 不在 LAYER_ORDER 中，该层规则将被静默丢弃`);
        }

        const finalPool = [_SENTINEL_START];
        // 按 LAYER_ORDER 顺序展开各层，单次迭代用 push(r) 规避大型数组 push(...arr) 的 RangeError。
        for (const key of LAYER_ORDER) {
            for (const r of layerPools[key]) finalPool.push(r);
        }
        finalPool.push(_SENTINEL_END);

        // 插入到规则列表最前面（最高优先级）
        config.rules = finalPool.concat(config.rules);

        console.log("=".repeat(28));
        // 🔍 运行诊断日志（规则注入成功后输出各开关状态及统计信息）
        console.log("✅ 规则注入成功");
        // ENABLE_SCRIPT=false 时函数已在上方提前 return，执行到此处时 ENABLE_SCRIPT 必定为 true。
        console.log(`   脚本状态:   ✅ 已启用`);
        console.log(`   拦截模块:   ${ENABLE_BLOCK         ? "✅" : "❌"}`);

        // Firefly 放行状态需结合 isFireflyActive 综合判断后显示。
        if (ENABLE_FIREFLY) {
            if (isFireflyActive) {
                console.log(`   Firefly 放行: ✅（adobeSharedDeps + adobeFireflyOnly 均已注入 allow 层，走[${proxyGroupName}]）`);
            } else {
                console.log(`   Firefly 放行: ❌ ENABLE_BLOCK=false，Firefly 豁免未启用`);
            }
        } else {
            console.log(`   Firefly 放行: ❌`);
        }
        console.log(`   进程规则:   ${ENABLE_PROCESS_RULE  ? "✅（需管理员权限+TUN 模式，另须 config 开启获取进程信息，条件不满足则静默失效）" : "❌"}`);
        console.log(`   代理规则:   ${ENABLE_PROXY         ? "✅" : "❌"}`);
        // ENABLE_AGGRESSIVE 激进模式日志增加警告行，列出已知受影响域。
        if (ENABLE_AGGRESSIVE) {
            console.warn(`   激进模式:   ⚠️ 已开启`);
            console.warn(`   ⚠️ 激进模式已开启，可能导致以下服务不可用：`);
            console.warn(`      adobe.io（插件市场/字体）、adsk.com（Autodesk 官网）、`);
            console.warn(`      accounts.autodesk.com（Autodesk 登录）、entitlement.autodesk.com（Autodesk 授权）、`);
            console.warn(`      officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA）`);
        } else {
            console.log(`   激进模式:   ❌`);
        }
        console.log(`   直连规则:   ${ENABLE_DIRECT        ? "✅" : "❌"}`);
        console.log(`   Hosts 覆写:  ${ENABLE_HOSTS_OVERRIDE   ? "✅ [" + HOSTS_MODE + "]" : "❌"}`);
        console.warn("⚠️ [udpBlock] 所有 UDP 规则依赖域名识别（Fake-IP / Sniffer），ECH 下可能全部失效。"
        + "若应用绕过 Mihomo DNS 且启用 ECH，则此规则可能静默失效。");
        // 注入规则条目分层统计日志
        // ▶▶ 分层统计开始 ▶▶
        console.log(`   ▶ 注入规则条目分层统计:`);
        console.log(`      - 放行层 (allow)     : ${layerPools.allow.length} 条`);
        console.log(`      - 拦截层 (block)     : ${layerPools.block.length} 条`);
        console.log(`      - 进程层 (process)   : ${layerPools.process.length} 条`);
        console.log(`      - 代理层 (proxy)     : ${layerPools.proxy.length} 条`);
        console.log(`      - 激进层 (aggressive): ${layerPools.aggressive.length} 条`);
        console.log(`      - 直连层 (direct)    : ${layerPools.direct.length} 条`);
        // ◀◀ 分层统计结束 ◀◀

        console.log(`   注入规则数: ${finalPool.length} 条（上述分层之和 + 首尾 2 条哨兵）`);
        console.log(`   总规则数:   ${config.rules.length} 条`);
        console.log(`   脚本执行耗时: ${Date.now() - _startTime} ms（含指纹注入，不含 Hosts 覆写）`);
        console.log("=".repeat(28));

    } catch (err) {
        // ⚠️ 降级说明：规则注入异常时不再立即 return，让代码继续执行到下方独立的 Hosts 注入 try 块。
        //    Hosts DNS 覆写（尤其是后门域名黑洞化）在规则注入失败时仍有独立防护价值，应尽力执行。
        // ⚠️ 降级场景的哨兵边界说明：
        //   _SENTINEL_END 在 finalPool 构建阶段（LAYER_ORDER for 循环结束后）即已压入，
        //   config.rules 赋值（finalPool.concat）是单条同步语句，在 JS 单线程模型中不会被中断：
        //     · 若错误发生在赋值之前（for 循环中），config.rules 尚未被写入，返回干净状态；
        //     · 若错误发生在赋值之后（console.log 阶段），全量注入规则已完整写入（不存在半写入状态），且两端哨兵均已完整写入，不产生孤儿哨兵。
        //   结论：catch 块捕获的异常不会产生孤儿 START，返回的 config.rules 始终处于一致状态（赋值前为干净状态，赋值后为完整注入状态，不存在半截注入的中间状态）。
        console.error("❌ 规则注入阶段异常（config.rules 处于一致状态：赋值前=未写入，赋值后=已完整写入，无半写入），继续执行 Hosts 覆写:", err);
        console.log(`   失败耗时:   ${Date.now() - _startTime} ms`);
        // 不再 return config，继续执行到 Hosts 注入 try 块。
    }

    // ═══════════════ 4. Hosts 级 DNS 拦截 ═══════════════
    //  （四种劫持子模式：黑洞型与欺骗型，由 HOSTS_MODE 选择）
    //  【DNS 内部处理流（来源：wiki.metacubex.one/en/config/dns/diagram）】
    //   DNS 解析阶段（按优先级）：
    //     1. Hosts 匹配  → 命中则立即返回映射地址，不再向下执行
    //     2. fake-ip-filter（虚假 IP 过滤表）判断 → 域名在列表中则走真实 DNS 查询
    //     3. Fake-IP（虚假 IP，Mihomo 分配的 198.18.x.x 虚拟地址）生成 → 不在列表则分配虚拟 IP
    //     → 结论：hosts 优先级高于 fake-ip-filter
    //   Hosts 覆写生效前提：Mihomo 必须拦截到 DNS 查询才能返回拦截地址。
    //   系统代理模式：app → Mihomo DNS（先检查内置 hosts 表，命中则直接返回拦截地址：黑洞/欺骗，取决于 HOSTS_MODE）→ app 连接立即失败
    //   TUN 模式（需满足前提：dns-hijack: any:53）：
    //     app → TUN → DNS 接管 → hosts → 返回拦截地址（黑洞/欺骗，取决于 HOSTS_MODE）→ app 连接立即失败
    //     ⚠️ 若 TUN 未配置 dns-hijack，app 可绕过 Mihomo DNS 直接查询外部 DNS，hosts 将不生效。
    //
    //   ⚠️ 两种模式的共同边界——应用使用硬编码 IP（完全绕过 DNS）：
    //     app → 直接发起 IP 连接 → 路由规则匹配 → DOMAIN-SUFFIX / DOMAIN 规则不触发（无域名可匹配） → PROCESS-NAME / IP-CIDR / NETWORK 规则触发 → REJECT-DROP
    //     此时 DOMAIN 类规则全部失效，仅剩 PROCESS-NAME（进程规则）和 IP-CIDR 规则作为有效防线。
    //
    // 💡【Hosts 与 Rules 分层说明】
    //    hosts 命中后，DNS 已在解析阶段返回拦截地址，TCP 连接不会发出，rules 层（DOMAIN-SUFFIX REJECT-DROP 等）不会执行。
    //    rules 层是 hosts 未生效时（用户未开启「使用 Hosts」或应用使用硬编码 IP 绕过 DNS）的兜底。
    //    两者存在有意的依赖关系：Hosts 层优先，rules 层兜底；Hosts 命中时 rules 不参与，
    //    两者形成有序的优先级覆盖结构——Hosts 为主防线、rules 为兜底——而非两层并行对同一流量重复处理的冗余关系。
    //
    //   各 HOSTS_MODE 的连接失败类型：
    //     0.0.0.0 / :: → ENETUNREACH（Linux/Android）/ WSAEINVAL（Windows，10022，通常返回，因 Windows 版本而异：0.0.0.0 为非法连接目标）
    //                    或 WSAENETUNREACH（10051，断网状态下可能出现）；OS 直接拒绝，TCP SYN（握手第一包）不会发出。
    //     127.0.0.1 / ::1 → ECONNREFUSED（本地无监听端口时，本地 OS TCP 栈返回 RST 重置包）应用层收到连接拒绝错误（而非路由不可达），欺骗性拦截效果更温和。
    //
    // 模式说明（与顶部 HOSTS_MODE 对应）：
    //   ipv4-loopback  → 127.0.0.1          回环模拟拦截（ECONNREFUSED），更温和
    //   ipv4-blackhole → 0.0.0.0            黑洞拦截，OS 拒绝（WSAEINVAL/ENETUNREACH，见上），通常 TCP SYN 不会发出；阻断速度最快，但可能被部分应用归类为断网状态
    //   dual-loopback  → 127.0.0.1 + ::1    IPv4/IPv6 双栈回环模拟拦截
    //   dual-blackhole → 0.0.0.0 + ::       IPv4/IPv6 双栈黑洞拦截（慎用，最彻底但可能影响某些应用）
    //
    // 【hosts 值格式（来源：wiki.metacubex.one/en/config/dns/hosts）】
    //   单 IP：字符串 "0.0.0.0"
    //   多 IP：数组   ["0.0.0.0", "::"]
    //   域名 → IP：字符串（单 IP）或数组（多 IP，Mihomo hosts 支持），域名 → 域名重定向：仅字符串，不支持数组，为规避解析歧义，统一使用字符串（单 IP）或数组（多 IP）

    if (ENABLE_HOSTS_OVERRIDE) {
        try {

            // modeMap 值格式：
            //   单 IP 模式 → 字符串（避免单元素数组的解析歧义）
            //   双栈模式   → 数组（Mihomo hosts 明确支持多 IP 数组）
            // 命名说明：
            //   ipv4-loopback  / ipv4-blackhole  → 单栈，前缀 ipv4- 明确标示 IPv4
            //   dual-loopback  / dual-blackhole  → 双栈，前缀 dual- 明确标示 IPv4+IPv6（对称命名）
            const modeMap = {
                "ipv4-loopback":   "127.0.0.1",
                "ipv4-blackhole":  "0.0.0.0",
                "dual-loopback":   ["127.0.0.1", "::1"],
                "dual-blackhole":  ["0.0.0.0", "::"],
            };
            const target = modeMap[HOSTS_MODE];
            if (!target) throw new Error(
                `未知 HOSTS_MODE: "${HOSTS_MODE}"。` +
                `有效值为：ipv4-loopback / ipv4-blackhole / dual-loopback / dual-blackhole`
            );

            // 拦截域名列表（针对全部高危非官方修改补丁回传域名）
            // Mihomo hosts 通配符说明（来源：wiki.metacubex.one/en/config/dns/hosts）：
            //   +.domain → 匹配主域本身 + 所有多级子域，等效 DOMAIN-SUFFIX。老版内核不支持该语法
            //   *.domain → 仅匹配单级子域，不含主域和多级子域
            //   .domain  → 匹配所有多级子域，不含主域本身
            //
            // hijackDomains 覆盖所有后门域名的 DNS 解析（+.domain 语法），与 rules 层的 backdoorSuffix REJECT-DROP 配合，形成 DNS + rules 双层防御。
            const hijackDomains = BACKDOOR_BASE_DOMAINS.map(d => `+.${d}`);

            const customHosts = Object.fromEntries(hijackDomains.map(d => [d, target]));

            // 顶层 hosts + DNS 模块双重注入（兼容性策略，而非功能需要）
            // ⚠️ 不同内核/版本对 hosts 段和 dns.hosts 段的支持情况可能不同，双写确保覆盖
            // ⚠️ config.dns 可能不存在（订阅无 dns 块时为 undefined），必须先确保 dns 对象存在再操作子字段。

            // ensureHostsObj：hosts / dns.hosts 字段类型校验辅助工具，就近声明于首次使用处。
            // 若上游订阅将 hosts 写成数组/字符串，直接展开产生以索引为 key 的非法对象；
            // typeof + !Array.isArray 双重验证，类型异常时安全退化为空对象。
            // ⚠️ 不可简化为 val || {}：|| 无法拦截数组/字符串类型。
            const ensureHostsObj = val =>
                (typeof val === "object" && val !== null && !Array.isArray(val)) ? val : {};

            config.hosts     = { ...ensureHostsObj(config.hosts),     ...customHosts };

            // 初始化 dns 对象（若缺失则补全）
            if (config.dns == null) {
                config.dns = {};
            }

            // dns.hosts 注入
            let _dnsValid = false;
            if (typeof config.dns === "object" && !Array.isArray(config.dns)) {
                config.dns.hosts = { ...ensureHostsObj(config.dns.hosts), ...customHosts };
                _dnsValid = true;
            } else {
                console.warn("⚠️ config.dns 类型异常，已写入顶层 hosts，跳过 dns.hosts 注入（fake-ip-filter 仍会清理）");
            }

            //    Clash Verge Rev 的配置生效顺序：
            //    订阅 yaml → 脚本注入 → UI 设置覆盖 → 写入 clash-verge.yaml → Mihomo 加载
            //    → 必须在 CVR 设置 › DNS 覆写 › 手动开启「使用 Hosts」，Hosts DNS 覆写才能真正生效。
            //    注意：同页面还有「使用系统 Hosts」开关，该开关控制的是系统原生 hosts 文件，与本脚本向 Mihomo 注入的 hosts 条目完全独立，保持关闭即可。

            // fake-ip-filter 维护（无论 dns 是否异常，均须执行）
            // 确保 dns 对象和 fake-ip-filter 数组存在，以便后续写入
            if (!_dnsValid) {
                config.dns = { "fake-ip-filter": [] };
            } else if (!Array.isArray(config.dns["fake-ip-filter"])) {
                config.dns["fake-ip-filter"] = [];
            }

            if (true) { // 此 if 仅用于保持代码块缩进，可忽略
                const _CURRENT_MANAGED = new Set(
                    BACKDOOR_BASE_DOMAINS.flatMap(d => [`+.${d}`, d, `*.${d}`]).map(s => s.toLowerCase())
                );

                const _HISTORICAL_MANAGED = new Set([
                    "api.966v26.com",
                    "status.966v26.com",
                    "+.cc-cdn.com",
                    "cc-cdn.com",
                    "*.cc-cdn.com",
                ].map(s => s.toLowerCase()));

                const _SCRIPT_MANAGED_HIJACK = new Set([..._CURRENT_MANAGED, ..._HISTORICAL_MANAGED]);
                if (ENABLE_MAINTENANCE_CHECKS) {
                    const _redundantHistorical = [..._HISTORICAL_MANAGED].filter(entry => _CURRENT_MANAGED.has(entry));
                    if (_redundantHistorical.length > 0) {
                        console.warn("⚠️ fake-ip-filter 历史托管域名集合中存在仍属于当前活跃域名的条目，"
                            + "这可能是从 BACKDOOR_BASE_DOMAINS 移除域名后忘记同步清理历史集合所致：",
                            _redundantHistorical);
                    }
                }

                const existingSet   = new Set();
                const cleanExisting = [];
                let cleanedCount    = 0;
                for (const entry of config.dns["fake-ip-filter"]) {
                    const s  = typeof entry === "string" ? entry.trim() : "";
                    const sl = s.toLowerCase();
                    if (!s) continue;
                    if (_SCRIPT_MANAGED_HIJACK.has(sl)) {
                        cleanedCount++;
                        continue;
                    }
                    if (existingSet.has(sl)) continue;
                    existingSet.add(sl);
                    cleanExisting.push(s);
                }
                const newEntries = hijackDomains.filter(d => !existingSet.has(d.toLowerCase())).sort();
                config.dns["fake-ip-filter"] = [...cleanExisting, ...newEntries];

                console.warn("⚠️ Hosts DNS 覆写模块已启用，但仅在 CVR 同时开启两个前置开关时生效：CVR › DNS 覆写 → 必须开启「启用 DNS」和「使用 Hosts」。两个开关缺一不可！");
                console.log("💡 脚本无法检测 UI 层开关状态；未开启时仍打印成功日志");

                const targetStr = Array.isArray(target) ? target.join(" / ") : target;
                console.log(`🛡️ Hosts DNS 覆写已写入: ${hijackDomains.length} 条`
                    + `，模式: [${HOSTS_MODE}] → ${targetStr}`
                    + `，但需 CVR 开启「启用 DNS」与「使用 Hosts」才能生效。`);

                console.log(`   fake-ip-filter 本次清理旧脚本条目: ${cleanedCount} 条，`
                    + `新增注入: ${newEntries.length} 条`
                    + `（订阅原有非脚本条目共 ${existingSet.size} 条）`);
                if (existingSet.size === 0) {
                    console.log("   （订阅 fake-ip-filter 此前为空或已被 CVR UI 清空，已完整重建）");
                }
            } else {
                console.warn("⚠️ config.dns 类型异常，跳过 fake-ip-filter 维护");
            }
        } catch (err) {
            console.error("❌ Hosts DNS 覆写注入失败:", err);
        }
    }

    return config; // 返回修改后的最终配置

} // function main 结束

/**
 *
 * ══════════════════════ ░░ 附录：技术白皮书 ░░ ═══════════════════════
 * 
 * ══════════════════════════ ░░ 风险边界 ░░ ══════════════════════════
 *
 *   ⚠️ AND 逻辑规则版本依赖（两个粒度，需分别理解）：
 *     ① AND 整体：Mihomo v1.15 以下可能将整条 AND 规则静默忽略（udpBlock / processBlockRules 均受影响）
 *     ② AND 内嵌 DOMAIN-REGEX：即使 AND 整体可解析，内嵌 DOMAIN-REGEX 的括号语法在 v1.15 以下
 *        额外存在解析失败风险（特指 udpBlock 中含 _ADOBE_RAND_RE_STR 的条目）
 *     - 建议升级内核至 v1.15 或以上；若无法升级，将 AND 规则替换为单条
 *       PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP 作为进程级兜底（覆盖范围缩小）
 *
 *   ⚠️ 进程规则（PROCESS-NAME）：
 *     - 需要管理员权限 + TUN / Service 模式，系统代理模式下完全无效
 *     - Windows 进程名大小写不敏感，macOS / Linux 严格区分大小写
 *       扩展前务必在任务管理器中核对精确名称，建议仅作为辅助手段
 *
 *   ⚠️ 激进模式（ENABLE_AGGRESSIVE）：
 *     - 可能影响官网 / 插件商店 / 云功能访问，请阅读注释后谨慎开启
 *     - 已知受影响域名：adobe.io（插件市场/字体）、adsk.com（Autodesk 官网）、
 *       officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA 系统）
 *
 *   ℹ️ no-resolve 修饰符：
 *     - 仅对 IP 类规则（IP-CIDR / GEOIP）有意义，
 *       DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX 等域名类规则加 no-resolve 无效，本脚本已全部移除，无需手动处理
 *     - 补充：若流量到达 Mihomo（本脚本所依赖的代理内核）时已携带真实 IP（应用层自行完成 DNS（域名系统）解析），
 *       no-resolve 在此场景下自然无需发挥作用，规则仍按 IP 直接比对，与有无 no-resolve 无关
 *
 *   ⚠️ REJECT-DROP（静默丢包）vs REJECT（立即拒绝）选型原则：
 *     REJECT      → TCP 侧：立即返回 TCP RST（重置报文），软件快速感知失败（具体行为依软件实现而异），启动无卡顿；
 *                   UDP 侧：返回 ICMP Port Unreachable，软件同样立即感知失败；推荐用于遥测 / 授权域名
 *     REJECT-DROP → TCP/UDP 均适用：静默丢包，不回应任何报文；TCP 侧：软件 Socket 陷入 SYN_SENT 直至系统 TCP 超时，应用层 Socket 阻塞约 15–30s（含 TCP 重传轮次），
 *                   实际取决于 OS TCP 重传配置（Windows 10 默认 TcpMaxSynRetransmissions=2，SYN 重传总时长约 21s；Windows 11 默认值已调整，
 *                   实际超时可能有所不同）；UDP 侧：数据包被无声丢弃，软件等待响应直至应用层超时；仅用于非官方修改补丁后门（backdoorSuffix / backdoorKeyword）和进程规则，
 *                   以此拖延被拦截进程感知失败的时间（Socket 等待超时而非立即失败），阻碍恶意程序快速识别阻断并切换备用通信方式/域名，降低其自适应速度
 *     ⚡ 代价：软件启动时若命中 REJECT-DROP 会有明显卡顿，如遇启动极慢可将 REJECT-DROP 批量改为 REJECT
 *
 *   ⚠️ Hosts 模块生效前提（ENABLE_HOSTS_OVERRIDE）：
 *     - CVR › DNS 覆写，必须同时开启「启用 DNS」和「使用 Hosts」，缺一不可。
 *     - 脚本不写入 use-hosts，此字段由 CVR 的开关管理，写入后仍会被 CVR UI 设置覆盖，必须在 CVR › DNS 覆写 手动开启「使用 Hosts」，脚本无法替代手动操作。
 *     - 「使用系统 Hosts」与脚本注入的 Mihomo hosts 是两套完全独立的机制：前者对应系统原生 hosts 文件，后者由 Mihomo 内核管理，无需开启「使用系统 Hosts」。
 *     - 未开启时本模块静默失效（脚本仍打印成功日志，但拦截实际不生效）。
 *
 * ══════════════════════════ ░░ 设计取舍 ░░ ══════════════════════════
 *
 *   💡 规则去重策略：未采用 Set+filter 去重——真正原因是去重操作可能改变规则顺序，
 *      而 first-match 语义下顺序即策略，顺序改变直接导致规则语义变化（语义风险）。工程成本（代码复杂度）仅为次要因素。
 *      数据层按厂商拆分后各数组职责单一，跨数组重复概率极低，改由人工维护数据层唯一性。
 *      注：fake-ip-filter（虚假 IP 过滤表）合并使用 Set 仅为去重，顺序无关，与此场景不同。
 *
 *   💡 adobeSharedDeps（共用鉴权端点） 推测项集中于数组末尾：
 *      独立块注释区分「已确认 / 待抓包确认」，优先保证 Firefly 功能正常可用，而非严格遵循最小权限原则；待抓包确认后可视情况将推测项移至 adobeSuffix（改为 REJECT）。
 *
 *   💡 Firefly 依赖链放行（基于依赖链考量的必要豁免，原因见下）：
 *      isFireflyActive=true 时，以下进程的鉴权请求均走代理，进程规则仅覆盖 AdobeGCClient.exe：
 *        AdobeGCClient.exe  ← 由 processBlockRules REJECT-DROP 兜底（已覆盖）
 *        Creative Cloud.exe ← 含授权心跳（必要豁免）
 *        CCXProcess.exe     ← CC 扩展宿主进程（必要豁免）
 *        CoreSync.exe       ← CC 同步守护进程（必要豁免）
 *      取舍依据：非官方激活环境中，补丁修改了 AdobeGCClient.exe 的本地验证逻辑（本地返回激活成功，无需真实网络应答）；本脚本在此基础上阻断其出站连接，
 *      作为额外网络层防线，防止激活状态回报和设备信息上传。其余进程的心跳即便放行也不会触发重新验证；TUN 进程规则本身不可靠，扩展覆盖成本高于收益。
 *
 *   💡 KEYWORD "entitlement.autodesk" 与 "api.entitlements.autodesk.com" 无重叠：
 *      DOMAIN-KEYWORD 为子串匹配，"entitlement.autodesk"（entitlement 后紧跟点）
 *      在 "api.entitlements.autodesk.com"（entitlement 后跟 s 再跟点）中不存在；简言之：匹配 entitlement.autodesk.com，
 *      但不匹配 entitlements.autodesk.com（复数形式，不同 API 端点）。两者均为独立覆盖，不可互相替代（见 autodeskKeyword / autodeskSuffix 注释）。
 *
 *   💡 BLOCK vs AGGRESSIVE 重叠为纵深防御设计意图：
 *      "entitlement.autodesk" 同时出现在 autodeskKeyword（BLOCK 层）和 aggressiveRules（AGGRESSIVE 层）。
 *      所有开关组合下均无副作用，无需合并或删除任一条目（见 BLOCK vs AGGRESSIVE 重叠说明注释块）。
 *
 * ══════════════════════════ ░░ 逻辑架构 ░░ ══════════════════════════
 *
 *   ── 规则分层结构（layerPools 容器 + LAYER_ORDER 驱动）──
 *     allow → block → process → proxy → aggressive → direct
 *     first-match（首条命中即生效，后续规则对该连接不再参与匹配）
 *     layerPools（小写）为可变规则池（const 仅防止重新赋值，各层数组持续被 pushLayer 写入）；
 *     LAYER_ORDER（全大写 + Object.freeze）为真正不可变的优先级顺序声明，
 *     与 layerPools 键迭代顺序无关。调整 LAYER_ORDER 顺序即改变规则路由语义，操作前须理解各层依赖关系（见 LAYER_ORDER 注释处的两个典型错误示例）
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── 代理组识别策略链（多级降级，依次尝试直至成功）──
 *     [优选·关键词] 关键词 / include-all / 多节点三路并联  ← 最优先，覆盖最广
 *     [优选·正则]   正则宽松匹配           ← 次选，排除兜底组
 *     [优选·类型]   类型约束              ← 放宽数量约束
 *     [兜底降级]    兜底组选取             ← GLOBAL/"全局" 等
 *     [最终容错选取] 排除固定链路（relay）/ 测速专用（url-latency-benchmark）；smart 已纳入白名单，不再排除
 *     全部失败 → 直接 return config（显式中止注入，网络回退至订阅原始规则）
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── 哨兵清理算法（哨兵索引截断，O(N) 单次遍历，处理任意数量堆叠）──
 *     原理：单次遍历原数组，重建新数组 newRules，用栈记录每个 START 被压入时 newRules 的长度（注入区间在 newRules 中的起始快照）；
 *           遇 END 时弹出栈顶快照，将 newRules.length 设为快照值（O(1) 截断，length= 无 splice 的数组拷贝开销）；孤儿 END（栈为空）静默跳过（不 break，继续处理后续规则）；
 *           孤儿 START 本身不写入 newRules（continue 跳过），但其长度快照压栈；其后的规则正常推入 newRules，最终保留在输出中（旧注入规则与新注入共存一个周期）。
 *           循环结束后自然保留，无需额外处理；最坏情形：孤儿 START 是上次注入区间开头（崩溃导致 END 未写入），其后旧注入规则不被截断，
 *           但孤儿之后的完整配对仍可正确处理。此情形仅在上次 finalPool.concat 赋值未完成时出现，正常路径不产生孤儿。
 *
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── isFireflyActive 派生开关（Derived State，单向只读投影）──
 *     isFireflyActive 是 ENABLE_FIREFLY && ENABLE_BLOCK 的派生值，无独立存储，是两个上游开关逻辑与运算的投影，
 *     无法独立修改，即无法反向影响 ENABLE_FIREFLY 或 ENABLE_BLOCK。
 *     所有 Firefly 逻辑均使用此变量，防止"看起来开了但没生效"的状态误读（ENABLE_FIREFLY=true + ENABLE_BLOCK=false 时 Firefly 豁免不生效）。
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── client-fingerprint 注入模块 ──
 *     该模块在所有节点上统一注入 TLS 客户端指纹（如 chrome），以增强抗检测能力。
 *     设计意图：模拟主流浏览器 TLS 握手特征，减少因代理客户端指纹异常触发的验证码。
 *     注意：模块不覆盖已设置指纹的节点（尊重已有配置），修改 DEFAULT_FINGERPRINT 后需手动清理旧指纹。
 *     关键词跳过名单对 ASCII 关键词使用强边界正则匹配，对含中文关键词使用子串匹配。用于保护特殊节点（如专用 IP 落地机）不被修改。
 *     模块在 ENABLE_SCRIPT 检查之后执行，因此受 ENABLE_SCRIPT 统一控制。
 *   ──────────────────────────────────────────────────────────────
 * 
 * ══════════════════════════ ░░ 维护规范 ░░ ══════════════════════════
 *
 *   ⚠️ 位置解耦准则（严禁在注释中建立对绝对行号的行号锚点依赖，防止代码重构引发锚点失效）：
 *     - 【禁止绝对坐标】禁止在注释中引用具体行号（如「见 120 行」），必须使用变量名或锚点关键词定位（如「见 adobeSharedDeps 注释」）   
 *     - 【禁绝对值】禁止引用「数组第 N 项」、「前几项」、「第几个」等绝对坐标；
 *                  禁止引用策略编号（如「阶段 1」、「步骤 3」）；必须使用逻辑描述或变量名作为锚点（如「关键词优选策略」、「最终容错选取」）
 *     - 【禁止标记】严禁在逻辑行添加动态标记（如 // Fix by XXX），保持代码无状态
 *
 *   变量和常量的命名准则：
 *    _camelCase 对应运行时临时变量，_UPPER_CASE 对应运行时常量（冻结集合/正则），不应被修改。两段命名语义上是对称的，类似于"私有变量"与"私有常量"的区分惯例。
 * 
 *   🛠️ 编程防御：
 *     - 严禁直接访问 config[n]，必须使用 ?. 或 Array.isArray() 级联校验
 *     - 数据层（域名 / 组名）必须在配置区声明，逻辑层只负责读取，严禁硬编码
 *
 *   📐 注释语义与 emoji 规范：
 *     - 🛡️ [安全/防护/注入成功]  核心加固逻辑或注入点生效
 *     - 🚫 [拦截/阻断]           拦截策略、REJECT / REJECT-DROP 逻辑
 *     - 🔓 [放行/豁免]           Firefly 调度或特定域名白名单
 *     - ⚠️ [高危/警告/风险边界]  必须重点阅读，涉及系统代理失效或权限要求
 *     - ⚡ [风险/潜在隐患]       可能导致卡顿、重连或极端情况下的逻辑失效
 *     - ⚙️ [配置/开关]           用户可调节的变量定义
 *     - 🔍 [诊断/审计]           console.log 运行日志或逻辑对齐
 *     - 💡 [设计/原理]           解释为何不使用状态机、为何采用 for...of 哨兵索引截断等深度意图
 *     - ℹ️ [提示/注意]           中性信息说明，如环境要求、路径说明等
 *     - › 表示 UI 路径
 *     - → 逻辑结果、映射或规则路由
 */
