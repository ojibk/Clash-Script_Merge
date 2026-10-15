/**
 * Clash-Script 全局扩展脚本 · 基于哨兵标记的规则幂等注入 v261015
 * 功能：拦截广告/遥测/正版校验 + 白名单豁免特定 AI 服务（Adobe Firefly），Hosts 覆写，TLS 指纹注入等。
 * 使用：调整顶部配置区开关，在对应数组中增删域名，保存后重载订阅即可生效。
 */

function main(config) {
    const _startTime = Date.now();

    // ═══════════════ 通用诊断显示工具（异常安全） ═══════════════
    // _safeDisplayValue：将诊断值尽可能转为可读字符串；所有转换均纳入 try/catch，避免日志格式化中断脚本。
    // String(Symbol(...)) 安全；模板字符串直接插入 Symbol 才会抛 TypeError。
    // BigInt 加 n 后缀；函数、循环对象或转换失败的对象降级为类型描述。
    // 字符串保留 JSON 转义形式（含双引号），并对 JSON.stringify 不做显式转义的少数不可见字符做二次转义，
    // 以便在“值诊断”场景下稳定呈现 U+200B（ZWSP）、U+2028（LS）、U+2029（PS）、U+FEFF（BOM）等字符。
    // 说明：ECMAScript 的 JSON.stringify 对 C0 控制字符（U+0000–U+001F）会输出 \uXXXX，但对上述少数
    // Unicode 行分隔符与零宽字符不会显式转义；因此本函数在 JSON.stringify 之上追加一层仅用于诊断的可见化转义。
    // 该二次转义只作用于日志输出，不修改任何实际配置值。
    // ⚠️ 维护约束：_POST_JSON_ESCAPE_RE 与 _POST_JSON_ESCAPE_MAP 必须保持同步。
    //    若未来向正则新增字符而忘记更新映射，替换回调会返回 undefined 并由 `|| ch` 回退到原字符，静默失效；
    //    因此新增字符时必须同步在映射对象中补充对应条目。
    // 本函数保护值转换过程，但不保护此前的属性读取；节点名称读取需单独捕获异常。
    const _POST_JSON_ESCAPE_RE = /[\u200B\u2028\u2029\uFEFF]/g;
    const _POST_JSON_ESCAPE_MAP = {
        "\u200B": "\\u200B",
        "\u2028": "\\u2028",
        "\u2029": "\\u2029",
        "\uFEFF": "\\uFEFF",
    };
    const _safeDisplayValue = value => {
        try {
            if (value === null) return "null";
            if (typeof value === "function") return "<function>";
            if (typeof value === "symbol") return Symbol.prototype.toString.call(value);
            if (typeof value === "bigint") return `${value}n`;
            if (typeof value === "number" && !Number.isFinite(value)) return String(value);
            if (value instanceof RegExp) return RegExp.prototype.toString.call(value);
            if (value instanceof Map) return `Map(${value.size})`;
            if (value instanceof Set) return `Set(${value.size})`;
            const serialized = JSON.stringify(value);
            if (serialized === undefined) return String(value);
            // 对 JSON.stringify 未显式转义的少数不可见/行分隔字符做可见化处理。
            return serialized.replace(_POST_JSON_ESCAPE_RE, ch => _POST_JSON_ESCAPE_MAP[ch] || ch);
        } catch {
            try { return `<${typeof value}>`; }
            catch { return "<unprintable>"; }
        }
    };

    // _displayName：面向用户的“名称”日志（组名、节点名、类型名等），字符串直接原样输出，不附加 JSON 引号。
    // 与 _safeDisplayValue 分工明确：_displayName 承担可读性，_safeDisplayValue 承担值诊断的保真与转义。
    // 非字符串值回退到 _safeDisplayValue，因此组名若被 YAML 解析为数字等仍可安全展示。
    // 若名称为 Symbol，_safeDisplayValue 内部调用 Symbol.prototype.toString.call，避免直接模板插值抛错。
    const _displayName = value => {
        try {
            if (typeof value === "string") return value;
            return _safeDisplayValue(value);
        } catch {
            return "<unprintable>";
        }
    };

    // _formatError：默认输出单行 "name: message"；
    // name 与 message 会统一经 _toSingleLine 处理：非字符串分支也做 String 转换，并将 CRLF、CR、LF、U+2028、U+2029
    // 替换为可见的转义文本 \n（反斜杠加字母 n），避免任何输入破坏单行日志格式。
    // 如需完整堆栈定位，将 DEBUG_ERROR_STACK 置为 true（会输出多行）。
    const DEBUG_ERROR_STACK = false;

    // 优先匹配 CRLF 整体，使一个逻辑换行只产生一个可见的 \n 转义；
    // 其余行终止符按单个字符匹配。字符集为 ECMAScript 定义的行终止符集合。
    // 边界说明：该改进仅在含 CRLF 的输入下产生可观察差异。
    // 对只含 LF、CR、U+2028、U+2029 的输入，/\r\n|[\r\n\u2028\u2029]/g 与 /[\r\n\u2028\u2029]/g 行为一致。
    const _ONE_LINE_RE = /\r\n|[\r\n\u2028\u2029]/g;
    const _toSingleLine = value => {
        try {
            const s = typeof value === "string" ? value : String(value);
            // 替换字符串为 "\\n"：反斜杠 + 字母 n，输出可见的两个字符，保证结果不含实际换行。
            return s.replace(_ONE_LINE_RE, "\\n");
        } catch {
            return "<unprintable>";
        }
    };

    const _formatError = value => {
        try {
            if (value instanceof Error) {
                if (DEBUG_ERROR_STACK && typeof value.stack === "string" && value.stack) return value.stack;
                return `${_toSingleLine(value.name)}: ${_toSingleLine(value.message)}`;
            }
            return _safeDisplayValue(value);
        } catch {
            return `<${typeof value}>`;
        }
    };

    // _displayNameSingleLine：用于“名称必须出现在单行日志中”的场景。
    // 与 _displayName 的区别：对字符串也执行 _toSingleLine，把 CRLF/CR/LF/U+2028/U+2029 转为可见的 \n 文本，
    // 避免未清洗的节点名或自定义组名破坏日志格式。非字符串值经 _displayName 的安全回退后再单行化。
    // ⚠️ 该函数会改变名称的实际内容：若名称含行终止符，日志中显示的文本将与配置文件中的原始名称不完全一致。
    //    若需要按名称与配置文件逐字比对，请直接查看配置源文件，而非以日志输出为准。
    const _displayNameSingleLine = value => {
        try {
            return _toSingleLine(_displayName(value));
        } catch {
            return "<unprintable>";
        }
    };

    // ═══════════════ 配置区（按需调整） ═══════════════
    const ENABLE_SCRIPT                = true;            // 脚本总开关（关闭时仍执行遗留标记清理）
    const ENABLE_BLOCK                 = true;            // 拦截模块（域名层面；不影响进程拦截规则）
    const ENABLE_FIREFLY               = true;            // Firefly 专属豁免代理策略（豁免 Adobe 拦截并导向代理组；仅 ENABLE_BLOCK=true 时生效；ENABLE_BLOCK=false 时不注入 Firefly 专属规则）
    const ENABLE_PROCESS_RULE          = true;            // 进程规则总开关（同时控制进程拦截、进程代理、进程直连三组规则；需满足 Mihomo 的进程识别与流量接管条件；Windows 下通常还需 TUN + 管理员权限）
    const ENABLE_PROXY                 = true;            // 代理模块（域名层面；不影响进程代理规则）
    const ENABLE_AGGRESSIVE            = false;           // 激进阻断（谨慎开启）
    const ENABLE_GLOBAL_KEYWORD_BLOCK  = false;           // 全局关键词阻断（极度激进）
    const ENABLE_DIRECT                = true;            // 直连模块（域名层面；不影响进程直连规则）
    const ENABLE_HOSTS_OVERRIDE        = true;            // Hosts 覆写

    // Hosts 覆写与 Fake-IP 维护相互关联但并非同一功能：
    //   · Hosts 覆写负责写入 config.hosts；
    //   · Fake-IP 维护负责规范化 fake-ip-filter-mode 并按稳定管理集合清理/注入 fake-ip-filter 条目。
    // 二者独立开关，便于用户只保留其中一项。关闭 Fake-IP 维护时，脚本不会清理已写入的 +.domain 条目，
    // 也不会新增或规范化过滤列表，避免在缺少明确迁移策略的情况下静默删除用户配置。
    const ENABLE_FAKE_IP_MAINTENANCE   = true;            // Fake-IP 维护开关（独立于 Hosts 覆写）
    const HOSTS_MODE                   = "ipv4-loopback"; // 模式: ipv4-loopback | ipv4-blackhole | dual-loopback | dual-blackhole
    const ENABLE_CLIENT_FINGERPRINT    = true;            // TLS 指纹注入开关（为未设置 client-fingerprint 的代理配置批量写入；不按协议类型是否支持指纹注入情况过滤）
    const DEFAULT_FINGERPRINT          = "chrome";        // TLS 指纹默认预设（对未设置 client-fingerprint 的代理配置统一注入；不按协议类型是否支持指纹注入情况过滤）

    // 指纹跳过名单：含 Unicode 统一表意文字的关键词按子串匹配；其他关键词按 Unicode 字母边界匹配。
    // 连续字母子串（HKG / xHK）不命中 HK；数字、标点、空白、符号和 emoji 等非字母字符均视为边界，故 HK01、01HK、HK2 会命中。
    // 这比旧版预定义分隔符集合更宽，是本版本明确采用的语义；修改时须同步更新规格与回归用例。
    const FINGERPRINT_SKIP             = [];

    // tier1：手动精确指定总控代理组名（留空时跳过 tier1，进入 tier2~tier6 自动识别）
    const PRIMARY_GROUP_NAME           = "";

    // fake-ip-filter 在 whitelist/rule 模式下的迁移策略：
    //   false（默认）= 只计数并告警，不自动删除同值条目，避免误删用户自行维护的配置。
    //   true       = 允许删除匹配脚本稳定管理集合的条目（高级用户显式选择，自担风险）。
    // 注意：本开关仅作用于非 blacklist 模式；blacklist 模式下的自动清理仅针对“已确认由脚本稳定生成”的 +.domain 形式。
    // ⚠️ 行为补充：在 blacklist 模式下，除清理“脚本稳定管理条目”外，脚本还会执行一般性列表规范化，
    //    即删除非字符串条目、清洗后为空的条目，并对重复值去重（每类均带计数告警）。
    //    这意味着“仅维护脚本所有条目”这一表述不完全覆盖 blacklist 路径的实际副作用；若严格保护所有非脚本数据，
    //    需修改实现而非仅调整文案。当前保留规范化动作，因为非字符串/空值/重复项在 Mihomo 的 fake-ip-filter
    //    语义下均无实际匹配收益。
    const ALLOW_FAKE_IP_FILTER_MIGRATION = false;

    // 是否在未设置 fake-ip-filter-mode 时写回 "blacklist"：
    //   false（默认）= 仅在本地按默认值处理，不修改用户配置文本。
    //   true       = 显式写回 "blacklist"，便于配置审计，但会引入 diff 变化。
    // ⚠️ 本开关只控制“原本未设置模式时是否写回默认值”，并不控制所有模式规范化写回：
    //    若用户已显式提供 fake-ip-filter-mode（如 " BLACKLIST "），脚本仍会将其规范化为 blacklist 并写回，
    //    因为这是“已有值的规范化”而非“默认值写回”，属于无条件行为，与本文开关无关。
    const WRITE_BACK_DEFAULT_FAKE_IP_FILTER_MODE = false;

    // ═══════════════ process-proxy 目标声明（进程代理规则唯一维护点） ═══════════════
    // 增删进程代理目标：仅修改此数组，不要修改 processProxyRules。元素语义：进程名字符串；外围空白不具有业务意义
    const PROCESS_PROXY_TARGETS = [
        "Telegram.exe",
        // "Slack.exe",
    ];

    // 唯一规范化下游输入：下游 process-proxy 逻辑统一消费 processProxyTargets，不得直接读取 PROCESS_PROXY_TARGETS。
    // 容器策略：必须是数组；异常时告警并按空列表处理，避免 null 令脚本中止或字符串被逐字符迭代成错误规则。
    // 元素策略：类型约束 → trim → 空值剔除 → 结构字符过滤；非法非字符串/内部结构字符汇总 warn，规范化后空值静默剔除。
    // String.trim() 会规范化首尾 TAB/VT/FF/SP/NBSP/BOM(U+FEFF)/CR/LF/U+2028/U+2029。
    // 因此首尾换行与首尾 BOM 都按外围空白处理；内部换行与内部 BOM 都按结构错误或不可见字符处理。
    // U+200B（ZWSP）、U+200C（ZWNJ）、U+200D（ZWJ）、U+2060（WJ）不在 trim 范围内；
    // 它们不会破坏规则结构，但通常会导致规则无法命中实际进程名，因此保留该元素并汇总告警，由用户确认是否为误填。
    // U+FEFF 首尾会被 trim 清除；仅内部 U+FEFF 会进入不可见字符告警路径。
    const _PROCESS_TARGET_STRUCTURAL_RE = /[,\r\n\u2028\u2029]/;
    const _PROCESS_TARGET_INVISIBLE_RE = /[\u200B-\u200D\u2060\uFEFF]/;
    const _invalidProcessTargets = [];
    const _invisibleProcessTargets = [];
    const processProxyTargets = [];
    const _rawProcessTargets = Array.isArray(PROCESS_PROXY_TARGETS) ? PROCESS_PROXY_TARGETS : [];

    if (!Array.isArray(PROCESS_PROXY_TARGETS)) {
        const _actualProcessTargetsType = PROCESS_PROXY_TARGETS === null ? "null" : typeof PROCESS_PROXY_TARGETS;
        console.warn(`⚠️ PROCESS_PROXY_TARGETS 容器类型异常：期望数组，实际为 ${_actualProcessTargetsType}；已按空列表处理`);
    }

    for (const raw of _rawProcessTargets) {
        if (typeof raw !== "string") { _invalidProcessTargets.push(raw); continue; }

        const name = raw.trim();
        if (name === "") continue;
        if (_PROCESS_TARGET_STRUCTURAL_RE.test(name)) { _invalidProcessTargets.push(raw); continue; }

        if (_PROCESS_TARGET_INVISIBLE_RE.test(name)) _invisibleProcessTargets.push(name);
        processProxyTargets.push(name);
    }

    if (_invalidProcessTargets.length) {
        console.warn(`⚠️ PROCESS_PROXY_TARGETS 存在 ${_invalidProcessTargets.length} 个非法元素，已忽略：${_invalidProcessTargets.map(_safeDisplayValue).join("、")}`);
    }
    if (_invisibleProcessTargets.length) {
        console.warn(`⚠️ PROCESS_PROXY_TARGETS 存在 ${_invisibleProcessTargets.length} 个含不可见字符（U+200B/U+200C/U+200D/U+2060/U+FEFF）的元素，已保留但可能无法匹配实际进程名：${_invisibleProcessTargets.map(_safeDisplayValue).join("、")}`);
    }

    const fireflyUseProxy = ENABLE_FIREFLY && ENABLE_BLOCK;

    // ── proxyGroupName 消费者清单 ──
    //   ① ENABLE_PROXY                    → proxySuffixList
    //   ② fireflyUseProxy                 → Firefly allow
    //   ③ ENABLE_PROCESS_RULE + 目标非空  → processProxyRules
    const NEED_PROXY_GROUP =
        ENABLE_PROXY ||
        fireflyUseProxy ||
        (ENABLE_PROCESS_RULE && processProxyTargets.length > 0);

    // ═══════════════ 防御性检查 ═══════════════
    if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw new Error("[Script] 非法 config");
    }

    // rules：缺失/null 为正常场景，静默重置；类型异常为异常场景，警告后重置。
    // 重置而非跳过，是因为空数组是合法的 Mihomo 输入，而保留非法类型会导致本函数内后续对 config.rules 的数组操作（filter、for...of、concat 等）抛出 TypeError。
    if (config.rules == null) {
        config.rules = [];
    } else if (!Array.isArray(config.rules)) {
        console.warn(`⚠️ config.rules 类型异常（${typeof config.rules}），已重置为空数组以继续处理`);
        config.rules = [];
    }

    // proxy-groups：同上；注意 key 含连字符，必须用方括号访问
    if (config["proxy-groups"] == null) {
        config["proxy-groups"] = [];
    } else if (!Array.isArray(config["proxy-groups"])) {
        console.warn(`⚠️ proxy-groups 类型异常（${typeof config["proxy-groups"]}），已重置为空数组以继续处理`);
        config["proxy-groups"] = [];
    }

    if (ENABLE_FIREFLY && !ENABLE_BLOCK) console.warn("⚠️ Firefly 放行需 ENABLE_BLOCK=true");
    if (ENABLE_FIREFLY && ENABLE_AGGRESSIVE && !ENABLE_BLOCK) console.warn(`⚠️ ENABLE_BLOCK=false 时 Firefly 专属规则不会注入；若同时启用 ENABLE_AGGRESSIVE，可被识别为 adobe.io 的相关端点将命中 aggressiveRules 的 DOMAIN-SUFFIX 规则并 REJECT-DROP`);

    const _configuredFindProcessMode = config["find-process-mode"];
    if (ENABLE_PROCESS_RULE) {
        if (_configuredFindProcessMode == null) {
            console.log("ℹ️ 配置未显式声明 find-process-mode；Mihomo 通常默认使用 strict。如需强制匹配进程，可考虑 always，实际行为以目标核心版本为准。");
        } else if (_configuredFindProcessMode !== "strict" && _configuredFindProcessMode !== "always") {
            console.warn(`⚠️ 进程规则预期 find-process-mode=strict/always，当前 [${_safeDisplayValue(_configuredFindProcessMode)}]`);
        }
    }

    // ═══════════════ 共享常量：后门域名与 Hosts/Fake-IP 托管列表 ═══════════════
    // BACKDOOR_BASE_DOMAINS 是 Hosts 覆写与 Fake-IP 维护共用的基础域名清单。
    // hijackDomains 是派生的 +.domain 形式，两个独立功能块都读取它；放置在两个 if 之外，
    // 以便：无论 ENABLE_HOSTS_OVERRIDE 是否开启，Fake-IP 维护都能独立访问该列表，而不会因作用域问题抛 ReferenceError。
    const BACKDOOR_BASE_DOMAINS = [
        "966v26.com",                            // 后门裸域：用于 DOMAIN-SUFFIX、Hosts 与 Fake-IP 排除，覆盖裸域及其所有子域，如 api. 与 status. 等子域
        "vposy.com",                             // 非官方修改补丁作者关联域名
        "api.pzz.cn",                            // 国内后门回传接口（主动上报数据的 API 端点）
        // "cc-cdn.com",                         // 【待验证】命名形似 Adobe CC CDN，无抓包证据；当前不列入 Hosts/Fake-IP 管理集合
    ];
    const hijackDomains = BACKDOOR_BASE_DOMAINS.map(d => `+.${d}`);

    // ═══════════════ 哨兵完整性判定与幂等清理 ═══════════════
    // 安全原则：只有全部 START/END 结构完整时，才允许清理旧脚本块。
    // 若存在未闭合 START、孤立 END 或嵌套标记，保留 config.rules 原数组，且跳过本轮新规则注入；
    // 不尝试猜测异常标记附近哪些无标记规则属于旧版脚本。
    //
    // 哨兵必须是严格非嵌套结构：任意位置只允许一个未闭合 START。
    // 连续出现多组完整的 START/END（即 [START ... END][START ... END]）是允许的；
    // 但只要出现“尚未闭合的 START 之后又出现新的 START”，就判定为结构异常。
    // 理由：嵌套结构会让外层区间覆盖内层区间之外的用户规则，导致误删不属于脚本的内容。
    //
    // 异常处理边界：本扫描阶段不对数组索引读取做局部 try/catch。
    // 若 originalRules 是带异常索引访问器的特殊数组，异常会直接向 main(config) 的调用方传播，
    // 后续的哨兵清理、规则组装与 Hosts/Fake-IP 阶段都不会执行。
    // 这是一个明确的 fail-fast 选择：异常输入不应被静默吞掉，也不应让脚本在“结构可能已经损坏”的前提下继续执行；
    // 调用方（CVR/Mihomo 脚本宿主）会收到异常，并可按自身策略决定是否放弃本次配置重载。
    const _SENTINEL_START = "DOMAIN,START-rule-injection-sentinel.invalid,REJECT";
    const _SENTINEL_END   = "DOMAIN,END-rule-injection-sentinel.invalid,REJECT";
    let _sentinelIntegrityOk = true;

    // 记录进入哨兵阶段前的原始规则数组，供规则组装失败时进行真正的整段回滚。
    const _originalRulesBeforeSentinel = config.rules;
    {
        const originalRules = config.rules;
        const sentinelPairs = [];
        const openStack = [];
        const orphanEndIndices = [];
        const nestedStartIndices = [];

        for (let i = 0; i < originalRules.length; i++) {
            const rule = originalRules[i];
            if (rule === _SENTINEL_START) {
                if (openStack.length > 0) {
                    // 严格非嵌套：已有未闭合 START 时再次遇到 START，直接判定为结构异常。
                    nestedStartIndices.push(i);
                    // 仍继续扫描以收集完整的异常位置清单；配对逻辑按“忽略嵌套 START”处理。
                    continue;
                }
                openStack.push(i);
            } else if (rule === _SENTINEL_END) {
                if (openStack.length > 0) {
                    sentinelPairs.push({ startIndex: openStack.pop(), endIndex: i });
                } else {
                    orphanEndIndices.push(i);
                }
            }
        }

        const unmatchedStarts = openStack.slice().sort((a, b) => a - b);
        const firstUnclosedStart = unmatchedStarts.length ? unmatchedStarts[0] : null;
        const hasSentinelDamage =
            unmatchedStarts.length > 0 ||
            orphanEndIndices.length > 0 ||
            nestedStartIndices.length > 0;

        if (hasSentinelDamage) {
            // 发现任意哨兵损坏时，不进行局部清理。
            // 不能仅清理异常区域前的完整块，因为本轮同时会跳过新块注入，
            // 否则可能删除仍在承担路由功能的旧规则，造成规则净丢失。
            _sentinelIntegrityOk = false;

            if (unmatchedStarts.length) {
                const retainedTailLength = originalRules.length - firstUnclosedStart;
                console.warn(`⚠️ 检测到 ${unmatchedStarts.length} 个未闭合 START；最早未闭合位置为原始索引 ${firstUnclosedStart}，其后 ${retainedTailLength} 条原始规则属于受保护区域。`);
                for (const originalIndex of unmatchedStarts) {
                    console.warn(`   未闭合 START：原始规则索引 ${originalIndex}。`);
                }
            }
            if (orphanEndIndices.length) {
                console.warn(`⚠️ 检测到 ${orphanEndIndices.length} 个孤立 END 标记；原始索引：${orphanEndIndices.join("、")}。`);
            }
            if (nestedStartIndices.length) {
                console.warn(`⚠️ 检测到 ${nestedStartIndices.length} 个嵌套 START 标记（在尚未闭合的 START 之后出现新 START）；原始索引：${nestedStartIndices.join("、")}。`);
                console.warn("   嵌套哨兵会使外层区间覆盖内层之外的用户规则，属于结构异常，按整段保留处理。");
            }

            console.warn("⚠️ 哨兵结构异常：本轮不会清理任何旧脚本块，也不会注入新规则块；config.rules 保持原状。");
            console.warn("⚠️ 修复指引：在配置中搜索下列两条哨兵标记，使 START/END 成对、非嵌套出现后重载订阅：");
            console.warn(`   START = "${_SENTINEL_START}"`);
            console.warn(`   END   = "${_SENTINEL_END}"`);
            console.warn("⚠️ 每次加载都会重新检查哨兵结构；在 START/END 标记结构被人工修复前，规则块替换仍会被跳过。");
            console.warn("⚠️ 保留区可能包含旧版脚本规则，这些规则仍可能参与匹配，请人工检查后重载。Hosts/Fake-IP 等独立阶段仍会继续执行（脚本总开关关闭时除外）。");
        } else {
            // 结构完整时，所有配对都可以安全地作为旧脚本管理块移除。
            const shouldRemove = new Array(originalRules.length).fill(false);
            for (const pair of sentinelPairs) {
                for (let i = pair.startIndex; i <= pair.endIndex; i++) shouldRemove[i] = true;
            }
            const newRules = [];
            for (let i = 0; i < originalRules.length; i++) {
                if (!shouldRemove[i]) newRules.push(originalRules[i]);
            }
            config.rules = newRules;
        }
    }

    // ═══════════════ 脚本总开关与禁用标记逻辑 ═══════════════
    const _DISABLED_MARKER = "DOMAIN,debug-script-disabled.marker.invalid,REJECT";
    if (!ENABLE_SCRIPT) {
        if (_sentinelIntegrityOk) {
            config.rules = config.rules.filter(r => r !== _DISABLED_MARKER);
            config.rules.unshift(_DISABLED_MARKER);
        } else {
            console.warn("⚠️ 脚本总开关已关闭，但哨兵结构异常；为避免改动受保护规则，本轮不清理或新增禁用标记。");
            console.warn("⚠️ 由于禁用标记未写入规则列表，无法通过规则列表确认脚本已关闭；请以本控制台日志为准。");
        }
        return config;
    }

    // 只有哨兵结构完整时才清理遗留调试标记，避免异常恢复路径修改规则数组。
    if (_sentinelIntegrityOk) {
        config.rules = config.rules.filter(r => r !== _DISABLED_MARKER);
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
        // iOS 与 ios 都接受，以兼容旧脚本和不同版本文档中的大小写写法；目标 Mihomo 核心仍需实测确认。
        const _VALID = new Set(["chrome","firefox","safari","ios","iOS","android","edge","360","qq","random"]);
        let _rawFP;
        if (_VALID.has(DEFAULT_FINGERPRINT)) {
            _rawFP = DEFAULT_FINGERPRINT;
        } else {
            console.warn(`⚠️ 无效指纹 "${DEFAULT_FINGERPRINT}"，降级为 "none"`);
            _rawFP = "none";
        }

        // random = 脚本在配置重载时一次性解析，将结果写入所有需要注入的节点；单次重载内固定，跨重载重新抽取。
        // 概率：Chrome 50%，Safari 25%，ios 16.7%（即 1/6），Firefox 8.3%（即 1/12），与 Mihomo 原生 random 权重（6:3:2:1）一致。
        // 与原生 random 的差异在于抽样生命周期（脚本重载级 vs Mihomo 进程级），非概率分布。
        const _effectiveFP = _rawFP === "random"
            ? (() => {
                const rand = Math.random();
                if (rand < 0.50) return "chrome";
                if (rand < 0.75) return "safari";
                if (rand < 11/12) return "ios";
                return "firefox";
              })()
            : _rawFP;

        // 兼容旧配置中的 iOS 拼写；脚本统一输出小写 ios，核心接受值仍须按目标版本验证。
        const _normalizedFP = _effectiveFP === "iOS" ? "ios" : _effectiveFP;
        if (_effectiveFP === "iOS") {
            console.warn('⚠️ DEFAULT_FINGERPRINT="iOS" 已规范化为小写 "ios" 写入；请在目标 Mihomo 核心验证该值。');
        }

        if (_normalizedFP === "none") {
            console.log("ℹ️ TLS 指纹注入因配置无效已降级为 'none'，跳过");
        } else {
            if (_rawFP === "random") console.log(`💡 本次加载已从 random 解析为: ${_normalizedFP}`);
            // NODE_FINGERPRINTS：脚本当前认可的已有节点 client-fingerprint 有效值集合（比 _VALID 宽：另含 none / chrome120 / firefox120 / safari16）。
            // ⚠️ 该集合是"脚本当前认可"，非"Mihomo 全部有效值全集"；未来 Mihomo 增加新合法 fingerprint 时脚本不破坏但会告警，需手动更新。
            const NODE_FINGERPRINTS = new Set([
                "none",
                "chrome", "firefox", "safari", "ios", "iOS", "android", "edge", "360", "qq", "random",
                "chrome120", "firefox120", "safari16",
            ]);
            const _skipKw = [], _skipRe = [];
            for (const raw of FINGERPRINT_SKIP) {
                if (typeof raw !== "string" || !raw) continue;
                if (/\p{Unified_Ideograph}/u.test(raw)) _skipKw.push(raw.toLowerCase());
                else _skipRe.push(new RegExp(`(^|[^\\p{L}])${raw.replace(/[\\^$*+?.()|[\]{}]/g, '\\$&')}([^\\p{L}]|$)`, 'iu'));
            }

            let inj = 0, skip = 0, exist = 0, invalidProxyEntryCount = 0, proxyFieldErrorCount = 0;
            config.proxies = config.proxies.map(p => {
                if (!p || typeof p !== "object") {
                    invalidProxyEntryCount++;
                    return p;
                }
                try {
                    if (Array.isArray(p)) {
                        invalidProxyEntryCount++;
                        return p;
                    }
                } catch (err) {
                    invalidProxyEntryCount++;
                    console.warn(`⚠️ 无法检查代理数组项类型，已跳过指纹处理：${_safeDisplayValue(err)}`);
                    return p;
                }

                let hasFP, fpVal;
                try {
                    hasFP = Object.prototype.hasOwnProperty.call(p, "client-fingerprint");
                    fpVal = hasFP ? p["client-fingerprint"] : undefined;
                } catch (err) {
                    proxyFieldErrorCount++;
                    console.warn(`⚠️ 无法读取代理节点的 client-fingerprint，已跳过该节点：${_safeDisplayValue(err)}`);
                    return p;
                }

                const isAbsent = !hasFP || fpVal == null || fpVal === "";

                // 显式非空值优先：有效值直接保留；未知值保留并告警。仅为告警读取 name，且单独捕获异常。
                if (!isAbsent) {
                    if (!(typeof fpVal === "string" && NODE_FINGERPRINTS.has(fpVal))) {
                        let displayName = "?";
                        try {
                            const nodeNameForLog = p.name;
                            if (nodeNameForLog != null && nodeNameForLog !== "") displayName = nodeNameForLog;
                        } catch {
                            // 名称不可读只影响诊断标签，不影响已有指纹保留。
                        }
                        console.warn(`⚠️ 节点 [${_displayNameSingleLine(displayName)}] 的 client-fingerprint 值 ${_safeDisplayValue(fpVal)} 不在脚本认可的集合内，已保留原值不做覆盖`);
                    }
                    exist++;
                    return p;
                }

                // 只有未设置指纹时才读取节点名做 Skip 判断。
                let nodeName;
                try {
                    nodeName = p.name;
                } catch (err) {
                    proxyFieldErrorCount++;
                    console.warn(`⚠️ 无法读取代理节点名称，已跳过该节点的指纹处理：${_safeDisplayValue(err)}`);
                    return p;
                }

                let rawName;
                if (typeof nodeName === "string") {
                    rawName = nodeName;
                } else if (nodeName == null) {
                    rawName = "";
                } else {
                    try {
                        rawName = String(nodeName);
                    } catch (err) {
                        proxyFieldErrorCount++;
                        console.warn(`⚠️ 无法转换代理节点名称，已跳过该节点的指纹处理：${_safeDisplayValue(err)}`);
                        return p;
                    }
                }

                const lowerName = rawName.toLowerCase();
                const isSkipped = _skipKw.some(k => lowerName.includes(k)) || _skipRe.some(r => r.test(rawName));
                if (isSkipped) { skip++; return p; }

                try {
                    p["client-fingerprint"] = _normalizedFP;
                    inj++;
                } catch (err) {
                    proxyFieldErrorCount++;
                    console.warn(`⚠️ 无法写入代理节点的 client-fingerprint，已保留该节点原状：${_safeDisplayValue(err)}`);
                }
                return p;
            });

            console.log(`✅ TLS 指纹注入完成: 新增 ${inj}，跳过 ${skip}，已有字段 ${exist}，异常代理项 ${invalidProxyEntryCount}，字段访问/写入异常 ${proxyFieldErrorCount}；指纹: ${_normalizedFP}`);
            console.log("ℹ️ 配置写入成功不等同于 TLS/REALITY 握手已验证；REALITY 兼容性还受服务端版本及 Mihomo/uTLS 组合影响。");

            const realityNodeCount = config.proxies.filter(p => {
                try { return !!(p && typeof p === "object" && !Array.isArray(p) && p["reality-opts"]); }
                catch { return false; }
            }).length;
            if (realityNodeCount) {
                console.warn(`⚠️ 检测到 ${realityNodeCount} 个包含 reality-opts 的节点。client-fingerprint 不保证 REALITY 所需的 ML-KEM 能力。`);
                console.warn(`   关于 REALITY 兼容性，建议按以下顺序排查，而非直接套用单一字段：`);
                console.warn(`   1) 先核对目标 Xray 服务端版本与当前 Mihomo 版本的兼容性——Mihomo 文档中曾有与 Xray 高版本不兼容的声明；`);
                console.warn(`   2) 再检查当前 client-fingerprint 是否能够提供服务端所需的密钥交换参数；`);
                console.warn(`   3) 必要时按节点级追加 support-x25519mlkem768: true，并以真实握手结果为准。`);
                console.warn(`   本脚本不会自动注入该字段；是否添加请依据目标服务端与目标 Mihomo 版本的官方文档。`);
            }
        }
    }

    // ═══════════════ 1. 识别代理策略组（独立子阶段） ═══════════════
    let proxyGroupName = null;
    // 设计说明：代理组识别失败不再阻断独立规则生成。规则组装异常由外层 catch 隔离，确保仍会进入 Hosts 覆写阶段。
    if (NEED_PROXY_GROUP) {
        try {
            const EXCLUDED_NAMES = new Set(["DIRECT","REJECT","REJECT-DROP","COMPATIBLE","DEFAULT","MATCH","PASS"]);
            const FALLBACK_NAMES = new Set(["GLOBAL"]);
            const EXCLUDED_CN_RE = /^(?:全(?:部|网|球)|所有|默认|直连|拒绝)$/;
            const FALLBACK_CN_RE = /^全局$/;

            // 展示性组名负筛选：启发式，非完备识别器；覆盖已知展示性/信息面板命名模式，其中部分为低置信度。覆盖 tier1/2/3/4/6；tier5 走 fallback 路径不读 eligible，不受此约束。
            // 与 Merge.yaml 的 filter_basic 概念相关但独立维护，不应强制镜像词表。⚠️ 距离.{0,4}重置 未锚定、官网/网址 为低置信度，均可能误伤真实功能组名。
            const DECORATIVE_GROUP_NAME_RE =
                /订阅信息|流量信息|流量查询|剩余流量|到期时间|套餐(?:信息|到期)|距离.{0,4}重置|使用说明|免责声明|官网|网址/;

            const VALID_PROXY_TYPES = new Set(["select","url-test","fallback","load-balance","smart"]);
            const NONROUTABLE_TYPES = new Set(["relay","url-latency-benchmark"]);

            // ═══════════════ 基础控制字符集（清洗和校验共用） ═══════════════
            // 本集合用于清除代理组名中可能破坏匹配或规则结构的字符；.trim() 负责清理首尾可识别空白；
            // 正则额外清理出现在名称中间位置的以下字符：
            //   · C0 控制字符（U+0000–U+001F）与 C1 控制字符（U+007F–U+009F），含 DEL、NEL 等；
            //   · 软连字符、阿拉伯字母标记等格式类字符；
            //   · U+2000–U+200B 范围内的多种 Unicode 空格（含 EN QUAD、EM SPACE、零宽空格等）与格式字符；
            //   · U+200E–U+200F 双向控制字符；
            //   · U+2028–U+202E 段落/嵌入/覆盖类控制字符；
            //   · U+2060–U+2064、U+2066–U+2069 词连接符与方向隔离类控制字符；
            //   · U+FEFF BOM。
            // ⚠️ U+200C（ZWNJ）与 U+200D（ZWJ）刻意保留：
            //   · U+200D 请求连接相邻字符，参与部分 emoji ZWJ 序列：
            //     🏴‍☠️（U+1F3F4 U+200D U+2620 U+FE0F）、
            //     👨‍💻（U+1F468 U+200D U+1F4BB）；
            //   · U+200C 请求阻止连接，在阿拉伯语 / 波斯语 / 印度语系（天城文、孟加拉文等）中用于控制连字与字形；
            //   二者均为合法排版控制符，保留属文字兼容性考量。
            //   代价：不可见字符可能使组名难以辨识；保留它们是兼容性与可辨识性之间的取舍，不代表所有不可见字符都无风险。
            const _CONTROL_CHARS = "\u0000-\u001F\u007F-\u009F\u00AD\u061C\u2000-\u200B\u200E-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u2069\uFEFF";
            const _SANITIZE_RE = new RegExp(`[${_CONTROL_CHARS}]`, "gu");
            const sanitizeName = n => (typeof n === "string" && n) ? n.replace(_SANITIZE_RE, '').trim() : "";
            const _isFallback = t => !!(t && (FALLBACK_NAMES.has(t.toUpperCase()) || FALLBACK_CN_RE.test(t)));
            const _isEligible = t => !!(t && (_isFallback(t) || (!EXCLUDED_NAMES.has(t.toUpperCase()) && !EXCLUDED_CN_RE.test(t) && !DECORATIVE_GROUP_NAME_RE.test(t))));

            // 结构安全谓词（共享）：逗号是 Mihomo 规则字符串的字段分隔符，必须禁止；
            // CR/LF/U+2028/U+2029 会破坏单行规则结构，也必须禁止。
            // 方括号与花括号（[ ] { }）曾在旧版被一并拒绝，但 Mihomo 官方文档未明确禁止这些字符出现在代理组名中，
            // 且脚本未做实测验证。为避免误伤合法组名（如 "[主线路] 自动选择"），本版本不再将它们纳入硬性拒绝集合。
            // 若目标部署环境确实不接受这些字符，可通过外部配置或后续版本引入可选的严格校验开关。
            const _GROUP_NAME_STRUCTURAL_RE = /[,\r\n\u2028\u2029]/u;
            const hasStructuralGroupNameChars = name =>
                typeof name === "string" && _GROUP_NAME_STRUCTURAL_RE.test(name);

            // isSafeGroup：使用候选预处理阶段缓存的 nameValue 与 clean，不再访问原始对象的 name 属性。
            // 若该候选的 name 读取在预处理阶段已经捕获到异常，nameValue 为 undefined，本谓词返回 false；
            // 单个异常候选只影响自身，不影响其他候选。
            const isSafeGroup = e => {
                try {
                    if (!e) return false;
                    const name = e.nameValue;
                    if (typeof name !== "string") return false;
                    if (name === "") return false;
                    if (name !== e.clean) return false;
                    if (hasStructuralGroupNameChars(name)) return false;
                    return true;
                } catch {
                    return false;
                }
            };

            // entry 在此处声明，使候选识别分支与后续对象身份校验共享同一词法作用域。
            let entry = null;
            if (config["proxy-groups"].length) {
                const _KW_RE = /节点选择|手动选择|选节点|proxy|auto|自动|🚀|飞机|机场|线路|订阅|代理|选择/i;

                // 预处理候选：一次性缓存 name/type/include-all 等后续筛选依赖的属性。
                // 每个属性读取单独捕获异常，读取失败则该字段为 undefined，并用独立布尔标记区分“缺失 name”与“读取抛错”。
                // 后续所有 tier 的 filter/find、最终提交、对象身份校验均使用缓存字段，不再访问原始对象属性。
                const prepped = config["proxy-groups"].map(g => {
                    let nameValue;
                    let nameReadFailed = false;
                    let clean = "";
                    let typeValue;
                    let includeAllValue;
                    let includeAllProxiesValue;
                    let includeAllProvidersValue;
                    let useValue;
                    let proxiesValue;

                    try { nameValue = g?.name; } catch { nameValue = undefined; nameReadFailed = true; }
                    try { clean = sanitizeName(nameValue); } catch { clean = ""; }
                    try { typeValue = g?.type; } catch { typeValue = undefined; }
                    try { includeAllValue = g?.["include-all"]; } catch { includeAllValue = undefined; }
                    try { includeAllProxiesValue = g?.["include-all-proxies"]; } catch { includeAllProxiesValue = undefined; }
                    try { includeAllProvidersValue = g?.["include-all-providers"]; } catch { includeAllProvidersValue = undefined; }
                    try { useValue = g?.use; } catch { useValue = undefined; }
                    try { proxiesValue = g?.proxies; } catch { proxiesValue = undefined; }

                    return {
                        g,
                        nameValue,
                        nameReadFailed,
                        clean,
                        fallback: _isFallback(clean),
                        eligible: _isEligible(clean),
                        typeValue,
                        includeAllValue,
                        includeAllProxiesValue,
                        includeAllProvidersValue,
                        useValue,
                        proxiesValue,
                    };
                });

                // 候选诊断：六类分别列出——
                //   ① 缺失 name（undefined，且未发生读取异常）；
                //   ② 读取 name 时 getter 抛错（nameReadFailed 为 true，与抛出的值无关）；
                //   ③ 非字符串 name；
                //   ④ 清洗后与原始不同的 dirty name（含不允许的空白/控制/格式字符），附码点方便定位不可见字符；
                //   ⑤ 清洗后不变但仍含结构字符（当前主要为逗号）的 name —— CR/LF/U+2028/U+2029 会被 sanitizeName 清除，
                //      原始名称因此归入第四类，不会进入本类；
                //   ⑥ 空字符串 name —— 字段存在但值为空，会被 isSafeGroup 拒绝，与"缺失 name"语义不同（缺失是无有效字段）。
                const _codePointList = value => {
                    try {
                        return Array.from(String(value)).map(ch => `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`).join(" ");
                    } catch { return "<unprintable>"; }
                };

                const _missingNameGroups = [], _getterThrowGroups = [], _nonStringNameGroups = [], _dirtyNameGroups = [], _structuralNameGroups = [], _emptyNameGroups = [];
                prepped.forEach((e, i) => {
                    if (e.nameReadFailed) { _getterThrowGroups.push(i); return; }

                    const rawName = e.nameValue;
                    if (rawName === undefined) _missingNameGroups.push(i);
                    else if (typeof rawName !== "string") _nonStringNameGroups.push({ i, type: typeof rawName });
                    else if (rawName === "") _emptyNameGroups.push(i);
                    else if (rawName !== e.clean) _dirtyNameGroups.push({ i, name: rawName });
                    else if (hasStructuralGroupNameChars(rawName)) _structuralNameGroups.push({ i, name: rawName });
                });

                if (_missingNameGroups.length) console.warn(`⚠️ ${_missingNameGroups.length} 个代理组缺少 name 字段，已排除: ${_missingNameGroups.map(i => `[index=${i}]`).join("、")}`);
                if (_getterThrowGroups.length) console.warn(`⚠️ ${_getterThrowGroups.length} 个代理组的 name 读取时抛出异常，已排除: ${_getterThrowGroups.map(i => `[index=${i}]`).join("、")}`);
                if (_nonStringNameGroups.length) console.warn(`⚠️ ${_nonStringNameGroups.length} 个代理组 name 类型非字符串，已排除: ${_nonStringNameGroups.map(x => `[index=${x.i}, type=${x.type}]`).join("、")}`);
                if (_emptyNameGroups.length) console.warn(`⚠️ ${_emptyNameGroups.length} 个代理组 name 为空字符串，已排除: ${_emptyNameGroups.map(i => `[index=${i}]`).join("、")}`);

                if (_dirtyNameGroups.length) {
                    console.warn(`⚠️ ${_dirtyNameGroups.length} 个代理组名含不允许的空白/控制/格式字符，已排除:`);
                    for (const x of _dirtyNameGroups) console.warn(`   [index=${x.i}] 原始=${_safeDisplayValue(x.name)} 码点=${_codePointList(x.name)}`);
                }
                if (_structuralNameGroups.length) {
                    console.warn(`⚠️ ${_structuralNameGroups.length} 个代理组名含规则结构字符（当前主要为逗号），已排除:`);
                    for (const x of _structuralNameGroups) console.warn(`   [index=${x.i}] 原始=${_safeDisplayValue(x.name)} 码点=${_codePointList(x.name)}`);
                }

                // ═══════════════ 保留代理目标常量（用于排除已知的非代理特殊目标） ═══════════════
                const _RESERVED_PROXY_TARGETS = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]);

                // 仅做单层字面量检测：若 proxies 引用其他策略组，此处不会递归展开判断其最终是否包含真实代理来源。
                // 此为有意保留的边界，避免为代理组识别引入递归展开及循环引用处理。
                const isNonReservedProxyTarget = p => {
                    if (typeof p !== "string") return false;
                    const t = p.trim();
                    return t !== "" && !_RESERVED_PROXY_TARGETS.has(t.toUpperCase());
                };

                // 配置代理目标来源单一数据源（hasConfiguredNodeSource 和 _nodeDesc 共用）；新增引入方式时在此追加记录即可。
                // ⚠️ 设计取舍说明：hasConfiguredNodeSource 使用 some() 按数组顺序短路判断，仅检查"是否至少有一个来源能提供节点"，不比较不同组的节点数量。这意味着：
                //   若组A仅有1个静态节点，组B有50个 provider 节点，some() 对两者均返回 true；在 tier2 中先通过 filter() 汇总关键词候选并优先选择 select，tier3/tier4 则通过 find() 选择第一个符合条件的节点来源组，
                //   因此仍不会按节点数量择优。
                // 原因：1. 静态节点通常是用户精选的高质量节点，"少而精"可能优于"多而杂"；2. 避免为统计节点总数引入额外遍历开销。
                // ⚠️ 配置代理目标来源检测只判断配置中存在一种可接受的节点来源形态：不检查实际节点数量、过滤结果、健康状态或 provider 加载状态。新增节点来源方式时，在此追加 test/desc。
                // 对于 proxies 来源，仅判断存在非保留字符串，不验证该字符串是否确实对应 config.proxies / proxy-provider 或有效策略组成员，因此可能产生伪节点来源假阳性。
                // test 与 desc 参数为候选对象 e，属性访问使用缓存字段，不访问原始 g 上的属性。
                const NODE_SOURCE_CHECKS = [
                    {
                        test: e => Array.isArray(e.proxiesValue) && e.proxiesValue.some(isNonReservedProxyTarget),
                        desc: e => {
                            try { return `${e.proxiesValue.filter(isNonReservedProxyTarget).length} 个非保留 proxies 项`; }
                            catch { return "proxies 项读取异常"; }
                        },
                    },
                    {
                        test: e => Array.isArray(e.useValue) && e.useValue.length > 0,
                        desc: e => { try { return `use:${e.useValue.length} 个 provider`; } catch { return "use 读取异常"; } },
                    },
                    {
                        test: e => e.includeAllValue === true || e.includeAllValue === "true",
                        desc: () => "include-all",
                    },
                    {
                        test: e => e.includeAllProxiesValue === true || e.includeAllProxiesValue === "true",
                        desc: () => "include-all-proxies",
                    },
                    {
                        test: e => e.includeAllProvidersValue === true || e.includeAllProvidersValue === "true",
                        desc: () => "include-all-providers",
                    },
                ];

                const hasConfiguredNodeSource = e => {
                    try { return NODE_SOURCE_CHECKS.some(c => { try { return c.test(e); } catch { return false; } }); }
                    catch { return false; }
                };
                const _nodeDesc = e => {
                    try {
                        const hit = NODE_SOURCE_CHECKS.find(c => { try { return c.test(e); } catch { return false; } });
                        if (!hit) return "未检测到配置代理目标来源";
                        try { return hit.desc(e); } catch { return "描述读取异常"; }
                    } catch { return "节点来源诊断异常"; }
                };

                // tier（层级）多级降级识别：tier1 优先采用手动精确指定，tier2 匹配名称含关键词的合格策略组，tier3 包含 include-all，tier4 放宽名称限制，tier5 降级使用兜底组，tier6 最终容错
                // 所有 tier 均使用缓存字段，避免直接访问原始对象属性。
                // tier1：手动精确指定（PRIMARY_GROUP_NAME 非空时）——指定组验证成功后直接采用并跳过 tier2~tier6 的启发式识别；基础候选验证失败时回退自动识别。
                // ⚠️ isSafeGroup 检查放在 eligible 检查之前：手动指定的组若名称含脚本禁止的控制/格式字符，
                //    或清洗后发生改变（例如含逗号、C0/C1 控制字符、软连字符、RTL 控制字符等），必须在此处即回退到自动识别，
                //    而不是等到最终提交阶段才抛错并中止整条识别路径。
                if (PRIMARY_GROUP_NAME) {
                    const _hit = prepped.find(e => e.nameValue === PRIMARY_GROUP_NAME);
                    if (!_hit) {
                        console.warn(`⚠️ PRIMARY_GROUP_NAME=[${_displayNameSingleLine(PRIMARY_GROUP_NAME)}] 未在 proxy-groups 中找到同名条目，回退到自动识别`);
                    } else if (!isSafeGroup(_hit)) {
                        // 名称结构不安全：进入此分支的情形包括（与 sanitizeName 的清理范围一致）：
                        //   · 名称含脚本禁止的控制/格式字符（C0/C1 控制字符、软连字符、Unicode 行/段分隔符、双向控制字符等）；
                        //   · 名称在清洗后发生了任何变化（包括首尾空白、软连字符、阿拉伯字母标记等）；
                        //   · 名称含逗号（规则字段分隔符）。
                        // 注意：ZWJ/ZWNJ（U+200C/U+200D）是刻意保留的字符，不会被 sanitizeName 清除；含它们的合法组名
                        // 会通过 isSafeGroup，不会进入此分支。
                        console.warn(`⚠️ PRIMARY_GROUP_NAME=[${_displayNameSingleLine(PRIMARY_GROUP_NAME)}] 名称含脚本禁止的控制/格式字符，或清洗后发生改变；回退到自动识别`);
                    } else if (!_hit.eligible) {
                        // 提前用 eligible 拦一道，避免"这里预选成功、下面排除断言又将其剔除"这种前后矛盾的日志
                        console.warn(`⚠️ PRIMARY_GROUP_NAME=[${_displayNameSingleLine(PRIMARY_GROUP_NAME)}] 不符合代理组要求（命中保留目标/排除词，或不允许作为总控组），回退到自动识别`);
                    } else if (!VALID_PROXY_TYPES.has(_hit.typeValue) || !hasConfiguredNodeSource(_hit)) {
                        console.warn(`⚠️ PRIMARY_GROUP_NAME=[${_displayNameSingleLine(PRIMARY_GROUP_NAME)}] 存在，但类型不受支持或未检测到配置代理目标来源（type: ${_safeDisplayValue(_hit.typeValue)}, ${_nodeDesc(_hit)}），回退到自动识别`);
                    } else {
                        entry = _hit;
                        console.log(`✅ 代理组（手动指定 PRIMARY_GROUP_NAME）: [${_displayNameSingleLine(entry.nameValue)}]`);
                    }
                }

                // tier2: 关键词命中。多个候选并列时，优先取 type === "select"（人工总控选择组的惯例类型），
                // 命中多个候选时打印诊断日志列出全部候选，避免地区级 url-test 组（如含"自动"）或展示性 select 组
                // （如含"订阅"的"📊 订阅信息"）单纯因为排在数组前面而被静默选中。仍需强调：这不是"顺序无关"——
                // 无 select 候选、或多个候选类型相同时，胜出者依旧由数组声明顺序决定。
                if (!entry) {
                    const _tier2Candidates = prepped.filter(e => isSafeGroup(e) && e.eligible && !e.fallback && VALID_PROXY_TYPES.has(e.typeValue) &&
                        _KW_RE.test(e.clean) && hasConfiguredNodeSource(e));
                    entry = _tier2Candidates.find(e => e.typeValue === "select") || _tier2Candidates[0];
                    if (_tier2Candidates.length > 1) {
                        console.warn(`⚠️ tier2 命中 ${_tier2Candidates.length} 个候选组，已选 [${_displayNameSingleLine(entry?.nameValue)}]，其余候选：${_tier2Candidates.filter(e => e !== entry).map(e => `[${_displayNameSingleLine(e.nameValue)}](${_displayNameSingleLine(e.typeValue)})`).join("、")}`);
                    }
                }

                // tier3: 仅当 tier2 全表落空时，才接受包含 include-all 的合格策略组（此时数组顺序才会成为决定因素）
                if (!entry) entry = prepped.find(e => isSafeGroup(e) && e.eligible && !e.fallback && VALID_PROXY_TYPES.has(e.typeValue) &&
                    (e.includeAllValue === true || e.includeAllValue === "true") && hasConfiguredNodeSource(e));

                // tier4：取消名称关键词要求；名称排除词/装饰名过滤、类型、节点来源及非 fallback 条件仍生效
                if (!entry) entry = prepped.find(e => isSafeGroup(e) && e.eligible && !e.fallback && VALID_PROXY_TYPES.has(e.typeValue) && hasConfiguredNodeSource(e));

                // tier5: 降级使用兜底组
                if (!entry) {
                    entry = prepped.find(e => isSafeGroup(e) && e.fallback && VALID_PROXY_TYPES.has(e.typeValue) && hasConfiguredNodeSource(e));
                    if (entry) console.warn(`⚠️ 降级使用兜底组 [${_displayNameSingleLine(entry.nameValue)}]`);
                }

                // tier6: 最终容错
                if (!entry) {
                    entry = prepped.find(e => isSafeGroup(e) && e.eligible && e.typeValue != null && !NONROUTABLE_TYPES.has(e.typeValue) && hasConfiguredNodeSource(e));
                    if (entry) console.warn(`🚨 已进入最终容错，选取代理组 [${_displayNameSingleLine(entry.nameValue)}]`);
                }

                if (entry) {
                    if (!isSafeGroup(entry)) { console.error(`❌ 代理组名含首尾空白、不可见字符或结构非法字符`); throw new Error("proxy-group-setup-aborted: 代理组名结构不安全"); }
                    proxyGroupName = entry.nameValue;
                    console.log(`${entry.fallback ? "⚠️" : "✅"} 代理组: [${_displayNameSingleLine(proxyGroupName)}] (type: ${_displayNameSingleLine(entry.typeValue ?? "?")})`);
                } else {
                    console.error("❌ 无可用代理组，跳过依赖代理组的规则");
                    prepped.forEach((e, idx) => {
                        const { eligible, fallback } = e;
                        const status = (!eligible || !isSafeGroup(e)) ? "❌" : (fallback ? "⚠️" : "✅");
                        const groupName = _displayNameSingleLine(e.nameValue ?? "<name-unavailable>");
                        const groupType = _displayNameSingleLine(e.typeValue ?? "?");
                        console.log(`   ${idx + 1}. ${status} [${groupName}] (${groupType}, ${_nodeDesc(e)})`);
                    });
                    throw new Error("proxy-group-setup-aborted: 无可用代理组");
                }
            } else {
                console.error("❌ proxy-groups 为空，跳过依赖代理组的规则");
                throw new Error("proxy-group-setup-aborted: proxy-groups 为空");
            }

            // 代理组排除断言
            // ⚠️ 本断言不检查 DECORATIVE_GROUP_NAME_RE。当前 DECORATIVE 名称无法到达此处（普通路径已被 eligible 过滤；fallback 路径当前与其无交集）。若未来扩展 FALLBACK_NAMES 至含展示性名称，需同步检查此断言。
            {
                const s = sanitizeName(proxyGroupName);
                if (!s || EXCLUDED_NAMES.has(s.toUpperCase()) || EXCLUDED_CN_RE.test(s)) {
                    console.error(`❌ 代理组排除断言触发：[${_displayNameSingleLine(proxyGroupName)}]`);
                    throw new Error("proxy-group-setup-aborted: 代理组排除断言触发");
                }
            }

            // 结构字符校验：与 isSafeGroup 共用同一份 hasStructuralGroupNameChars 谓词（此处是候选对象写入全局状态后的独立复核，双层防御职责不同，不合并）。
            if (hasStructuralGroupNameChars(proxyGroupName)) {
                console.error(`❌ 代理组名含非法结构字符`);
                throw new Error("proxy-group-setup-aborted: 代理组名含非法结构字符");
            }

            // 防御性校验：确保识别的代理组仍存在于原数组中。
            // 使用对象身份比较，检查当前 config["proxy-groups"] 中是否仍存在 entry.g 这个对象本身。
            // ⚠️ 旧实现比较的是 prepped[idx].g 与 entry.g，两者取自同一缓存，恒为同一引用，
            //    无法发现当前数组中对象已被替换/删除的情形；此处改为按当前数组元素做对象身份校验。
            // 防御性写法：先判定 entry 存在，再读取 entry.g，避免未来重构后 entry 可能为 null 时抛 TypeError。
            if (!entry || !config["proxy-groups"].some(g => g === entry.g)) {
                console.error(`❌ 代理组 [${_displayNameSingleLine(proxyGroupName)}] 不存在`);
                throw new Error("proxy-group-setup-aborted: 代理组不存在于原数组");
            }
        } catch (err) {
            if (err instanceof Error && err.message.startsWith("proxy-group-setup-aborted")) {
                console.log("ℹ️ 代理组识别未成功，依赖代理组的规则将不会注入；独立规则仍会生成。");
            } else {
                console.error(`❌ 代理组识别异常: ${_formatError(err)}`);
            }
            proxyGroupName = null;
        }
    }

    // ═══════════════ 2. 数据层（不依赖代理组） ═══════════════
    const pushSuffix  = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN-SUFFIX,${v},${a}`); });
    const pushDomain  = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN,${v},${a}`); });
    const pushKeyword = (d, a, p) => d.forEach(v => { if (typeof v === "string" && v) p.push(`DOMAIN-KEYWORD,${v},${a}`); });

    // Firefly 专属域名的 TCP 限定规则：仅对 adobeFireflyOnly 中的域名生成 TCP 条件匹配，令这些域名的 UDP/QUIC 不经本层，
    // 交由 udpBlock 的 adobe.io/adobe.com 规则拦截。
    // ⚠️ 不承诺"REJECT 让 UDP/QUIC 快速失败"或"提供 TCP 回退条件"：UDP 侧的实际连接失败表现及 QUIC → TCP 回退时序
    //   由 Mihomo、客户端与协议栈共同决定，脚本不保证其行为（详见 udpBlock 上方的机制说明）。
    const pushFirefly = (d, a, p) => d.forEach(v => {
        if (typeof v === "string" && v) p.push(`AND,((NETWORK,TCP),(DOMAIN-SUFFIX,${v})),${a}`);
    });

    // ── Adobe 共用鉴权端点（包括 Firefly 和 CC） ──
    // 受控于 fireflyUseProxy = ENABLE_FIREFLY && ENABLE_BLOCK。当 ENABLE_BLOCK=true：ENABLE_FIREFLY=true → 代理组；ENABLE_FIREFLY=false → REJECT。
    // 当 ENABLE_BLOCK=false：整个 adobeSharedDeps 不注入任何层（既不代理也不拦截）。
    // 此处走 pushSuffix(无协议限定)，故 UDP 与 TCP 遵循相同的目标动作(Firefly 启用时二者皆走代理组，禁用时二者皆被 REJECT)，
    // UDP 最终是否经该代理组转发，还取决于所选出口是否支持 UDP。不像 adobeFireflyOnly 那样单独对 UDP 做 udpBlock 强制拦截。
    const adobeSharedDeps = [
        "ims-na1.adobelogin.com",                 // 登录令牌刷新
        "adobeid-na1.services.adobe.com",         // Adobe ID 服务
        "auth.services.adobe.com",                // Adobe ID 鉴权，Firefly Token 来源
        "cc-api-cp.adobe.io",                     // CC 权限校验，含 Firefly 订阅验证
        "cc-api-data.adobe.io",                   // CC 生成结果存储
        "lcs-roaming.adobe.io",                   // 云端许可漫游同步（联网同步后可暂时离线使用相关功能）/ Firefly 订阅状态同步
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
        "adobe-dns.adobe.com",                    // Adobe 自有 DNS 服务（可能用于内部服务发现或授权查询，拦截以增强隔离）
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

    const _ADOBE_ALNUM_SUBDOMAIN_RE = "^[A-Za-z0-9]{8,12}\\.adobe\\.io$"; // 匹配符合 8~12 位字母/数字命名模式的 .adobe.io 子域
    // const _ADOBESTATS_ALNUM_SUBDOMAIN_RE = "^[A-Za-z0-9]{10}\\.adobestats\\.io$"; // 匹配符合 10 位字母/数字命名模式的 .adobestats.io 子域
    const adobeRegex = [
        `DOMAIN-REGEX,${_ADOBE_ALNUM_SUBDOMAIN_RE},REJECT`,
        // `DOMAIN-REGEX,${_ADOBESTATS_ALNUM_SUBDOMAIN_RE},REJECT`, // 已被 adobeSuffix 的 "adobestats.io" 规则遮蔽
    ];

    // ── UDP / QUIC 拦截 ──
    // ⚠️ 当 ENABLE_BLOCK=true 时，相关 UDP 流量在 block 层已被 udpBlock 拦截（REJECT），因此 direct 层的 fonts/color/assets 规则不会直接匹配这些 UDP；支持 TCP 回退的客户端在回退后才可能命中对应的 TCP DIRECT 规则。
    // 此处使用 REJECT 而非 REJECT-DROP。UDP 侧的实际连接失败表现及 QUIC → TCP 回退时序由 Mihomo、客户端与协议栈共同决定，脚本不保证其行为。
    // REJECT 与 REJECT-DROP 在 UDP 场景的具体实现差异，应以目标核心版本源码为准；本脚本不绑定任何具体版本或提交作为该差异的断言依据。
    const udpBlock = [
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT",
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT",
        // "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobelogin.com)),REJECT", // ⚠️ Firefly 禁用时由 adobeSharedDeps 里的 "ims-na1.adobelogin.com" 用 pushSuffix（无协议限定）子域规则覆盖，Firefly 启用时 UDP 由 allow 层路由至代理组
        // "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT", // SUFFIX 规则的 adobestats.io（无协议条件）已覆盖所有协议，此处冗余
        // `AND,((NETWORK,UDP),(DOMAIN-REGEX,${_ADOBE_ALNUM_SUBDOMAIN_RE})),REJECT`, // 已被同层 adobe.io 的 UDP SUFFIX 规则覆盖，此处冗余
    ];

    // ── Adobe 遥测子域（wss 为子域名前缀，非协议标识）──
    const adobeWsDomain = ["wss.adobe.io"];

    // ── Firefly 生成式 AI 专属放行域名 ──
    // 注意：senseicore.adobe.io 与 senseimds.adobe.io 会被 _ADOBE_ALNUM_SUBDOMAIN_RE 规则（符合 8–12 位字母数字命名模式的 adobe.io 子域）命中
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

    // 运行时检查：每个 adobeFireflyOnly 域名都应落在 adobe.com 或 adobe.io 之下，
    // 以便由 udpBlock 的对应后缀规则处理其 UDP/QUIC 流量。
    // 不在覆盖范围内的域名，其 UDP/QUIC 流量不会被这两条规则拦截。
    // ⚠️ 即使域名属于上述域，若因 ECH 等原因导致域名无法被可靠识别，相关 UDP 规则仍可能失效，Firefly 同样受此限制。
    {
        const _uncovered = adobeFireflyOnly.filter(d => !/\.(adobe\.com|adobe\.io)$/i.test(d));
        if (_uncovered.length) {
            console.warn(`⚠️ adobeFireflyOnly 存在无法被 udpBlock 覆盖的域名，相关 UDP/QUIC 流量将失去 UDP 层拦截覆盖: ${_uncovered.join(", ")}`);
        }
    }

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

    // ── Autodesk (CAD / 3dsMax / Maya) 授权、遥测及相关端点拦截 ──
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
        "autodesk.com.edgekey.net",              // Akamai CDN 节点（推断授权校验请求会经此回源；拦截后可能影响下载等服务，但此处优先保障授权拦截）
        "crp.autodesk.com",                      // 云渲染授权
        "autodesk.flexnetoperations.com",        // FlexNet Operations 许可云平台
        "entitlement.autodesk.com",              // 疑似 Autodesk 授权端点；待抓包验证，拦截后可能影响正版授权校验
    ];
    const autodeskDomain = [
        "ipm-aem.autodesk.com",                  // 弹窗消息（精确匹配）
    ];
    const autodeskKeyword = [
        // "adlm",                                  // 桌面许可证模块关键词。⚠️ 4字符短串，存在低概率误伤不相关含 adlm 子串的域名
        "telemetry.autodesk",                    // Autodesk 遥测域关键词兜底
        "entitlements.autodesk",                 // Autodesk 授权域关键词兜底
    ];

    // ── 非官方修改补丁后门 ──
    const backdoorSuffix = [...BACKDOOR_BASE_DOMAINS];
    const backdoorKeyword = ["966v26"];          // 后门特征关键词。当前维护范围内未发现合法域名包含该字符串，误匹配概率极低。

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
        // "tonec.com",                             // ⚠️ 泛域阻断：IDM 开发商官网
    ];
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
        // "watson.telemetry.microsoft.com",        // Watson 崩溃报告服务，冗余覆盖，被上条遮蔽
        "nexus.officeapps.live.com",             // Office 遥测上报
        "officeclient.microsoft.com",            // Office 客户端统计
        "vortex.data.microsoft.com",             // Windows 错误报告
        "settings-win.data.microsoft.com",       // Windows 诊断数据上报
        // 注：当前按 v10/v20 两个版本域名分别枚举拦截。若微软推出 v30 等新版本需手动添加；
        // 若改用 DOMAIN-SUFFIX,events.data.microsoft.com 则覆盖未知子域，但也会扩大拦截面。
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
        // "upgrade.hikvision.com",                 // 海康固件升级检查（拦截后固件更新通知失效）
        // "ezdns.hikvision.com",                   // 海康 DDNS 回传（拦截后 HiDDNS 远程访问失效）
        // "cloudmsg.hikvision.com",                // 海康云消息推送（拦截后移动端报警推送失效）
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
        // "i.snssdk.com",                          // 字节跳动国内 SDK 主接口，拦截后可能导致字节系应用 SDK 初始化异常
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
        "2345.com",                              // 2345 生态主域：如导航/弹窗等，整体阻断
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
        // Flash
        "flash.cn",                              // Flash 国内分发域
        // PotPlayer（注意：以下 Kakao/Daum 分析平台结构域名基于 2019-2020 年的抓包资料与第三方 hosts 名单，建议定期抓包复核）
        "stat.tiara.kakao.com",                  // Kakao Tiara 分析平台统计上报
        "track.tiara.daum.net",                  // Daum/Kakao 追踪端点
        "analytics.ad.daum.net",                 // Daum 广告分析
        "display.ad.daum.net",                   // Daum 广告展示
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

    // ── Google / Chrome 隐私追踪与功能服务 ──
    const googleTrackSuffix = [
        "google-analytics.com",                  // Google Analytics 主域
        "analytics.google.com",                  // Google Analytics API
        "googletagmanager.com",                  // Google Tag Manager
        "redirector.gvt1.com",                   // Google 更新/扩展下载重定向服务（非纯遥测，拦截可能影响更新）
        "optimizationguide-pa.googleapis.com",   // Chrome 优化提示遥测
    ];
    const googleTrackKeyword = ["safebrowsing.google"]; // Safe Browsing 接口（拦截后失去钓鱼防护）

    // ── YouTube 遥测与 CDN 负载均衡 ──
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
    const globalKeyword = ["telemetry", "analytics", "stats", "metrics"]; // ⚠️ 慎用：存在误匹配风险，仅建议临时排查，不建议长期启用

    // ═══════════════ 进程规则（需满足 Mihomo 的进程识别与流量接管条件；Windows 下通常还需 TUN + 管理员权限）═══════════════
    // 注：规则中 REJECT-DROP（静默丢弃请求）不主动返回拒绝结果；REJECT（立即拒绝连接）TCP 场景通常表现为快速失败，具体表现取决于传输协议及应用自身的重试/超时策略。选择依据是进程对网络超时的敏感度。
    const processBlockRules = [
        // "AND,((NETWORK,UDP),(DST-PORT,443),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP", // 仅 UDP 443
        // "AND,((NETWORK,UDP),(PROCESS-NAME,AdobeGCClient.exe)),REJECT-DROP", // 全部 UDP
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",        // Adobe 正版验证进程；在前置域名规则未命中时，兜底拦截该进程的剩余流量（TCP+UDP）
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

    // ── 进程代理规则（只读，由 PROCESS_PROXY_TARGETS 派生） ──
    // 不要直接修改此数组；增删进程代理目标请修改 PROCESS_PROXY_TARGETS。位置保持：位于代理组识别块之后。
    // 控制流说明：代理组识别失败后，外层 catch 会把 proxyGroupName 设置为 null 并继续执行；
    // 因此本 IIFE 会被执行到。其内部的显式 guard 会在 proxyGroupName 不可用时返回空规则集，
    // 避免生成目标为 null 的进程规则（即 "PROCESS-NAME,xxx,null"）。
    // 这是纵深防御：既依赖 NEED_PROXY_GROUP 公式保证必要条件，又依赖显式 guard 保证安全失败。
    const processProxyRules = (() => {
        if (!ENABLE_PROCESS_RULE || !processProxyTargets.length) return [];
        if (typeof proxyGroupName !== "string" || proxyGroupName === "") {
            console.warn("⚠️ processProxyTargets 非空但 proxyGroupName 不可用，已跳过进程代理规则");
            return [];
        }
        return processProxyTargets.map(name => `PROCESS-NAME,${name},${proxyGroupName}`);
    })();

    const processDirectRules = [ // 进程直连规则
        // "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",              // 百度网盘
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
        "store.steampowered.com",                 // Steam 商店
        "steamcommunity.com",                     // Steam 社区
        "login.steampowered.com",                 // Steam 登录鉴权 (极易被阻断，需代理)
        "help.steampowered.com",                  // Steam 客服/退款 (易被阻断)
        "steam-chat.com",                         // Steam 好友聊天框架
        "api.steampowered.com",                   // Steam API，视网络情况决定是否代理
        // "steamstatic.com",                        // (可选) 如果 Steam 商店页面经常加载不出图片和CSS排版，可取消注释放入代理
        // "steamusercontent.com",                   // Steam 创意工坊/用户截图/头像
        // "openai.com",                             // OpenAI，有地区限制需绕开
        // "gemini.google.com",                      // Gemini（⚠️ 与 google.com 须同策略组，IP 不同可能触发风控）
    ];

    // ── 直连规则 ──
    const directRules = [
        // 厂商官网与常用服务
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
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",        // NCSI 连通性探测（直连以确保网络状态检测正常；拦截可能导致 Windows 显示「无网络」）
        "DOMAIN-SUFFIX,msftncsi.com,DIRECT",               // NCSI 旧版探测域
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",            // Adobe Fonts 字体同步服务
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",            // Adobe Color 配色工具
        "DOMAIN,assets.adobe.com,DIRECT",                  // Adobe 静态资源 CDN（精确匹配以防无关子域被直连）
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",               // Autodesk 官网放行（下载/论坛）
        "DOMAIN-SUFFIX,corel.com,DIRECT",                  // Corel 官网放行
        // 基础设施
        "AND,((NETWORK,UDP),(DST-PORT,123)),DIRECT",       // NTP 时间同步：对被 Mihomo 接管的 UDP/123 流量生效
        // 游戏平台
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",           // Steam 主域系直连（部分业务子域已由前置规则代理）
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",           // Steam 游戏内容分发 CDN（高带宽资源直连）
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",            // Steam 联机对战后端
        "DOMAIN-SUFFIX,steamstatic.com,DIRECT",            // Steam 商店静态资源
        // 工具与下载站
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
        // "DOMAIN-KEYWORD,amazon,DIRECT",                 // 亚马逊直连（⚠️ 会覆盖 AWS，若需代理可改用精确规则）
        // "DOMAIN-SUFFIX,tmall.hk,DIRECT",                // 淘宝 .hk 域，如被代理可能影响商品价格加载
    ];

    // ── 激进阻断规则（默认关闭）──
    const aggressiveRules = [
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",                // adobe.io 裸域+全部子域
        // "DOMAIN-REGEX,^.+\\.adobe\\.io$,REJECT-DROP",     // 所有 adobe.io 子域（已由上条 SUFFIX 超集覆盖，此条冗余）
        "DOMAIN,cclibraries-defaults-cdn.adobe.com,REJECT", // CC Libraries 默认资源 CDN（功能性端点，拦截后默认画笔/色板不可加载）；需快速失败避免面板挂起
        // "DOMAIN-SUFFIX,workflowusercontent.com,REJECT-DROP", // 多平台共用域，建议审查后启用
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",              // Office CDN
        "DOMAIN,geo.adobe.com,REJECT-DROP",                  // Adobe 地理区域识别
        "DOMAIN,geo2.adobe.com,REJECT-DROP",                 // Adobe 地理区域识别备用
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",   // Autodesk 账户登录
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP",         // IE 内核在线检测 / 旧版 Office 激活
    ];

    // ═══════════════ 3. 规则组装与注入（受哨兵完整性门禁） ═══════════════
    if (!_sentinelIntegrityOk) {
        console.warn("⚠️ 因哨兵结构异常，本轮跳过新规则注入；保留原有规则，继续执行 Hosts/Fake-IP 阶段。");
    } else {
        // 事务式组装：先在临时变量中完成全部构建，只有全部步骤成功，才一次性写回 config.rules。
        // 失败时回退到进入哨兵阶段前的原始规则数组 _originalRulesBeforeSentinel，而非清理后的中间状态；
        // 这保证失败路径下旧脚本块与新规则块要么同时保留、要么同时替换，不留下半成品。
        // ⚠️ 边界：本事务只覆盖 config.rules。指纹注入发生在规则组装之前，其副作用不随本回滚撤销。
        try {
            // 层序：allow 与 block 先行；aggressive 只对其后的 process/proxy/direct 层具有更高优先级，不覆盖前置 allow/block。
            const LAYER_ORDER = Object.freeze(["allow","block","aggressive","process","proxy","direct"]);
            const layerPools = { allow:[], block:[], aggressive:[], process:[], proxy:[], direct:[] };
            const pushLayer = (l, r) => {
                if (!(l in layerPools)) {
                    throw new Error(`[Script] 未知层 '${l}'，请检查 layerPools 键名`);
                }
                if (!Array.isArray(r)) {
                    throw new TypeError(`[Script] 层 '${l}' 的规则集合必须为数组`);
                }
                for (const x of r) {
                    if (typeof x !== "string" || !x) {
                        throw new TypeError(`[Script] 层 '${l}' 存在空字符串或非字符串规则项`);
                    }
                    layerPools[l].push(x);
                }
            };

            const effectiveProxyGroupName = (typeof proxyGroupName === "string" && proxyGroupName !== "") ? proxyGroupName : null;
            const useFireflyProxy = fireflyUseProxy && effectiveProxyGroupName !== null;

            if (ENABLE_BLOCK) {
                // 放行模式下注入 allow 层（先于 block 匹配），拦截模式下注入 block 层
                const [act, pool] = useFireflyProxy ? [effectiveProxyGroupName, layerPools.allow] : ["REJECT", layerPools.block];
                if (fireflyUseProxy && !useFireflyProxy) {
                    console.warn("⚠️ Firefly 放行需要有效代理组，但代理组不可用，已降级为拦截模式（REJECT）。");
                }
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

            if (ENABLE_AGGRESSIVE) pushLayer("aggressive", aggressiveRules);

            if (ENABLE_PROCESS_RULE) {
                pushLayer("process", processBlockRules);
                if (processProxyRules.length) pushLayer("process", processProxyRules);
                pushLayer("process", processDirectRules);
            }

            if (ENABLE_PROXY) {
                if (effectiveProxyGroupName !== null) {
                    pushSuffix(proxySuffixList, effectiveProxyGroupName, layerPools.proxy);
                } else {
                    console.warn("⚠️ 代理规则需要有效代理组，但代理组不可用，已跳过代理规则注入。");
                }
            }

            if (ENABLE_DIRECT) pushLayer("direct", directRules);

            const finalPool = [_SENTINEL_START];
            for (const k of LAYER_ORDER) for (const r of layerPools[k]) finalPool.push(r);
            finalPool.push(_SENTINEL_END);

            // 提交点：至此所有构建步骤均已成功。此时才把哨兵清理后的规则接到新规则池之后。
            config.rules = finalPool.concat(config.rules);

            console.log("=".repeat(28));
            console.log("✅ 规则注入成功");
            console.log(`   脚本状态: ✅ 已启用`);
            console.log(`   拦截模块（域名层）: ${ENABLE_BLOCK ? "✅" : "❌"}`);

            // Firefly 状态四态化：区分"未启用 / 拦截模块关闭未注入 / 代理组不可用降级 / 正常放行"。
            // 当 ENABLE_BLOCK=false 且 ENABLE_AGGRESSIVE=true 时，Firefly 域名仍会被 aggressive 层的 adobe.io 规则无差别拦截；
            // 因此本状态行若显示“未注入 Firefly 专属规则”，紧随其后的 aggressive 层警告会补充说明实际拦截路径。
            if (!ENABLE_FIREFLY) {
                console.log(`   Firefly 放行: ❌ (ENABLE_FIREFLY=false)`);
            } else if (!ENABLE_BLOCK) {
                console.log(`   Firefly 放行: ❌ (ENABLE_BLOCK=false，未注入 Firefly 专属规则)`);
                if (ENABLE_AGGRESSIVE) {
                    console.warn(`      注：当前 ENABLE_AGGRESSIVE=true，adobe.io 相关域名仍会命中激进阻断规则；Firefly 可能因此不可用。`);
                }
            } else if (!effectiveProxyGroupName) {
                console.log(`   Firefly 放行: ❌ (代理组不可用，已降级为 REJECT)`);
            } else {
                console.log(`   Firefly 放行: ✅ (allow 层，走 ${_displayNameSingleLine(effectiveProxyGroupName)})`);
            }

            console.log(`   进程规则: ${ENABLE_PROCESS_RULE ? "✅ (需满足进程识别与流量接管条件，如：管理员权限+TUN)" : "❌"}`);
            console.log(`   代理规则（域名层）: ${ENABLE_PROXY ? (effectiveProxyGroupName ? "✅" : "⚠️ 已跳过（无有效代理组）") : "❌"}`);

            if (ENABLE_AGGRESSIVE) {
                console.warn(`   激进阻断: ⚠️ 已开启（位于 process/proxy/direct 之前，但不覆盖 allow/block）`);
                console.warn(`   ⚠️ 激进阻断可能导致以下服务不可用：`);
                console.warn(`      - adobe.io（CC 插件/API 端点）`);
                console.warn(`        注：ENABLE_BLOCK=true 时 Firefly 域名先由上游规则处理，放行或拦截取决于 ENABLE_FIREFLY；ENABLE_BLOCK=false 时同样被本规则无差别拦截`);
                console.warn(`      - accounts.autodesk.com（Autodesk 账户登录）`);
                console.warn(`      - geo.adobe.com / geo2.adobe.com（Adobe 地理区域识别）`);
                console.warn(`      - officecdn（Office 更新/模板）`);
                console.warn(`      - ieonline.microsoft.com（ActiveX/旧版 Office 激活）`);
            } else {
                console.log(`   激进阻断: ❌`);
            }

            if (ENABLE_GLOBAL_KEYWORD_BLOCK)
                console.warn(`   全局关键词阻断: ⚠️ 已开启 (含: ${globalKeyword.join(", ")})`);
            else
                console.log(`   全局关键词阻断: ❌`);

            console.log(`   直连规则（域名层）: ${ENABLE_DIRECT ? "✅" : "❌"}`);
            console.log(`   Hosts 覆写: ${ENABLE_HOSTS_OVERRIDE ? "✅ [" + HOSTS_MODE + "]" : "❌"}`);
            console.log(`   Fake-IP 维护开关: ${ENABLE_FAKE_IP_MAINTENANCE ? "✅ 已启用（结果见后续阶段日志）" : "❌ 已关闭"}`);

            const _LAYER_LABELS = {
                allow:"白名单/条件代理优先层",
                block:"拦截层",
                aggressive:"激进层（优先于 process/proxy/direct）",
                process:"进程层",
                proxy:"代理层",
                direct:"直连层"
            };
            for (const k of LAYER_ORDER) {
                console.log(`      - ${_LAYER_LABELS[k]} (${k})  : ${layerPools[k].length} 条`);
            }
            console.log("=".repeat(28));

            if (ENABLE_BLOCK) {
                console.log("ℹ️ [udpBlock] 相关 UDP 规则依赖域名识别；无法可靠获得目标域名时，相关规则可能无法命中（包括 ECH 等场景），Firefly 的 UDP/QUIC 回退亦受影响。");
            }
        } catch (err) {
            // 组装失败：回退到进入哨兵阶段前的原始规则数组，保留旧脚本块，
            // 避免留下"旧块已清、新块未注入"的空配置。
            config.rules = _originalRulesBeforeSentinel;
            console.error(`❌ 规则注入异常，已回退到哨兵处理前的原始规则集，继续执行 Hosts: ${_formatError(err)}`);
        }
    }

    // ═══════════════ 4. Hosts 覆写 ═══════════════
    // 与 Fake-IP 维护分离：Hosts 覆写只负责写入 config.hosts；Fake-IP 维护只负责 DNS 过滤列表。
    // 两者各自 try/catch，异常不再共用同一条错误日志。
    // hijackDomains 与 BACKDOOR_BASE_DOMAINS 均在两个阶段之外的共享作用域中声明，任一开关关闭都不影响另一阶段访问。
    //
    // ⚠️ 冲突提示：Mihomo 的 Hosts 匹配规则中，精确域名键（如 `api.966v26.com`）的优先级高于通配符键（如 `+.966v26.com`）。
    //    若用户原有的 config.hosts 中已存在某个托管域名的子域精确键，脚本追加的 `+.domain` 通配键不会覆盖它；
    //    该子域将按用户原有的精确映射解析，而非脚本目标地址（如 127.0.0.1）。
    //    脚本会检测这类冲突并输出告警，但不会静默删除或覆盖用户的精确键——用户的精确映射可能是有意保留的控制权。
    //    如确需脚本完全接管，请手动移除冲突的精确键后重载。
    if (ENABLE_HOSTS_OVERRIDE) {
        try {
            const modeMap = new Map([
                ["ipv4-loopback", "127.0.0.1"],
                ["ipv4-blackhole", "0.0.0.0"],
                ["dual-loopback", ["127.0.0.1", "::1"]],
                ["dual-blackhole", ["0.0.0.0", "::"]],
            ]);
            const target = modeMap.get(HOSTS_MODE);
            if (target === undefined) throw new Error(`未知 HOSTS_MODE: ${HOSTS_MODE}`);

            const customHosts = Object.fromEntries(
                hijackDomains.map(d => [d, Array.isArray(target) ? [...target] : target])
            );

            // config.hosts：缺失/null 为正常场景，静默创建空对象；
            // 类型异常时忽略非法值并继续写入脚本指定的 Hosts 条目，
            // 以保证 Hosts 覆写这一核心功能不被跳过。
            let _hostsBase;
            if (config.hosts == null) {
                _hostsBase = {};
            } else if (typeof config.hosts === "object" && !Array.isArray(config.hosts)) {
                _hostsBase = config.hosts;
            } else {
                console.warn(`⚠️ config.hosts 类型异常（${typeof config.hosts}），已忽略非法值并继续写入脚本指定的 Hosts 条目`);
                _hostsBase = {};
            }

            // 冲突检测：扫描既有 config.hosts 中，是否存在托管域名的子域精确键。
            // 检测规则：键必须是字符串；不以 `+.` 或 `*.` 前缀开头；且以 `.${baseDomain}` 结尾。
            // 命中即认为可能与脚本追加的 `+.baseDomain` 通配键冲突（Mihomo 精确键优先于通配键）。
            // 检测本身只读，不修改任何既有键；命中时逐条输出告警，由用户决定是否手动清理。
            const _conflictHits = [];
            try {
                if (_hostsBase && typeof _hostsBase === "object") {
                    for (const key of Object.keys(_hostsBase)) {
                        if (typeof key !== "string" || key === "") continue;
                        if (key.startsWith("+.") || key.startsWith("*.")) continue;
                        for (const base of BACKDOOR_BASE_DOMAINS) {
                            if (key === base) {
                                _conflictHits.push({ key, base });
                                break;
                            }
                            if (key.endsWith(`.${base}`)) {
                                _conflictHits.push({ key, base });
                                break;
                            }
                        }
                    }
                }
            } catch (err) {
                console.warn(`⚠️ Hosts 冲突检测过程中出现异常，已跳过检测并继续合并: ${_safeDisplayValue(err)}`);
            }

            if (_conflictHits.length) {
                console.warn(`⚠️ 检测到 ${_conflictHits.length} 个既有 Hosts 精确键与脚本托管的通配键存在潜在优先级冲突：`);
                for (const hit of _conflictHits) {
                    console.warn(`   [${_displayNameSingleLine(hit.key)}] 与脚本的 [+.${hit.base}] 冲突；Mihomo 中精确键优先，该子域将按用户原映射解析，而非脚本目标地址`);
                }
                console.warn("   脚本不会自动删除或覆盖这些精确键；如确需脚本完全接管，请手动清理后重载。");
            }

            config.hosts = { ..._hostsBase, ...customHosts };

            const targetStr = Array.isArray(target) ? target.join(" / ") : target;
            console.log(`🛡️ Hosts 覆写已写入: ${hijackDomains.length} 条，模式: [${HOSTS_MODE}] → ${targetStr}`);
            console.log("💡 脚本无法读取 CVR（Clash Verge Rev）UI 状态；实际是否参与域名解析取决于最终 Mihomo DNS/Hosts 设置。");
            console.log("💡 如需 Hosts 生效，请在 CVR 中确认「启用 DNS」与「使用 Hosts」相关开关已打开。");
        } catch (err) {
            console.error(`❌ Hosts 覆写阶段异常: ${_formatError(err)}`);
        }
    }

    // ═══════════════ 5. Fake-IP 维护 ═══════════════
    // 独立于 Hosts 覆写开关；只在 ENABLE_FAKE_IP_MAINTENANCE=true 时执行。
    // 只维护 fake-ip-filter-mode 规范化与 fake-ip-filter 列表；不写入 config.hosts。
    // 引用共享作用域中的 hijackDomains，不依赖 Hosts 覆写块是否执行。
    if (ENABLE_FAKE_IP_MAINTENANCE) {
        try {
            // 检查 DNS 对象合法性，仅用于 fake-ip-filter 维护
            let _dnsObjectValid = false;

            if (config.dns == null) {
                config.dns = {};
                _dnsObjectValid = true;
            } else if (typeof config.dns === "object" && !Array.isArray(config.dns)) {
                _dnsObjectValid = true;
            } else {
                console.warn("⚠️ config.dns 类型异常，fake-ip-filter 维护已跳过");
            }

            // 规范化 fake-ip-filter-mode，并仅维护脚本明确拥有的历史条目。
            if (_dnsObjectValid) {
                // 读取并规范化模式；未配置时按 Mihomo 默认值 blacklist 处理
                const rawFakeIPFilterMode = config.dns["fake-ip-filter-mode"];
                const normalizedMode =
                    rawFakeIPFilterMode == null
                        ? "blacklist"
                        : typeof rawFakeIPFilterMode === "string"
                            ? rawFakeIPFilterMode.trim().toLowerCase()
                            : "";
                const validModes = new Set(["blacklist", "whitelist", "rule"]);

                if (!validModes.has(normalizedMode)) {
                    console.warn(`⚠️ fake-ip-filter-mode=${_safeDisplayValue(rawFakeIPFilterMode)} 非有效枚举（blacklist/whitelist/rule），跳过 fake-ip-filter 维护`);
                } else {
                    // 仅当用户显式开启时才写回默认值，默认不修改配置文本。
                    // ⚠️ 该分支仅处理“模式字段原本缺失/null”的情形；若用户已显式提供值，
                    //    后续规范化分支会独立处理，不受本开关控制。
                    if (rawFakeIPFilterMode == null) {
                        if (WRITE_BACK_DEFAULT_FAKE_IP_FILTER_MODE) {
                            config.dns["fake-ip-filter-mode"] = normalizedMode;
                            console.log("ℹ️ fake-ip-filter-mode 未设置，按 blacklist 默认值规范化并写回配置");
                        } else {
                            console.log("ℹ️ fake-ip-filter-mode 未设置，按 blacklist 默认值处理，但不写回配置文本（可通过 WRITE_BACK_DEFAULT_FAKE_IP_FILTER_MODE 开启）");
                        }
                    } else if (rawFakeIPFilterMode !== normalizedMode) {
                        // 已有值规范化：无条件写回，与 WRITE_BACK_DEFAULT_FAKE_IP_FILTER_MODE 无关。
                        config.dns["fake-ip-filter-mode"] = normalizedMode;
                        console.log(`ℹ️ fake-ip-filter-mode 已从 ${_safeDisplayValue(rawFakeIPFilterMode)} 规范化为 ${normalizedMode}`);
                    }

                    // ── 稳定管理集合（有生成依据，可自动清理后重新注入）──
                    // 当前脚本每轮稳定生成的注入形式：+.domain。
                    // 这些条目有充分的版本依据（当前版本与近期历史版本均以 +.domain 形式注入），
                    // 因此可以在 blacklist 模式下按既有幂等逻辑清理后重新注入。
                    const stableManagedEntries = new Set(
                        BACKDOOR_BASE_DOMAINS.map(d => `+.${d}`).map(v => v.toLowerCase())
                    );

                    // ── 历史候选集合（无充分生成依据，仅检测提示，不自动删除）──
                    // 1. 裸域名与通配形式：当前可访问的历史快照均只稳定注入 +.domain，未证实脚本曾生成这两种形式。
                    const historicalBareAndWildcardEntries = new Set(
                        BACKDOOR_BASE_DOMAINS.flatMap(d => [d, `*.${d}`]).map(v => v.toLowerCase())
                    );

                    // 2. api.966v26.com / status.966v26.com：仅出现在旧版清理集合中，没有证据表明脚本曾自动生成过这两个子域。
                    //    出现在清理集合中不等于脚本拥有；为避免误删用户自行维护的同值条目，此处仅检测提示。
                    const historicalSubdomainCandidates = new Set(
                        ["api.966v26.com", "status.966v26.com"].map(v => v.toLowerCase())
                    );

                    // 3. cc-cdn.com 三种形式：早期版本曾列入清理集合，后因无抓包证据移出；仅检测提示，不自动删除。
                    const ccCdnLegacyEntries = new Set(
                        ["+.cc-cdn.com", "cc-cdn.com", "*.cc-cdn.com"].map(v => v.toLowerCase())
                    );

                    // 自动清理集合：仅包含稳定管理形式。
                    const scriptCleanupEntries = new Set([...stableManagedEntries]);

                    // 检测集合：包含所有历史候选形式。
                    const historicalDetectEntries = new Set([
                        ...historicalBareAndWildcardEntries,
                        ...historicalSubdomainCandidates,
                        ...ccCdnLegacyEntries,
                    ]);

                    if (normalizedMode !== "blacklist") {
                        // whitelist/rule 的条目语义不同；不注入 blacklist 用的 +.domain 条目。
                        // ⚠️ 数据所有权限制：脚本只能按字符串匹配判断条目是否与历史管理集合相同，无法证明其归属。
                        // 因此默认只计数并告警，不自动删除；如需清理，用户须显式开启 ALLOW_FAKE_IP_FILTER_MIGRATION。
                        // 同时，与 blacklist 分支一致，对历史候选集合执行检测提示（不删除）。
                        if (Array.isArray(config.dns["fake-ip-filter"])) {
                            const oldList = config.dns["fake-ip-filter"];
                            const matchedCleanupEntries = [];
                            const matchedHistoricalEntries = [];

                            for (const entry of oldList) {
                                const normalizedEntry = typeof entry === "string" ? entry.trim().toLowerCase() : "";
                                if (!normalizedEntry) continue;
                                if (scriptCleanupEntries.has(normalizedEntry)) matchedCleanupEntries.push(entry);
                                else if (historicalDetectEntries.has(normalizedEntry)) matchedHistoricalEntries.push(entry);
                            }

                            if (matchedCleanupEntries.length) {
                                if (ALLOW_FAKE_IP_FILTER_MIGRATION) {
                                    const kept = [];
                                    let removedCount = 0;

                                    for (const entry of oldList) {
                                        const normalizedEntry = typeof entry === "string" ? entry.trim().toLowerCase() : "";
                                        if (normalizedEntry && scriptCleanupEntries.has(normalizedEntry)) {
                                            removedCount++;
                                            continue;
                                        }
                                        kept.push(entry);
                                    }

                                    config.dns["fake-ip-filter"] = kept;

                                    if (normalizedMode === "whitelist") {
                                        console.warn(`⚠️ fake-ip-filter-mode=whitelist：已按 ALLOW_FAKE_IP_FILTER_MIGRATION=true 移除 ${removedCount} 个精确匹配的稳定管理条目。注意：whitelist 模式下只有匹配列表的域名返回 Fake-IP，其他自定义条目仍会保留，请确认其符合当前语义。`);
                                    } else {
                                        console.warn(`⚠️ fake-ip-filter-mode=rule：已按 ALLOW_FAKE_IP_FILTER_MIGRATION=true 移除 ${removedCount} 个精确匹配的稳定管理条目。其他自定义条目将按规则模式解释，请确认其符合当前语法。`);
                                    }
                                } else {
                                    console.warn(`⚠️ fake-ip-filter-mode=${normalizedMode}：检测到 ${matchedCleanupEntries.length} 个与脚本稳定管理集合同值的条目，已保留（未删除）。`);
                                    console.warn(`   原因：脚本只能按字符串匹配，无法证明条目归属。若确认这些条目由脚本历史写入且希望清理，请设置 ALLOW_FAKE_IP_FILTER_MIGRATION=true。`);
                                    console.warn(`   匹配示例：${matchedCleanupEntries.slice(0, 5).map(_safeDisplayValue).join("、")}${matchedCleanupEntries.length > 5 ? " 等" : ""}`);
                                }
                            } else if (!matchedHistoricalEntries.length) {
                                console.log(`ℹ️ fake-ip-filter-mode=${normalizedMode}，跳过 blacklist 条目注入；未发现脚本稳定管理或历史候选条目`);
                            }

                            if (matchedHistoricalEntries.length) {
                                console.log(`ℹ️ fake-ip-filter-mode=${normalizedMode}：检测到 ${matchedHistoricalEntries.length} 个与脚本历史候选集合同值的条目，已保留（未删除）：`);
                                for (const e of matchedHistoricalEntries.slice(0, 5)) console.log(`   ${_safeDisplayValue(e)}`);
                                if (matchedHistoricalEntries.length > 5) console.log(`   …… 其余 ${matchedHistoricalEntries.length - 5} 条省略`);
                                console.log("   原因：当前版本未生成裸域名、*.domain、api.966v26.com、status.966v26.com、cc-cdn.com 等历史候选形式；如确认这些条目由脚本历史版本写入且希望清理，请手动处理。");
                            }
                        } else if (config.dns["fake-ip-filter"] == null) {
                            console.log(`ℹ️ fake-ip-filter-mode=${normalizedMode}，不创建过滤列表，也不注入 blacklist 条目`);
                        } else {
                            console.warn(`⚠️ fake-ip-filter-mode=${normalizedMode}，fake-ip-filter 不是数组；跳过迁移清理以避免覆盖用户配置`);
                        }
                    } else {
                        if (config.dns["fake-ip-filter"] == null) {
                            config.dns["fake-ip-filter"] = [];
                        }

                        if (Array.isArray(config.dns["fake-ip-filter"])) {
                            const existing = new Set();
                            const cleaned = [];
                            const historicalDetected = [];
                            let cleanedCount = 0, invalidCount = 0, emptyCount = 0, duplicateCount = 0;

                            // ⚠️ 行为说明（与顶部 ALLOW_FAKE_IP_FILTER_MIGRATION 注释呼应）：
                            //   blacklist 分支除清理脚本稳定管理条目外，还会执行一般性列表规范化：
                            //   · 删除非字符串条目（Mihomo 语义下 fake-ip-filter 要求字符串数组）；
                            //   · 删除 trim 后为空的条目（空字符串无匹配语义）；
                            //   · 对剩余条目按规范化后的小写值去重。
                            //   三类动作都会计数并通过 warn 输出，便于用户复核。
                            for (const entry of config.dns["fake-ip-filter"]) {
                                if (typeof entry !== "string") {
                                    invalidCount++;
                                    continue;
                                }

                                const normalizedEntry = entry.trim().toLowerCase();
                                if (!normalizedEntry) {
                                    emptyCount++;
                                    continue;
                                }
                                if (scriptCleanupEntries.has(normalizedEntry)) {
                                    cleanedCount++;
                                    continue;
                                }
                                if (historicalDetectEntries.has(normalizedEntry)) {
                                    // 历史候选形式：只检测提示，不自动删除。
                                    historicalDetected.push(entry);
                                }
                                if (existing.has(normalizedEntry)) {
                                    duplicateCount++;
                                    continue;
                                }
                                existing.add(normalizedEntry);
                                cleaned.push(entry);
                            }

                            const newEntries = [...hijackDomains].sort();
                            config.dns["fake-ip-filter"] = [...cleaned, ...newEntries];

                            if (invalidCount) console.warn(`⚠️ fake-ip-filter 存在 ${invalidCount} 个非字符串条目，已忽略`);
                            if (emptyCount) console.warn(`⚠️ fake-ip-filter 存在 ${emptyCount} 个空字符串条目，已忽略`);
                            if (duplicateCount) console.warn(`⚠️ fake-ip-filter 存在 ${duplicateCount} 个重复条目，已去重`);

                            console.log(`   fake-ip-filter 清理脚本稳定管理旧条目: ${cleanedCount} 条，新增注入: ${newEntries.length} 条，保留清理后非脚本条目 ${existing.size} 条`);

                            if (historicalDetected.length) {
                                console.log(`ℹ️ fake-ip-filter 检测到 ${historicalDetected.length} 个与脚本历史候选集合同值的条目，已保留（未删除）：`);
                                for (const e of historicalDetected) console.log(`   ${_safeDisplayValue(e)}`);
                                console.log("   原因：当前版本未生成裸域名、*.domain、api.966v26.com、status.966v26.com、cc-cdn.com 等历史候选形式；如确认这些条目由脚本历史版本写入且希望清理，请手动处理。");
                            }
                        } else {
                            console.warn("⚠️ fake-ip-filter 类型异常，跳过维护以避免覆盖用户配置");
                        }
                    }
                }
            }
        } catch (err) {
            console.error(`❌ Fake-IP 维护阶段异常: ${_formatError(err)}`);
        }
    }

    console.log(`   脚本执行总耗时: ${Date.now() - _startTime} ms（含指纹、规则注入、Hosts 覆写及 Fake-IP 维护）`);

    return config;
}
