# 管理界面设计 Token 规范

管理界面（`internal/web/frontend`）只使用本文定义的 token。唯一来源是 `src/index.css` 的 `@theme`；TS 图表代码通过 `src/lib/tokens.ts` 的 `colorVar()` 引用同名 CSS 变量，不写字面色值。亮色与暗色两套主题共用同一组 token（见“主题”一节）。

`@theme` 中重置了 Tailwind 默认的颜色、字号、字重、圆角和阴影命名空间（`--color-*: initial` 等），因此 `bg-slate-50`、`text-xs`、`shadow-md` 这类原始类名不会生成样式；`src/design-tokens.test.ts` 会扫描源码，发现原始调色板类、任意 `text-[Npx]` 或十六进制色值即失败。新增 token 时同步更新 `src/lib/utils.ts` 中 tailwind-merge 的 theme 注册。

## 主题

界面有亮色和暗色两套主题，默认跟随系统设置，也可以在顶栏（和登录页右上角）的“主题”三选一里固定为亮色或暗色。

- **实现**：两套主题取值不同的 token 写成 `light-dark(<亮色值>, <暗色值>)`，取哪一侧由 `:root` 的 `color-scheme` 决定：默认 `light dark`（跟随系统），`<html data-theme="light">` 固定亮色，`data-theme="dark"` 固定暗色。`color-scheme` 同时让原生控件和滚动条跟着换。生产构建时样式优化器会把 `light-dark()` 改写成等价的变量写法以兼容旧浏览器。
- **记忆**：固定的主题存在浏览器的 `localStorage`（键 `llmapi-logger:theme`），“自动”时删除该键。`index.html` 里的内联脚本在首次绘制前按它设置 `data-theme`，避免闪烁。这里只存主题，不存任何凭据（凭据规则见 [09](../features/09-security-encryption-and-redaction.md)）。
- **哪些随主题变**：背景、表面、边框、文字、链接、状态色、图表框架和热力图。品牌主色阶、中性色阶和构成类别色两套主题相同：类别色在暗色表面上的对比度也都 ≥3:1，其上的白字保持可读。
- **写组件时**：只用语义 token，不要直接用 `neutral-*` / `primary-*` 色阶表达“表面”“文字”“选中”这些角色，否则暗色下不会跟着变。色阶只用于两套主题里本来就该一样的地方（灯箱等固定深色的浮层、品牌强调边框）。
- **暗色取值的对比度**（WCAG）：正文对表面 13.5:1，次要文字 8.1:1，辅助文字 5.8:1；状态文字对各自底色 8.5–9.3:1；主按钮白字 5.4:1，危险按钮白字 4.8:1。

## 颜色

### 品牌主色（钢蓝，低饱和）

| Token | 值 | 用途 |
|---|---|---|
| `primary-50` | `#f0f5fa` | —（选中行用 `selected`，info 背景用 `info-bg`） |
| `primary-100` | `#e3edf6` | 选中项悬停 |
| `primary-200` | `#c3d5e8` | — |
| `primary-300` | `#98b7d6` | — |
| `primary-400` | `#6893bf` | 项目序列色、悬停强调边框 |
| `primary-500` | `#4a7aab` | 焦点环 `ring`、单序列图表色 |
| `primary-600` = `primary` | `#3b6e9e` | 主操作按钮、链接（白字 5.37:1，AA） |
| `primary-700` = `primary-hover` | `#2c5378` | 主按钮悬停、info 文字（白字 8.03:1） |
| `primary-800` | `#1d3b57` | — |
| `primary-900` | `#13283c` | — |

### 中性与语义角色

中性色阶为 slate：`neutral-50 … 950`（`#f8fafc` … `#0b1420`），两套主题相同。组件使用下列语义 token，中性色阶只用于灯箱等固定深色的少量场景。

| Token | 亮色 | 暗色 | 用途 | 亮色对比度 |
|---|---|---|---|---|
| `background` | `#f4f6f9` | `#0c1117` | 页面底色 | — |
| `surface` | `#ffffff` | `#151c26` | 卡片、控件、浮层 | — |
| `surface-muted` | `#f8fafc` | `#111821` | 卡片内嵌区块、表头、折叠面板、悬停 | — |
| `surface-sunken` | `#f1f5f9` | `#0e141b` | 分段控件轨道、次级按钮、骨架屏、进度轨道、矩阵热力图 0 级 | — |
| `surface-sunken-hover` | `#e2e8f0` | `#1d2733` | 次级按钮悬停 | — |
| `selected` | `#f0f5fa` | `#182a3f` | 列表选中行 | — |
| `border` | `#e2e8f0` | `#253040` | 默认边框/分隔线（全局默认） | — |
| `border-strong` | `#cbd5e1` | `#3a4960` | 输入框、outline 按钮、强调分隔 | — |
| `foreground` | `#1e293b` | `#dde5ee` | 正文、标题 | 14.6:1 |
| `muted` | `#475569` | `#a7b3c2` | 次要文字、描述 | 7.6:1 |
| `subtle` | `#5d6c80` | `#8a97a9` | 辅助/元信息、占位符、坐标轴 | 5.35:1（底色上 4.95） |
| `ring` | `#4a7aab` | `#6893bf` | 焦点环 | — |
| `link` / `link-hover` | `#3b6e9e` / `#2c5378` | `#7fa9d4` / `#a9c6e3` | 正文里的链接 | 5.37:1 |
| `code` / `code-foreground` | `#172331` / `neutral-200` | `#0a0f15` / `neutral-200` | 深色代码/原始报文块 | 12.9:1 |
| `scrim` | `neutral-950` | 同左 | 图片灯箱遮罩（`/90`） | — |

暗色下表面的层次是：`background` 最深，`surface-sunken`、`surface-muted` 居中，`surface` 最亮；与亮色一样，“下沉”和“柔和”表面都比 `surface` 更靠近页面底色。

### 状态色（solid / bg / border / fg）

亮色：

| 状态 | solid | bg | border | fg | fg 对 bg |
|---|---|---|---|---|---|
| success | `#2f7d57` | `#edf6f1` | `#c3e0cf` | `#1f5e40` | 6.97:1 |
| warning | `#b07514` | `#fbf5e8` | `#ecd6a8` | `#7a4f0c` | 6.55:1 |
| danger | `#b23b3b`（hover `#9a3030`） | `#fbeeee` | `#efc8c8` | `#8f2b2b` | 7.29:1 |
| info | `#3b6e9e` | `#f0f5fa` | `#c3d5e8` | `#2c5378` | 7.32:1 |

暗色（底色是带色相的深色，文字是同色相的浅色）：

| 状态 | solid | bg | border | fg | fg 对 bg |
|---|---|---|---|---|---|
| success | `#3a9a6c` | `#12261d` | `#1f4a35` | `#8fd3ae` | 9.16:1 |
| warning | `#c08a25` | `#2a2110` | `#574414` | `#e6c170` | 9.24:1 |
| danger | `#c24a4a`（hover `#ab3d3d`） | `#2b1617` | `#5a2a2c` | `#f0a3a3` | 8.52:1 |
| info | `#4a7aab` | `#13202e` | `#27425e` | `#a9c6e3` | 9.32:1 |

类名形如 `bg-success-bg border-success-border text-success-fg`；solid 用于圆点、图表标记和危险按钮（白字亮色 5.86:1、暗色 4.80:1）。状态映射：

| 场景 | 状态 |
|---|---|
| completed / complete / ok、verified、启用、时间线完整、精确/回链关联 | success |
| partial / interrupted / client_cancelled、截断、推断关联、占用 ≥70% | warning |
| rejected / failed / error / proxy_error / newapi_error、校验失败、占用 ≥90% | danger |
| pending / processing / in_progress、会话筛选提示、说明性提示 | info |
| 其他（标签、计数、协议、客户端） | neutral / outline |

### 构成类别色（洞察图表）

8 个类别在 Treemap、DNA 条带、堆叠柱、构成条、图例和对话角色上使用同一映射，顺序固定。已用 dataviz 校验脚本验证：明度带、色度 ≥0.10、相邻 CVD ΔE ≥8、正常视觉 ΔE ≥15、对白底 ≥3:1。两套主题用同一组取值：对暗色表面 `#151c26` 的对比度为 3.0–5.3:1，色块上的白字不受主题影响。

| 类别 | Token | 值 | 标签 |
|---|---|---|---|
| system | `cat-system` | `#2f6aa3` | 系统提示 |
| tools | `cat-tools` | `#d0743c` | 工具定义 |
| user | `cat-user` | `#2a9c78` | 用户 |
| injected | `cat-injected` | `#b8861f` | 注入上下文 |
| assistant | `cat-assistant` | `#7466c0` | 助手 |
| reasoning | `cat-reasoning` | `#c7608c` | 推理 |
| tool_result | `cat-tool-result` | `#5f9a3a` | 工具结果 |
| media | `cat-media` | `#a0522d` | 多媒体 |
| 未知 | `cat-unknown` | 亮色 `#94a3b8`、暗色 `#64748b` | — |

对话角色复用类别色：system/developer → `cat-system`，user → `cat-user`，assistant → `cat-assistant`，tool → `cat-tool-result`。上下文事件标记：模型切换 `primary`、压缩 `danger`、清理 `warning`、系统提示/工具集/注入变化分别用对应类别色。热力图 0–4 级：0 级是 `chart-track`（活跃热力图）或 `surface-sunken`（人 × 项目矩阵），1–4 级是 `heat-1 … heat-4`：亮色 `#c3d5e8`、`#6893bf`、`#3b6e9e`、`#1d3b57`（由浅到深），暗色 `#27496c`、`#356e9f`、`#6a9ccb`、`#b6d2ec`（由深到浅），两套主题里都是数值越大离表面越远。Agent 树谱系线按黄金角取色，固定 `hsl(h 34% 48%)` 低饱和。

图表框架：`chart-grid`（网格，亮色 `#e2e8f0`、暗色 `#232e3c`）、`chart-axis`（坐标轴文字 = `subtle`）、`chart-cursor`（悬停底）、`chart-track`（构成条空轨道，亮色 `#e2e8f0`、暗色 `#202a38`）。recharts 自带的提示框默认是白底黑字，使用时必须加 `chartTooltip`（`src/lib/tokens.ts`）换成表面、边框和正文的 token。

## 字体

系统字体栈（`--font-sans` 沿用 v3 栈，不引入 Web 字体）；ID、哈希、正则、Header、代码使用 `font-mono`。

| Token | 字号/行高 | 用途 |
|---|---|---|
| `text-caption` | 11/16 | 时间戳、元信息、图表刻度、提示脚注 |
| `text-label` | 12/16 | 表单标签、徽标、表头、键值标签、紧凑表格 |
| `text-body-sm` | 13/20 | 卡片描述、表格正文、列表值 |
| `text-body` | 14/20 | 默认正文、按钮、输入框、对话正文 |
| `text-title` | 16/24 | 卡片/面板标题、页面内二级标题 |
| `text-heading` | 20/28 | 页面标题、KPI 数值 |
| `text-display` | 24/32 | 登录页品牌标题 |
| `text-code` | 12/20 | 代码块、原始报文（仅等宽） |

字重仅三档：`font-normal` 400、`font-medium` 500（标签、强调值、按钮）、`font-semibold` 600（标题）。行高随字号 token 成对给出，不再单独写 `leading-*`。

## 间距

4px 基准（Tailwind 数值刻度 `1` = 4px）。语义 token：

| Token | 值 | 规则 |
|---|---|---|
| `gutter` | 16 / 24（≥640）/ 32（≥1024） | 页头与主体左右内边距 `px-gutter` |
| `section` | 16 | 页面区块之间、卡片之间、卡片网格 `space-y-section` / `gap-section` |
| `card` | 16 | 卡片内边距 `p-card`；无头卡片 `CardContent` 加 `pt-card`（登录卡例外：24，`p-6`） |
| `stack` | 12 | 卡片头与内容、卡片内区块之间 `space-y-stack` |
| `header` | 56 | 顶栏最小高度，粘性列表据此计算 `top` |

控件：高度 sm 32（`h-8`）/ 默认 36（`h-9`）/ lg 40（`h-10`），水平内边距 12（`px-3`，默认按钮 16）。紧凑行/列表项 `px-3 py-2`，表格单元 `px-3 py-2`。行内图标与文字间距 6–8（`gap-1.5`/`gap-2`）。

## 圆角与阴影

| Token | 值 | 用途 |
|---|---|---|
| `rounded-xs` | 2 | 色块图例、数据标记、行内代码 |
| `rounded-sm` | 6 | 徽标、小块 |
| `rounded-md` | 8 | 按钮、输入框、内嵌面板、代码块、浮层提示 |
| `rounded-lg` | 12 | 卡片 |
| `rounded-full` | — | 胶囊筛选芯片、圆点、圆形按钮 |
| `shadow-xs` | 1px | 控件、分段选中项 |
| `shadow-card` | 双层 1–3px | 卡片 |
| `shadow-overlay` | 2–24px | 图表 tooltip、灯箱按钮等浮层 |

`rounded-xl` 与 `shadow-lg` 仅为保持品牌标识（`BrandMark`）原样保留，组件不得使用。

## 布局

| 项 | 规则 |
|---|---|
| 页面最大宽度 | `max-w-page`（1920px），水平居中 |
| 顶栏 | `min-h-header`（56），`bg-surface` + 底边框，粘性 |
| 页面纵向内边距 | `py-section` |
| 审计双栏 | `xl:grid-cols-[minmax(320px,25rem)_minmax(0,1fr)]`，`gap-section` |
| KPI 网格 | `grid-cols-2 md:grid-cols-4 xl:grid-cols-7`，`gap-3` |
| 卡片网格 | `md:grid-cols-2 2xl:grid-cols-3`，`gap-section` |
| 页头 | `PageHeader`：标题（`page` 级 `text-heading`，`panel` 级 `text-title`）+ 副标题（`text-body-sm text-muted`）+ 右侧操作；可选返回按钮。用于审计列表、规则页、洞察概览、会话趋势、Agent 树、审计详情 |

## 组件约定

- `Button`：`primary` / `secondary` / `outline` / `ghost` / `danger`；尺寸 `sm` / `default` / `lg` / `icon`。
- `ThemeSwitch`：主题三选一（自动 / 亮色 / 暗色），复用分段控件，放在顶栏导航之后和登录页右上角。
- `Badge`：`neutral` / `outline` / `info` / `success` / `warning` / `danger`，`text-label font-medium rounded-sm`。
- `Alert`：`neutral` / `info` / `success` / `warning` / `danger`，颜色只来自状态 token，调用方不再覆盖边框和文字色。
- `Card`：`rounded-lg border bg-surface shadow-card`；`CardTitle` 为 `text-title font-semibold`。
- `Input` / `Select`：`h-9 rounded-md border-border-strong bg-surface shadow-xs`，焦点 `ring-2 ring-ring/40` + `border-ring`。
- 表格：表头 `bg-surface-muted text-label font-medium text-muted`，单元格 `px-3 py-2`。
- 代码块：`codeBlockClassName`（`bg-code text-code-foreground text-code font-mono rounded-md p-3`）。
- 分段控件：轨道 `bg-surface-sunken rounded-md p-0.5`，选中项 `bg-surface shadow-xs text-foreground`。
