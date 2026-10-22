# 公开更新研究与本地分析对照

核对日期：2026-10-22。分析固件之外，同时核对公开项目的实际支持范围、
可读源码与维护者记录。下述链接提供出处，不代表本项目复现过其相机安装。
三个 WonderLantern 项目属于同一组织，不能计作三份相互独立的证明。

## 可核对的公开资料

| 来源 | 确认可见的内容 | 对 Z7 II 的限制 |
| --- | --- | --- |
| [摘要工具说明](https://github.com/WonderLantern/nikon-fw-key-tool/blob/33426e892afd329a3b366b73776bcf53b9ac4ee8/README.md) | 解码支持列表包含 Z6 II/Z7 II；摘要求解与重建支持列表仅为 Z8/Z9 | 解码支持不等于整包摘要支持 |
| [求解器源码](https://github.com/WonderLantern/nikon-fw-key-tool/blob/33426e892afd329a3b366b73776bcf53b9ac4ee8/solve_signature_e7.py) | `require_expeed7` 只接受型号标识 2070/1990；注释指出 E6 的 seed 由指令立即数构造；变换使用累加序列 | 没有提供 Z7 II 的 seed 构造函数、候选库或最终摘要验证结果；这是一条待验证的来源线索 |
| [Z30 项目记录](https://github.com/WonderLantern/wonder-lantern-z30/blob/8f662f8733531958e2c3947119914c4adc050a18/README.md) | 维护者记录 C 1.20 独立 EG 的相机安装，明确没有重建完整更新包 | 只支持该机型与版本 |
| [Z6 项目记录](https://github.com/WonderLantern/WonderLantern-z6/blob/7cac53a546c6645d499465875e0178a7ec44ebe5/README.md) | C 3.80 的安装说明使用 EG 成员与配套卡载文件 | 不是 Z6 II，更不是 Z7 II 的安装证明 |
| [另一作者的 Z8 项目](https://github.com/XinmiaoZhao/NikonFirmwarePatch) | 公开支持输入为 Z8 C 3.11，提供独立验证入口 | 没有声明支持 Z7 II，不能借用其兼容性结论 |
| [尼康 Z7 II 更新说明](https://downloadcenter-origin.nikonimglib.com/en/download/fw/561.html) | 提供原厂 C 1.70 更新及更新记录 | 不描述 K8 或独立 EG 的接受条件 |
| [尼康 Z7 II 产品规格](https://imaging.nikon.com/imaging/lineup/mirrorless/z_7_2/index.html) | 确认双 EXPEED 6 | 双引擎不能单独证明包校验策略或 seed 共享关系 |

## 对当前结论的修正

1. 从 `0x10000088` 读取 B8，只证明校验时的取值位置。没有独立的引导区
   目录成员，不等于该材料无法由分发代码中的立即数构造。代码注释不再
   断言这 8 字节必定不在更新文件中。
2. 外层三表 XOR、摘要变换用的两张表、种子值 `0x44B`、引导材料 B8、
   最终摘要附加字节 K8，以及用于验证的 seed 候选集合是不同概念。共享其中
   一项不能直接推出其他项相同；同 seed 也可能因机型串不同派生出不同 K8。
3. 已恢复的累加变换与公开源码一致。公开 E7 求解器对 E6 的拒绝只表示
   该脚本不支持，不能作为 E6 材料不可恢复的证明。
4. 实验控制台接受裸 master，只证明主机侧实验存储的行为。优先保留
   Z7 II 原厂整包校验路径的约束，不把 Z30/Z6 的安装记录外推到双引擎机型。

## 后续验证顺序

先核对 Z6 II/Z7 II 的更新扫描与分类条件，确定独立 EG 是否能到达实际
安装分支；同时追踪 B8 的初始化来源，检查常量构造而不只搜索连续的
8 字节窗口。若取得定义明确的 seed 候选库，再把候选代入已恢复算法，
以全部本地原厂包的头部摘要作为判据；用于筛选的版本和留出的验证版本
分别记录。候选通过摘要只证明摘要关系，不代表已经通过相机安装验证。

本次只补充公开资料与证据边界，没有导入第三方代码、固件或密钥，也没有
编译、生成更新文件或连接相机。现有样本与算法记录见
[固件更新路径](firmware_update.md)和[三版本对照](update_versions.json)。

## 本地样本跟进

Z6 II C 1.70 与 Z7 II C 1.70 的[双机型对照](z6ii_update_comparison.md)表明：
三张解码表、两张摘要变换表及累加循环一致，但种子参数、机型串及派生的
S8 不同。两份原始目录例程都接受整包、拒绝原厂裸 master/slave。
该结果限于局部执行；最终 K8 与 seed 候选集合的跨机型适用性仍未确认。
