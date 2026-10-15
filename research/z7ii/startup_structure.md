# Z7 II C 1.70 启动与初始化结构

本记录基于原始 master/slave 固件分析及独立执行实验。以下函数位置为成员文件偏移；
表中的源、目的、向量和栈为固件使用的软件地址，不直接代表物理 DRAM。

两份 EG 都以 ARM 分支进入启动代码，代码地址按 `0x10020000 + 文件偏移` 使用。
固件包含小端 ARM 与 Thumb 指令。分析时必须正确区分端序、指令状态及数据区；
错误解码得到的函数数量或缺失引用不能作为功能有无的证据。

| 项目 | master | slave |
| --- | --- | --- |
| 启动入口偏移 | `0xBC88` | `0xBCD4` |
| TTBR 软件地址 | `0x10030000` | `0x10030000` |
| 初始域访问值 | `0x55555555` | `0x55555555` |
| 向量地址 | `0x10100000` | `0x10034100` |
| UND 栈顶（core 0） | `0xB2BB0000` | `0xC1920000` |
| ABT 栈顶 | `0xB2BA8000` | `0xC1918000` |
| FIQ 栈顶 | `0xB2BA0000` | `0xC1910000` |
| IRQ 栈顶 | `0xB2B98000` | `0xC1908000` |
| SYS 栈顶 | `0xB2B90000` | `0xC1900000` |
| SVC 栈顶 | `0xB2B88000` | `0xC18F8000` |

启动读取 MPIDR 低四位，各模式栈顶减去 `core_id << 14`。非零 core 进入
`WFE`/`DMB` 等待路径，检查 `0x04008FFC` 的 `0xBABEBABE`，随后清除标记。
这证明固件具备多核启动代码，尚未确定实际核数及任务绑定。

## 两条初始化路径

早期启动代码有三段内联 ARM 复制循环，master 入口为 `0xBE74`、`0xBED0`、
`0xBF2C`；slave 各后移 `0x4C`。长度分别为 master 的 `0xAEDB8`、`0x105C`、0，
slave 的 `0x17D60`、`0xAD4`、0。第三段零长度循环必须保持目的数据不变。
循环按四字节向上取整处理长度；本版本的非零长度均已对齐。

`0x14000` 是另外一张初始化记录表，每条 16 字节，四个小端整数为源、目的、
长度和处理函数。全零记录结束表。master 有 20 条，slave 有 15 条，均包含四条复制。
`0x1002006C` 指向 Thumb 复制处理函数，`0x10020088` 指向 Thumb 清零处理函数。
处理函数地址字段为偶数，执行它们时仍须使用正确的 Thumb 状态。

| 角色 | 源地址 | 目的地址 | 长度 |
| --- | --- | --- | --- |
| master | `0x12399F94` | `0xB1800000` | `0xAEDB8` |
| master | `0x12448D80` | `0xB2BB0000` | `0x105C` |
| master | `0x12449E00` | `0xB2BB1080` | `0x46BD4` |
| master | `0x12490A00` | `0xB5F00000` | `0x7178` |
| slave | `0x1085C4D4` | `0xC1000000` | `0x17D60` |
| slave | `0x10874240` | `0xC1920000` | `0xAD4` |
| slave | `0x10874D40` | `0xC1920B00` | `0x13FE8` |
| slave | `0x10888D40` | `0xC5000000` | `0x4000` |

每角色四条复制累计 master 1,039,200 字节、slave 198,684 字节。
早期内联循环中零长度的第三段，在表中具有非零长度；两条初始化路径不可混为一谈。
清零记录的源字段不是读取长度的依据，不能据其巨大区间分配文件缓冲或读取镜像尾部。

通信 RAM 的清零记录分别为 `0xB7CF0000` 和 `0xC60F0000`，长度同为 `0xC618`。
这与之前通信代码中的地址相互印证。当前主板只提供这两处的普通 RAM 窗口；
协议、消息通知、地址映射和跨实例传输未接入。其余大范围清零记录尚未执行。
现已补充[通信区头部初始化](communication_header.md)的局部执行检查，验证四项
字写入及未写入字段保留；这不验证完整通信初始化或传输协议。

## 实现与复现

`analyze/firmware_structure.py` 严格校验完整镜像的长度、SHA-256 和 CRC，提取启动
literal、初始化表和 28 字节任务记录。任务配置仍保留四个未命名整数，避免把首字段
直接解释为 CPU affinity。master 293 条、slave 97 条的分工见平台比较记录。

```sh
python analyze/firmware_structure.py --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --report .local/structures.json
python tools/structure_probe.py --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/structure-run
```

实验用独立 QEMU 实例运行两份原厂镜像。按原厂 section 属性构建实验页表，保留
独立的合成向量和控制入口。检查三条 ARM 内联循环、四条 Thumb 表复制及通信 RAM
清零样本；复制前污染目的缓冲，逐字节比对结果，并检查尾部保护值；清零样本检查
前后保护值。默认使用 `virt`；原地址主板用 `--backend nikon-z72-lab --qemu ...`，
工具按角色选择 `nikon-z72-lab` 或 `nikon-z72-slave-lab`。

这些实验验证选定初始化例程，未验证自然启动、完整表分发调用链、全部清零、RTOS
任务创建、外设驱动或双 EXPEED 协作。完整镜像预加载也不证明相机加载器接受其长度。

2026-10-10 验证：`virt` 和 QEMU 10.2.4 原地址主板均通过上述两个角色的实验；
两个主板的合成 ARM/RAM 检查及原有显示实验的四个场景也通过。
结构与执行证据见 [结构记录](../../artifacts/structure_validation/structures.json)、
[virt 执行](../../artifacts/structure_validation/virt.json) 和
[原地址执行](../../artifacts/structure_validation/native.json)。
