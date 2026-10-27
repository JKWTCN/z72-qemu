# Z72 QEMU

[浏览器交互台](docs/browser.md)支持实时画面、按住输入、键盘快捷键与重启。
使用 `tools/web_console.py` 指定三份固件后，打开 `http://127.0.0.1:8666` 即可操作。

[English](README.md) · [架构](docs/architecture.md) · [开发状态](docs/porting.md) · [固件](docs/firmware.md) · [测试](docs/testing.md) · [发布](docs/publication.md) · [研究索引](research/README.md)

Z72 QEMU 是面向 Nikon Z7 II C 1.70 固件分析的实验性 QEMU 环境，提供独立 ARM
主板模型、严格的固件输入校验，以及内存初始化、MMU 权限和显示状态判断的可复现实验。

当前实现支持两份原厂引擎映像与原厂控制器映像组合启动至各自调度器且无执行
异常：合成电池对端完成原厂串行认证后，五秒供电限制消除，拍摄应用持续渲染；
按菜单键后原厂固件执行菜单启动入口，前台切换为菜单应用并显示覆盖全屏的
结构化菜单。菜单内四个方向输入可移动高亮并切换标签页，确认位到达引擎，
播放输入把前台切到播放应用。分析固件定位了原厂菜单固件更新服务、卡上更新
文件命名规则与包完整性检查库；交互台据此实现菜单门控的固件更新——待安装
master 镜像由启动参数提供（本仓库不含制作或解码工具），安装要求菜单应用
为前台，经原子校验的更新存储落盘，重启后加载已安装镜像并可回退原厂。
存储卡、文件系统与闪存写入环节仍是主机侧实验代替。传感器采样事件阶段
也已建模：采样结果窗口与第三同步库成为寄存器合同，可选采样源每帧锁存
已恢复的采样就绪线——原厂读出会执行并回报采样状态，而能让捕获状态机
前进的有效采样线型尚未恢复。肩屏（顶部面板）链路已完整追溯：主引擎在
串行通道 8 持续发布 112 字节标签 4 快照，控制器通道处理器与面板服务把它
消费为实时状态块，页面函数组装 12 字节寄存器结构与影子寄存器，物理面板
为八位寄存器 I2C 器件（寄存器 26 读身份、0xD6 写页选）。寄存器式面板
器件模型覆盖线协议并提供观察属性，浏览器交互台实时呈现原厂面板状态；
菜单稳定周期的退出画面不再出现 "Turn camera off and then on again"
对话框：采样源合同（`sensor-sample` 加 `sample-counter`）并入交互台
与探针后，菜单退出的重启路径不再产出致命消息，见
[错误显示研究](research/z7ii/error_display.md)。
原生显示输出合同已建模并经原厂固件验证：状态写一清除、掩码路由到
中断 111/112，可选的按帧完成源让原厂处理器确认事件、通知计数增长、
工作缓冲在帧池中轮换；交互台在图形画面之外渲染最终 LCD 输出平面
（1024×682 亮度，当前为清屏帧），见
[显示输出研究](research/z7ii/display_output.md)。菜单关闭后的重开
（采集状态 `0x3f` 门控）、拍摄画面 `Card`/`Err` 计数背后的存储槽
状态、菜单文字语义、捕获管线的实时取景像素与部分通知的自然产出
仍未完成：`0x4219`→`0x041b` 通知链整体休眠，启动期的设备服务注册
之后提供方从未应答（设备对象保持空），见
[通知链研究](research/z7ii/notification_chain.md)。其余边界见
[菜单键研究](research/z7ii/controller_keys.md)、
[菜单固件更新](research/z7ii/firmware_update.md)、
[传感器采样事件](research/z7ii/sensor_frames.md)与
[电池对端](research/z7ii/battery_serial.md)。

后续实验电池串行对端已解除启动后的五秒供电限制。完整采样确认原厂
拍摄应用与图形表面持续约 11.50 个虚拟秒；内部模式 3 → 1 没有使
前台应用退出。当前画面仍有 `Err`，菜单交互和正常完整启动尚未验证，见
[界面持续运行观察](artifacts/shooting_persistence_validation/report.json)。

[菜单键传输](research/z7ii/controller_keys.md)已确认扩展器输入 9 对应
第二个开关字的位 15，并进入原厂应用动作 `0x1c`。带存储尾标的实验
资源头经原厂复制路径加载，可消除 `0x44`；外部同步事件可解除产生
`0x3e` 的初始化等待。两者组合后曾到达模式 4 且状态列表为空，但
继续运行又产生 `0x3f`。资源正文仍为零，不代表校准数据。

此前持续输入探针从首次就绪的前台起按住菜单输入，原厂固件直接执行菜单启动入口
`0x1044e3ae`，前台切换为菜单应用（索引 1），释放后保持，捕获的
720×480 画面为覆盖全屏的结构化菜单；菜单键探针可复现
（`--resource-header --sync-pulse --settle-seconds 0`，按住按键
至前台切换）。后续已验证 100 毫秒模拟时间的短按也能在释放后打开菜单，
浏览器不再要求长按。动作链分析还原了常规切换机制：类型 1 系统事件在
`0x1053c5a8` 合成动作 `0x50`，其处理入口 `0x1062248a` 写入前台
切换请求；过晚按键产生未被应用处理器 `0x10541bc0` 处理的原始
动作 `0x1c`。菜单项交互与文字语义尚未验证。

另外支持独立 slave 初始化实验：分析并验证两份 EG 的启动入口、栈、初始化表和
任务记录，分别执行原厂复制及清零例程。详细地址和验证边界见
[启动结构](research/z7ii/startup_structure.md)。

```powershell
python tools/structure_probe.py --master "C:\firmware\eg1840_mas_01700.bin" --slave "C:\firmware\eg1840_sla_01700.bin" --destination ".local\structure-run"
```

默认使用 `virt`；编译后的原地址后端用 `--backend nikon-z72-lab --qemu ...`。
master 和 slave 使用独立实例；通信区当前为普通 RAM。

原地址主板还支持从原厂 EG 入口连续执行启动前段，使用原厂页表，检查六个模式栈，
在首次外设写入前停止，并验证无效代码段会触发取指异常。复现方法见
[复位启动前段](research/z7ii/reset_prefix.md)。当前尚未进入 RTOS 或显示菜单。

后续[早期配置阶段](research/z7ii/early_configuration.md)增加四个配置字和临时栈，
从原厂入口连续执行两次配置延时，到达系统初始化 `0x394` 前。支持原厂、
配置位保留和无效栈异常三种场景；完整启动与菜单仍待实现。

[系统配置首批写入](research/z7ii/system_configuration.md)继续执行 `0x394`，
检查 58 次原厂配置写入、slave 两条选择路径和数据异常负对照。
目前停在首次状态轮询调用前，尚未进入 RTOS 或显示菜单。

后续[完成反馈阶段](research/z7ii/system_completion.md)加入实验性同步完成与应答，
执行七次原厂轮询及五阶段命令，使第一次系统配置调用返回，进入 master `0x5354`
或 slave 的下一初始化入口。禁止完成场景执行原厂完整超时上限；完整启动和菜单仍待实现。

本批[平台初始化](research/z7ii/platform_initialization.md)完成两个通道的四次配置调用，
验证 360 次写入、48 次原厂轮询和 6 次结果读取，从原厂复位入口连续到达 master
`0xBDC4` / slave `0xBE10`。单个命令不完成的负对照执行完整超时；RTOS 启动与菜单仍待实现。

本批[启动衔接](research/z7ii/boot_continuation.md)增加 24 个精确配置字，恢复原厂 SVC 栈，
从复位入口连续执行三段早期复制循环，到达内存初始化完成等待入口。
后续[启动内存阶段](research/z7ii/boot_memory.md)实现实验性有界清零和完成／错误状态，
使原厂复位连续到达 master `0x416C60` / slave `0x1474A8`，通过整个清零范围、
两侧保护字及致命错误自循环检查。

本批[运行时启动](research/z7ii/runtime_bootstrap.md)继续执行 ARM／Thumb 切换、库状态初始化、
缓存维护，以及 16 KiB 原厂页表的复制和安装，准备初始 RTOS 配置后到达 master
`0xE8F9C` / slave `0x1A970`。主板接入标准 GICv2 与 CPU 定时器，采用实验性 CBAR 布局，
实际中断投递检查通过；原厂中断处理、任务调度和菜单仍待验证。

[初始运行时服务](research/z7ii/runtime_services.md)补齐两种角色的原厂堆区 RAM，
使 GIC 配置、内存池及四组空链表初始化正常返回 master `0xE3C5C` / slave `0x1570C`。
原厂路径继续到计时设备 `0x04266000` 首次访问前；头尾保护和无效堆段
异常检查通过。完整启动与菜单显示仍待实现。

[计数模块阶段](research/z7ii/runtime_counter.md)加入可推进、停止和复位的 MMIO 计数，
接通原厂 48 MHz CPU 频率声明。原厂启动完成后续 18 次内核模块调用，并创建、启动
启动任务，然后在 master `0xFE660` / slave `0x30034` 等待另一核就绪。
默认单核环境保持这个等待。

[第二核启动阶段](research/z7ii/smp_startup.md)支持每个独立角色内部的 `-smp 2`。
两个核执行原厂复位路径，第二核用原厂独占写发布就绪，调度器实际进入启动任务。
随后在尚未实现的字节寄存器 `0x2C090001` 处触发数据异常。
核间定向 SGI 和两个核各自的物理定时器已通过合成代码验证；完整启动、原厂 IRQ
处理和菜单仍待实现与验证。

[字符接口阶段](research/z7ii/console_boot.md)完成 `0x2C090000` 的全部 10 次原厂字节／
半字配置写入并恢复调用者，提供有界发送和可选日志输出。
原厂日志文本、接收和字符接口中断仍待验证。

[引脚组阶段](research/z7ii/library_boot.md)执行其后的库初始化：向 `0x04280030`
写入配置字，并把 12 组×5 字的引脚表从早期复制 RAM 源复制到 `0x04282000`
的五个 bank，master 另有原厂读-改-写位修改。原厂复位返回初始化链并在
`0x04281000` 首次写入处停止；引脚电气行为未建模。

[控制器链阶段](research/z7ii/controller_boot.md)执行该序列：`0x04281000`
的六个常量字与设置字、原厂计数器延时、`0x04280000` 派生字，以及 `0x04287000`
的轮询门控（master 三个相位、slave 五个）。原厂复位返回链并在 `0x20010044`
首次写入处停止；门控硬件语义未建模。

[配置快照阶段](research/z7ii/snapshot_boot.md)执行其后的初始化：门控
`0x20010044`，按恢复出的 19 个指针读取 `0x2001xxxx` 寄存器字并把值复制到
RAM。512 字源表 `0x20014800` 在启动流程中无任何写入者，按零初始化的只读
控制器内容建模。[参数块阶段](research/z7ii/parameter_boot.md)随后执行尾跳
恢复：十二段写入 `0x20013000`/`0x20016A00`、轮询寄存器就绪位、原厂 19 字
寄存器恢复、向 `0x24074000` 八区域窗口的镜像复制、尾部完成写入并返回初始化
链。master 随后把 `0x21538` 字节载荷复制进新增的 1 MiB 暂存窗口
`0xBAB00000`（逐字节核对一致）。

[内核移交阶段](research/z7ii/kernel_handoff.md)解释了其后的"长计算路径"：
载荷本身是异常/服务块（VBAR 自运行时引导起即指向其 `0x10100000` 运行时
地址），master 随即以描述符 `0x010B0211`、slave 链条以描述符 `0x80430200`
发起 `svc #6`，分别经向量块 `0x10100008`／蹦床 `0x14108` → 分发器
`0x15010` 进入服务实现并长期停留；两角色的暂存初始化续行与链条后续在有界
继续内均不再返回。描述符与固件跨引擎命令族同构，完成源判断为另一引擎的
协调应答，该传输尚未建模。访问观察点进一步还原等待本体：slave 以
"加载—零比较—非零跳出"（文件偏移 `0x19038`）轮询栈上保持为零的等待块，
master 反复经过载荷内的存储蹦床（`0x100430`）写堆对象；两侧等待字始终
不变、邮箱窗口字恒为零——边界是一个无人投递的 RTOS 事件；实验室中断注入
设备扫遍全部共享中断线，没有任何中断能独自释放等待。以一次调试器写入
替代对端响应（master 堆事件字 `0xB2C59A90`、slave 栈等待块 `0xC19B4FC8`）
后内核立即恢复活动（单次运行记录 433 个异常事件；`0x1E004A` 的链条重入
来自探察记录），两角色收敛到同一下一边界：对 `0x04281058` 的存储失效
（DFSR `0x8`），原厂自旋数据中止向量停摆到达的核。随后按执行证据逐轮
登记释放路径上的内容——控制器位库（`0x04281034/58/5C`）、console 邻接页
`0x2C0A0000`、计数器邻接寄存器文件 `0x0426F000..14`、以及 `0x04280000` 处
按 `0x04280004` 相对索引访问的寄存器文件窗口——运行持续前进，直至结构性
边界：固件页表在 `0x2C020000` 的二级缺项、替代值被当指针解引用（`1+0x33`）
与响应派生缓冲区指针 `0xB7F6A0EC`；单轮 freed slave 记录 590+ 个事件。
文件观察点恢复了首批描述符字段：内核在投递自身 `+0x30=0x410` 描述符后
轮询对端就绪字 `0x0428002C`——机器据此建模对端就绪（本地描述符已投递即
应答就绪），freed master 仅凭单次完成字替代写入即达约 2.5 万事件；残余
的 NULL+0x33 解引用来自对端响应结构的堆对象字段——其字段表是下一入口。暂存窗口改为可关断的设备块（负对照保留复制存储的段失效）。
吸收后 freed 双角色零数据中止停入调度派发环（[内核移交文档](research/z7ii/kernel_handoff.md)）。

[定时器节拍阶段](research/z7ii/kernel_handoff.md)解开空闲调度器：固件分析
还原了完整中断管路——载荷 IRQ 入口 `0x101036A8`、运行时一级/二级句柄表，
以及经派发线 237 服务的 `0x2B000000` 定时器块（启停字 `+0`、周期 `+4`、
事件字 `+8` 实测 `0x300`）；机器据此把武装掩码建模为周期契约。开启节拍后，
freed master 经原厂分发器应答节拍、拾起首个真实任务（每核当前任务表非零、
上万次中断进入、零数据中止）并持续执行内核工作，副核保持空闲。隔离 slave
不武装该定时器；菜单可见输出仍待引擎间传输。

[双引擎机器](research/z7ii/kernel_handoff.md)随后移除了全部替代写入：两份
原厂镜像在同一机器中经各自私有地址空间视图运行，共享消息 RAM 以原地址
映射进两侧，真实 slave 自然应答了 master 的移交等待。两引擎从复位自然
启动到各自调度器，全程零数据中止、无任何调试器写入；master 任务推进到
主镜像模块，slave 通信栈持续活动。剩余边界是通信握手的重试环（跨引擎
门铃中断未建模）与其后的显示链。

后续各阶段把前台等待链恢复到实时取景：
[等待界面的服务依赖](research/z7ii/message_wait.md)、实验性
[启动温度参数](research/z7ii/temperature_parameters.md)、
[输入通路与捕获缓冲区](research/z7ii/input_path.md)，以及
[捕获就绪边界](research/z7ii/capture_readiness.md)——操作完成回调表、
捕获子状态机、保持零值的就绪字节与本地资源位图更新。
子状态 0 在就绪检查之前直接返回；设备初始化的工作生产者仍待定位。
菜单尚未验证。
完整启动和菜单尚未实现。

[输入处理配置](research/z7ii/input_configuration.md)增加了各引擎独立的
格式、几何、分析参数与缓冲地址存储。合成检查覆盖地址边界、打包字段、
隔离与复位；配置写入不会自动执行像素传输或产生输入事件。
原厂运行已完成操作 14 回调，进入模式 3 并开始绘制拍摄界面；
继续观察后又转入模式 8 并清空表面，稳定启动与菜单交互仍待验证。
后续[拍摄界面观察](artifacts/shooting_interface_validation/report.json)已确认
原厂状态栏可见，并记录了随后的模式 3 → 1 → 8 切换链。
[启动时限分析](research/z7ii/startup_idle_timer.md)已确认清屏请求由五秒
应用计时器产生；同次电池通信状态为 9、供电策略标志为 2，完整电池
串口回复仍待实现。

## 固件输入

运行实验需要自行合法取得、未经修改的 C 1.70 master EG 镜像，长度为 38,239,098 字节，
SHA-256 为 `478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe`。
本项目不分发或下载原厂固件，固件版权归其权利人所有。完整更新包不能替代已提取的
master 镜像，本仓库也不包含更新包解码、提取或重打包工具。每个探针都会在 Guest
启动前校验长度、SHA-256、CRC 和结构；详见[固件输入](docs/firmware.md)。

## 快速开始

Windows 上需要 Python 3.10+、QEMU ARM、Clang 和 LLVM linker。Linux 同样支持。
在项目根目录运行，并将固件路径替换为实际文件路径：

```powershell
python tools/structure_probe.py --master "C:\firmware\eg1840_mas_01700.bin" --slave "C:\firmware\eg1840_sla_01700.bin" --destination ".local\structure-run"
```

默认使用现成 QEMU 的 `virt` 后端，不需编译自定义主板。
输出目录必须不存在。两个原厂镜像都会先验证长度、SHA256、CRC 和结构；
随后以投毒目标和尾部哨兵逐字节验证原厂早期复制循环、Thumb 表复制、
通信 RAM 清零记录和通信头存储块。结果位于 `.local/structure-run/report.json`，
原始输入不会修改。支持 `--qemu`、`--clang`、`--linker` 指定工具路径。
研究方法与验证边界见[启动结构](research/z7ii/startup_structure.md)，
验证证据见 [structure_validation](artifacts/structure_validation/summary.json)。

## 构建 Z72 主板

Linux / WSL，Python 3.12+：

```sh
sudo apt-get install build-essential ninja-build pkg-config python3-venv clang lld libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev
python3 tools/build.py --jobs 4
python3 tests/test_board.py --qemu .build/build/qemu-system-arm
python3 tools/boot_probe.py --qemu .build/build/qemu-system-arm --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/native-run
```

`nikon-z72-lab` 使用研究所需的原地址 RAM 窗口，默认单个实验 CPU，可选双核；
不是双 EXPEED 完整模型。CPU 型号和窗口容量是实验配置。
构建固定 QEMU 10.2.4 并检查上游压缩包哈希；支持 `--archive` 离线输入。
原厂复位前缀在两块原生主板上的验证证据见
[boot_validation](artifacts/boot_validation/report.json)。

## 测试

```sh
sh tests/run.sh
python tools/verify_release.py
```

测试覆盖输入保护、页表和源码集成，以及 ASan／UBSan 下的 GPU 合成检查。
验证范围和复现命令见 [测试说明](docs/testing.md)；发布清单与本地输出边界见
[发布说明](docs/publication.md)。

## 源码与证据

- `qemu/nikon-z72.c`、`nikon-z72-profile.h`：独立主板和地址窗口。
- `analyze/`：固件身份与结构校验、启动阶段分析和 QEMU 实验基础设施。
- `qemu/nikon-gpu.h`：图形组件；master 图形上传窗口已接入共享 GPU 命令执行器，原厂上传与完成回调已验证。菜单输出与 LCD 扫描尚未验证。
- `tests/`、`checks/`：输入、页表、集成、主板和 GPU 合成测试。
- [开发状态](docs/porting.md)、[架构](docs/architecture.md)、[验证](docs/testing.md)。
- [研究索引](research/README.md)：容器、双处理器、显示、运动估计、升级完整性。

源码目录不包含原厂固件、候选二进制或原厂机器码摘录；固件窗口以偏移、长度和
SHA-256 记录。本地生成文件留在忽略的 `.local/` 和 `.build/`。

## 致谢

感谢 [WonderLantern Z6 QEMU](https://github.com/WonderLantern/z6-qemu) 和
[WonderLantern Z7 QEMU](https://github.com/WonderLantern/z7-qemu)，
以及 R3tr0ooo 和各项目贡献者公开分享相机模拟、图形与图像处理实现及研究工具。

## 许可证

除文件另有声明外，本项目采用 [GPL-2.0-or-later](COPYING) 许可证。
上游署名和许可说明见 [NOTICE](NOTICE.md)。QEMU 保留各文件的原有许可证。
本项目与 Nikon 无隶属关系，项目许可证不授予 Nikon 固件的任何使用或再分发权利；
固件须由使用者自行合法取得。
