# Z7 II 研究索引

本目录记录 Nikon Z7 II C 1.70 的容器、系统平台及选定固件例程。
结论依据原始固件、CRC 通过的成员、指令与数据观察，以及明确限定条件的执行实验。
实验运行方法见项目 README。

- [容器和成员](z7ii/container.md)
- [多核、双 EXPEED 与任务配置](z7ii/platform_comparison.md)
- [启动、初始化表与独立主从实验](z7ii/startup_structure.md)
- [原厂复位启动前段与首次外设边界](z7ii/reset_prefix.md)
- [早期配置寄存器、临时栈与系统初始化入口](z7ii/early_configuration.md)
- [系统配置首批写入、slave 选择路径与状态轮询边界](z7ii/system_configuration.md)
- [系统配置完成反馈、五阶段命令与原厂超时返回](z7ii/system_completion.md)
- [双通道平台初始化、四次调用与启动代码返回](z7ii/platform_initialization.md)
- [启动返回后的配置、SVC 栈恢复与连续复制](z7ii/boot_continuation.md)
- [启动内存清零、完成应答与致命错误路径](z7ii/boot_memory.md)
- [运行时入口、页表安装、RTOS 配置与中断基础](z7ii/runtime_bootstrap.md)
- [初始运行时服务与堆区](z7ii/runtime_services.md)
- [计数模块、内核初始化与多核就绪等待](z7ii/runtime_counter.md)
- [第二核启动、就绪发布与启动任务执行](z7ii/smp_startup.md)
- [字符接口、原厂混合宽度配置与库初始化边界](z7ii/console_boot.md)
- [引脚组配置与下一控制器边界](z7ii/library_boot.md)
- [控制器链与门控序列](z7ii/controller_boot.md)
- [运行时门控完成与双引擎中断](z7ii/runtime_gate.md)
- [配置快照与批量源读边界](z7ii/snapshot_boot.md)
- [参数块恢复与镜像写边界](z7ii/parameter_boot.md)
- [通信区头部初始化](z7ii/communication_header.md)
- [显示、音频与长曝光](z7ii/display_audio.md)
- [运动估计](z7ii/motion_estimation.md)
- [固件身份](firmware_identity.json)

`artifacts/` 保存 JSON 验证证据，不包含固件。生成的运行输出保存在 `.local/`。
安装安全、完整启动、绘制及 slave 协作均未由这些局部实验证明。

- [串行总线与控制器等待](z7ii/serial_bus.md)
- [附加控制器的独立启动环境](z7ii/controller_core.md)
- [控制器 DMA 配置与有界传输](z7ii/controller_dma.md)
- [输入处理配置与初始拍摄界面](z7ii/input_configuration.md)
- [启动后的五秒时限与供电状态](z7ii/startup_idle_timer.md)
