# Z7 II PTP 固定 RAM 观察流程

执行文件：[`tools/ptp_checksum_context_probe.py`](../tools/ptp_checksum_context_probe.py)。
只适用于 **Z7 II、C 1.70**，脚本会核对机型和版本。版本不符时停止，
不要为了本实验升级或降级。

当前没有证据证明最终确认前会完成 SHA-1 校验，也没有证明校验后
还有可靠的取消节点。因此，**整个流程都不选择最终的“是 / Yes”**。
本实验是确认页以前的 RAM 观察，不能称为已经验证的“只校验后取消”。
依据见[服务与时序分析](../research/z7ii/ptp_service.md)。

## 操作范围

默认只显示离线计划，加 `--execute` 才通信。

| 操作 | 用途 |
| --- | --- |
| `0x1001` | 查询身份，不输出序列号 |
| `0x94FD`，内层 `F001` | 进入服务模式 |
| `0x94FF`，内层 `F032` | 只读取 `0xB2B422C8` 起的 52 字节 |
| `0x94FE`，内层 `F002` | 退出服务，出错时也尝试退出 |
| USB 后端的 `0x1002 / 0x1003` | 打开、关闭本脚本自己的 PTP 会话 |

脚本没有地址参数，不发送更新请求、数据写入或编程命令，不控制菜单。
服务模式会改变临时运行状态，所以先做两次基线对照。

## 一、准备和身份查询

关闭占用相机的照片导入、遥控和其他 PTP 程序，相机保持开机。
确认当前没有更新进度，再连接数据线。

Windows 自带 MTP/PTP 驱动可能不允许原始 USB 接口被直接占用。
优先复用本地 WPD 传输模块，保留当前相机驱动。只加载其 `WpdCamera`，
不运行所在目录中的其他功能脚本。

在 PowerShell 设置路径：

```powershell
Set-Location 'D:\code\z72-qemu'
$Python = 'C:\Users\15056\AppData\Local\Programs\Python\Python312\python.exe'
$Script = 'D:\code\z72-qemu\tools\ptp_checksum_context_probe.py'
$Transport = 'D:\Temporary\2610\24\NikonUnlock\wpd_transport.py'
$Master = 'D:\Temporary\2610\07\Z_72\eg1840_mas_01700.bin'
$Package = 'D:\Temporary\2610\24\z72\Z7_2_0170.bin'
```

WPD 需要 `comtypes`，未安装时运行第一条；然后查看离线计划并只查询身份：

```powershell
& $Python -m pip install comtypes
& $Python -B $Script
& $Python -B $Script --execute --backend wpd --transport $Transport --info-only
```

身份查询不进入服务模式。预期为 `model: Z 7_2`、`version: V1.70`。
找不到相机、版本不符或传输失败时停止，不继续菜单操作。

## 二、两次基线

```powershell
$ReadArgs = @('--execute', '--backend', 'wpd', '--transport', $Transport,
              '--master', $Master, '--package', $Package)
& $Python -B $Script @ReadArgs --destination .local/ptp-baseline-a
& $Python -B $Script @ReadArgs --previous .local/ptp-baseline-a/context.bin --destination .local/ptp-baseline-b
```

目录必须尚不存在，脚本不会覆盖记录。检查第二次的 `report.json`：

- `context_changed: false`：两次之间上下文稳定，可以继续观察。
- `context_changed: true`：先停止菜单实验；服务切换或后台活动可能
  影响上下文，不能把后续变化直接归因于菜单。
- `material_recovered: true` 且 `package_digest_verified: true`：已有
  材料匹配原厂包，不必通过菜单触发任何操作。
- 读取失败、内层 `0x201D`、外层 `0xA004` 或服务退出失败：停止，
  保留错误信息，不自动重试或更换命令。

全零或 `phase: unknown` 只表示没有取得可验证材料。

## 三、最终确认页选择“否”

仅在基线稳定且相机正常时进行。脚本已经结束并退出服务。

1. 手动断开 USB，保持相机同次开机，进入设置菜单的“固件版本”。
2. 如果有原厂更新文件，可以到明确的最终 Yes/No 确认页，记录
   当前版本和目标版本。没有更新入口时停止，不改文件名或版本记录。
3. **选择“否 / No”并退出，不选择最终“是 / Yes”。**
4. 保持开机，重新连接 USB，执行：

```powershell
& $Python -B $Script @ReadArgs --previous .local/ptp-baseline-b/context.bin --destination .local/ptp-after-no
```

不要在确认页连按确认键，不在更新进度中尝试取消或断电。如果意外
出现更新进度，已超出本观察流程，不以强制断电中止。
如果相机中间重启，放弃这组前后时序比较，重新建立基线。

USB 重连和服务切换本身也是实验变量。即使上下文变化，也不能仅凭
变化断言菜单已完成认证，仍须验证原厂整包摘要。

## 四、结果判读

| 文件 | 内容 |
| --- | --- |
| `context.bin` | 本地 52 字节原始快照 |
| `report.json` | 状态、哈希、变化偏移和摘要结果，不含材料字节 |
| `verified-material.json` | 仅摘要通过时生成，`boot_key` 为 B8，`appended_key` 为 K8 |

`context_binding_valid` 检查回调、机型、长度、种子阶段及原包头。
`package_digest_verified` 再核对完整解码主体与候选八字节的 SHA-1。
二者都成立才认为取得材料。

选否后仍无有效材料时，**不要点击最终 Yes 来触发校验**。
该结果不能区分尚未检查、已清空或服务切换改变状态，应回到固件分析。
反馈各次 `report.json`、菜单操作和是否重启的记录即可。
`context.bin`、`verified-material.json` 留在本地，不加入仓库或公开报告。

可离线重新核对已有快照：

```powershell
& $Python -B $Script --context .local/ptp-after-no/context.bin --master $Master --package $Package --destination .local/ptp-after-no-recheck
```

## 原始 USB 后端

系统已经允许访问 PTP 接口时，可以使用与参考脚本相同的 PyUSB 方式：

```powershell
& $Python -m pip install pyusb
& $Python -B $Script --execute --backend usb --info-only
```

PyUSB 还需要可用的 libusb 后端。Windows 无法占用接口时停止，
不自动分离或替换驱动，改用上述 WPD 路径。USB 实现处理拆包、合并
容器和事务号；已有会话不自动接管，失败不自动重试。

本轮通过 28 项针对性检查和既有 QEMU 原始函数对照。真实 USB
服务读取尚未验证，本流程保留这一限制。
