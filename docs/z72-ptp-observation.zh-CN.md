# Z7 II PTP 读取操作

适用于 **WSL、Z7 II、C 1.70**。下面的命令在 WSL 终端中逐条执行。
从项目根目录开始，所有文件路径均为相对路径。

**全程不要选择固件更新的最终“是 / Yes”。**
离线分析已将 C 1.70 普通整包菜单路径的摘要认证启动定位在选 Yes 之后。
到确认页选 No，不能用于触发本次 K8 生成；相同菜单实验无需重复。
详见[确认页分析](../research/z7ii/menu_confirmation.md)。
脚本只查询身份和读取固定的 52 字节 RAM，不发送更新或写入请求。
实机已完成两轮读取，选“否”前后均为全零；目前没有取得 K8。
相同流程暂时无需重复，以下保留已执行的操作步骤。
方案 A 的日志留存核对和方案 B 的固定 RAM 对照工具见
[读取路径前期验证](z72-ptp-read-paths.zh-CN.md)。
2026-10-25:材料已通过[失败认证法](z72-k8-recovery.zh-CN.md)在实机恢复
(坏摘要文件触发失败分支,`tools/ptp_failed_auth_probe.py` 读取并验证;
方法与流程见该文档,密钥值刻意不入库)。本页其余内容保留为历史参考。
你观察到 USB 拔插和脚本执行会伴随界面返回、闪动或声音，前后快照
因此还包含界面和会话切换的影响，不能单独用于判断菜单是否完成校验。

## 1. 打开目录，安装依赖

```bash
cd tools
python3 -m venv ../.venv
source ../.venv/bin/activate
python -m pip install pyusb
```

后续命令都在 `tools` 目录执行。虚拟环境和依赖只需创建、安装一次；
下次打开终端后，在 `tools` 目录运行 `source ../.venv/bin/activate` 即可。
如提示无法创建虚拟环境，先安装 WSL 发行版的 `python3-venv` 软件包。

## 2. 连接相机，查询机型

关闭照片导入、遥控等占用相机的软件。相机正常开机、没有更新进度时，
将 USB 连接到 WSL。`lsusb` 中应能看到 `04b0:044b`。
脚本使用 PyUSB 和系统 libusb，不加载外部 Python 文件。

```bash
python ./ptp_checksum_context_probe.py --execute --info-only
```

应显示 `model: Z 7_2`、`version: V1.70`。找不到相机、版本不符或报错时，先停止。
这一步不进入服务模式。

## 3. 连续读取两次，建立基线

第一次：

```bash
python ./ptp_checksum_context_probe.py --execute --master ../../../Temporary/2610/07/Z_72/eg1840_mas_01700.bin --package ../../../Temporary/2610/24/z72/Z7_2_0170.bin --destination ../.local/ptp-baseline-a
```

保持相机状态不变，第二次：

```bash
python ./ptp_checksum_context_probe.py --execute --master ../../../Temporary/2610/07/Z_72/eg1840_mas_01700.bin --package ../../../Temporary/2610/24/z72/Z7_2_0170.bin --previous ../.local/ptp-baseline-a/context.bin --destination ../.local/ptp-baseline-b
```

查看第二次输出：

- `context_changed: false`：两次读取一致，可以继续下一步。
- `context_changed: true`：先停止，暂时不能判断菜单带来的变化。
- `material_recovered: true` 且 `package_digest_verified: true`：已经取得匹配材料，无需再操作更新菜单。
- 任何报错：停止，保留错误信息。

输出目录必须尚不存在，脚本不会覆盖旧记录。重做实验时，为输出目录换一个名字，并相应修改后续的比较路径。

## 4. 菜单选“否”后的读取（已完成，暂不重复）

1. 等脚本结束后拔掉 USB，保持相机开机，中途不要重启。
2. 进入设置菜单的“固件版本”。如果已有原厂更新文件，可进入明确的最终 Yes/No 确认页，记录当前版本和目标版本。没有更新入口就停止，不改文件名或版本记录。
3. **选择“否 / No”并退出。不要选择最终“是 / Yes”。**
4. 重新连接 USB，执行下面这条命令。

```bash
python ./ptp_checksum_context_probe.py --execute --master ../../../Temporary/2610/07/Z_72/eg1840_mas_01700.bin --package ../../../Temporary/2610/24/z72/Z7_2_0170.bin --previous ../.local/ptp-baseline-b/context.bin --destination ../.local/ptp-after-no
```

如果相机中途重启，需要重新建立基线。如果意外出现更新进度，不要强制断电。
没有取得有效材料时，也不要为了触发校验去选择最终 Yes。

## 5. 看结果，反馈记录

结果保存在 `../.local` 下的三个对应目录中：

| 文件                       | 用途                           |
| -------------------------- | ------------------------------ |
| `report.json`            | 可以反馈的结果报告             |
| `context.bin`            | RAM 快照，留在本地             |
| `verified-material.json` | 仅摘要验证通过时生成，留在本地 |

请反馈三次的 `report.json`、菜单操作经过，以及中途是否重启。
`context_changed` 只说明内容变化；只有 `package_digest_verified: true` 才说明候选材料匹配原厂包。
全零、`phase: unknown` 或未取得材料，都不能据此判断菜单有没有执行校验。
USB 重连和服务切换也可能影响结果。

原理、命令范围及已有验证记录见[服务与时序分析](../research/z7ii/ptp_service.md)。

如果提示 `No backend available`，需安装 WSL 发行版的 `libusb-1.0-0` 软件包。
如果提示权限不足或接口被占用，先停止并检查 USB 访问权限及占用程序，
不要自动分离驱动或反复重试。
