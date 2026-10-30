# 计算程序架构资料的适用边界

现有固件中两个上传程序的处理器架构仍未确认。以下资料用于交叉核对，
不能用产品系列名称代替机器码验证。

- 原厂 XM4 架构资料的[公开镜像目录](https://github.com/qfdong/papers/tree/master/Todo/%E6%94%B6%E9%9B%86%E7%9A%84%E8%B5%84%E6%96%99/CEVA_Docs/CEVA-XM4_Arch_Spec_V1.1.3.F)：
  Volume I 第 7.2 节描述可变长并行指令包和扩展字段；Volume II
  第 3.4/3.9 节说明分支、调用的机器地址使用半字单位。
  这些性质与此前发现的偶数拆分值相容，但相容性不证明具体操作码。
  已检查的相关章节没有提供足以直接实现解码器的操作码位表。
- 原厂[二进制工具手册镜像](https://github.com/qfdong/papers/blob/master/Todo/%E6%94%B6%E9%9B%86%E7%9A%84%E8%B5%84%E6%96%99/CEVA_Docs/CEVA-Toolbox-documents/CEVA-Toolbox%20Binary%20Tools%20Reference%20Guide.pdf)
  第 3 节描述单个指令包和原始文件的解码接口。接口说明本身没有给出
  当前可用的解码实现。第 9.15 节的编码图属于用户扩展指令示例，不能
  当作基础指令集的编码表。
- 独立作者的[旧系列编码实验及原始数据](https://github.com/fxsheep/seewa-eks/tree/main/info/t32_insn_bruteforce)
  有明确的 16 位 `SQ.nop` 样本。该编码及其交换字节形式在当前从处理器
  上传程序的 `+0xc000` 之后均未找到。此结果不足以否定整个处理器家族，
  也没有证明这段程序的填充字就是空操作；目前不能直接复用该旧系列表。

下载的原始资料和校验摘要只保存在私有 `.local/compute-architecture-docs`
目录，未加入发布清单。未据这些资料修改固件、计算结果或中断通知。
