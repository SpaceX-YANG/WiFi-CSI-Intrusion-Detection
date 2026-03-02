# 基于 WiFi-CSI 的室内入侵检测系统 📡

## 💡 项目简介 (Project Overview)
本项目是我的优秀毕业设计作品。系统利用商用 WiFi 设备（树莓派 4代 + Nexmon固件）提取物理层的 CSI（信道状态信息）数据，通过对无线电波在空间中传播的多径效应进行分析，结合滑动时间窗口的动态阈值算法，实现了高灵敏度的非接触式室内人员入侵检测。

## 🛠️ 技术栈与核心工作 (Core Technologies)
- **硬件平台：** 树莓派 4B (Raspberry Pi 4B)
- **底层固件：** Nexmon (用于提取底层 OFDM 子载波的 CSI 数据)
- **数据处理：** Python (Numpy, Scipy, Matplotlib)
- **算法核心：** 
  - 应用巴特沃斯低通滤波器 (Butterworth Low-pass Filter) 滤除高频环境噪声。
  - 基于滑动时间窗口计算 CSI 幅值的移动平均与方差，实现动态阈值入侵判定。

## 📂 仓库内容说明 (Repository Structure)
- `signal_processing/` : Python 数据清洗与滤波处理代码
- `docs/` : 数据可视化图 

## 🚀 成果与商业思考 (Business Insight)
该项目摒弃了传统的红外或摄像头监控方案，探索了利用现有 WiFi 基础设施进行安防监控的可能性。具有无死角、保护隐私等商业潜力。展现了我从底层硬件信号提取到上层 Python 算法落地的软硬协同研发能力。
