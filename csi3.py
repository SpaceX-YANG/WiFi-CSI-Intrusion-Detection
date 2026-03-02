# 解析一个pcap文件（里面有30万个数据包），先对整体数据预处理再分解画图

# coding=utf-8
import matplotlib.pyplot as plt
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False
import os
from PIL import Image
import numpy as np
import matplotlib
from matplotlib import cm
from scapy.all import rdpcap
from matplotlib import font_manager
from datetime import datetime, timedelta, timezone

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from scipy.signal import butter, bessel, lfilter, filtfilt
from scipy.ndimage import median_filter
from scipy.interpolate import interp1d
from matplotlib.font_manager import FontProperties
import time


def __find_bandwidth(incl_len):  # 寻找网络带宽函数

    pkt_len = int.from_bytes(
        incl_len,
        byteorder='little',
        signed=False
    )
    nbytes_before_csi = 60
    pkt_len += (128 - nbytes_before_csi)

    bandwidth = 20 * int(
        pkt_len // (20 * 3.2 * 4)
    )

    return bandwidth


def __find_nsamples_max(pcap_filesize, nsub):  # 寻找数据帧数量函数
    nsamples_max = int(
        (pcap_filesize - 24) / (
                12 + 46 + 18 + (nsub * 4)
        )
    )
    return nsamples_max


def get_csi():
    file = 'D:/Python_Project/date_input/day3/test3-3-have.pcap'
    pcap_filesize = os.stat(file).st_size
    samp_rate = 1000  # 采样率
    bandwidth = 0
    nsamples_max = 0
    pcapfile = open(file, 'rb')
    fc = pcapfile.read()
    if bandwidth == 0:
        bandwidth = __find_bandwidth(  # 网络带宽
            fc[32:36]  # 第一帧数据的长度
        )
    nsub = int(bandwidth * 3.2)  # 子载波数量

    if nsamples_max == 0:
        nsamples_max = __find_nsamples_max(pcap_filesize, nsub)  # 理论的数据帧数
    csi = bytearray(nsamples_max * nsub * 4)
    time1 = bytearray(nsamples_max * 8)
    ptr = 24

    nsamples = 0  # 数据帧数量
    while ptr < pcap_filesize:
        ptr += 8
        frame_len = int.from_bytes(  # 获取每帧数据的数据长度
            fc[ptr: ptr + 4],
            byteorder='little',
            signed=False
        )
        ptr += 50
        csi[nsamples * (nsub * 4): (nsamples + 1) * (nsub * 4)] = fc[ptr + 18: ptr + 18 + nsub * 4]  # 提取CSI数据
        time1[nsamples * 8: (nsamples + 1) * 8] = fc[ptr - 58: ptr - 50]
        ptr += (frame_len - 42)  # 跳过已经提取的CSI数据帧
        nsamples += 1

    csi_np = np.frombuffer(  # 将提取出来的CSI数据转化为16位整数数组
        csi,
        dtype=np.int16,
        count=nsub * 2 * nsamples
    )
    time_np = np.frombuffer(  # 将提取出来的CSI数据转化为16位整数数组
        time1,
        dtype=np.int32,
        count=nsamples * 2
    )
    timestamps = time_np.reshape(-1, 2)
    timestamps_in_seconds = timestamps[:, 0] + timestamps[:, 1] / 1e6

    # 计算每个时间戳与第一个时间戳的差值（以毫秒为单位）
    base_timestamp = timestamps_in_seconds[0]
    time_diff = (timestamps_in_seconds - base_timestamp)
    # 打印结果
    #print(timestamps_in_seconds)
    #print(len(timestamps_in_seconds))
    csi_np = csi_np.reshape((nsamples, nsub * 2))  # 将CSI数据变成二维数组
    csi_cmplx = csi_np[:nsamples, ::2] + 1.j * csi_np[:nsamples, 1::2]

    # 删除不必要的列
    remove = [0, 1, 2, 3, 4, 5, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
    csi_cmplx = np.delete(csi_cmplx, remove, axis=1)
    csi_buff = np.abs(csi_cmplx)
    # print(csi_buff.shape)
    sub1_data = csi_buff[0:50000, :]
    print(sub1_data.shape)
    # 计算 CSI 幅度
    # csi_buff = np.abs(csi)

    # 绘制幅值图
    # font = font_manager.FontProperties(fname="C:/Windows/Fonts/SimHei.ttf")
    #
    # plt.plot(sub1_data)
    # plt.title('幅值图', fontproperties=font)
    # plt.xlabel('数据包/个', fontproperties=font)
    # plt.ylabel('幅值', fontproperties=font)
    # plt.show()

    def plot_nature_style(data, title, font_path):
        # 核心参数配置（单位：厘米）
        cm_to_inch = 1 / 2.54
        plt.figure(figsize=(8.7 * cm_to_inch, 6 * cm_to_inch), dpi=300)

        # 中文字体配置
        font = font_manager.FontProperties(fname=font_path, size=7)
        plt.rcParams.update({
            'font.size': 7,
            'axes.titlesize': 8,
            'axes.labelsize': 7,
            'xtick.labelsize': 6,
            'ytick.labelsize': 6,
            'lines.linewidth': 0.8,
            'axes.linewidth': 0.6,
            'xtick.major.width': 0.6,
            'ytick.major.width': 0.6
        })

        # 动态子载波选择
        n_sub = data.shape[1]
        step_size = max(1, int(n_sub / 12))
        selected_subcarriers = data[:, ::step_size]

        # Nature推荐色系（Cividis）
        colors = plt.cm.cividis(np.linspace(0, 1, selected_subcarriers.shape[1]))

        # 绘制核心数据
        for i in range(selected_subcarriers.shape[1]):
            plt.plot(selected_subcarriers[:, i],
                     color=colors[i],
                     alpha=0.9,
                     solid_capstyle='round')

        # 学术级中文标注
        plt.title(title, fontproperties=font, pad=8)
        plt.xlabel('数据包序列', fontproperties=font, labelpad=2)
        plt.ylabel('信号幅值', fontproperties=font, labelpad=2)

        # 坐标轴优化
        ax = plt.gca()
        ax.spines[:].set_linewidth(0.6)
        ax.spines[['top', 'right']].set_visible(False)
        plt.xlim(0, len(data))

        # 精简网格系统
        ax.grid(True, linestyle=':', linewidth=0.5, alpha=0.5)

        # 专业色标设计
        sm = plt.cm.ScalarMappable(
            cmap=plt.cm.cividis,
            norm=plt.Normalize(vmin=0, vmax=n_sub - 1)
        )
        cbar = plt.colorbar(sm, ax=ax, pad=0.02, aspect=35)
        cbar.set_label('子载波索引',
                       fontproperties=font,
                       rotation=270,
                       labelpad=12)
        cbar.ax.tick_params(width=0.6, length=3)
        # cbar.ax.yaxis.set_ticks_position('right')
        cbar.ax.set_yticklabels([str(int(i)) for i in np.linspace(0, 30, 5)])

        # 修复保存参数
        plt.tight_layout(pad=0.5)
        plt.savefig(f'{title}.tif', dpi=300, bbox_inches='tight', format='tiff')
        plt.show()


    font_path = "C:/Windows/Fonts/msyh.ttc"  # 微软雅黑更清晰

    # 在原始代码中替换绘图部分：
    # font = font_manager.FontProperties(fname="C:/Windows/Fonts/SimHei.ttf")

    plot_nature_style(sub1_data, '滤波后CSI信号', font_path)

    # 插值处理
    samp_rate = 1000  # 假设采样率
    interp_stamp = np.arange(0, np.floor(time_diff[-1] * samp_rate) + 1) / samp_rate
    csi_interp = np.zeros((len(interp_stamp), csi_buff.shape[1]))
    for jj in range(csi_buff.shape[1]):
        interp_func = interp1d(time_diff, csi_buff[:, jj], kind='linear')
        csi_interp[:, jj] = interp_func(interp_stamp)

    # 巴特沃斯低通滤波
    order = 3
    cutoff = 80
    fs = 1000
    nyq = 0.5 * fs
    normal_cutoff = cutoff / nyq
    b, a = butter(order, normal_cutoff, btype='low', analog=False)
    filt_csi = np.zeros_like(csi_interp)
    for i in range(csi_interp.shape[1]):
        filt_csi[:, i] = filtfilt(b, a, csi_interp[:, i])

#处理完成
    #print(filt_csi.shape)

    num_subarrays = filt_csi.shape[0] // 224
    for i in range(num_subarrays):
        start_idx = i * 224
        end_idx = (i + 1) * 224

    sub2_data = filt_csi[0:50000, :]  # 索引从0到299
    print(sub2_data.shape)  # 输出 (300, 234)

    # 绘制幅值图
    # font = font_manager.FontProperties(fname="C:/Windows/Fonts/SimHei.ttf")
    #
    # plt.plot(sub2_data)
    # plt.title('幅值图', fontproperties=font)
    # plt.xlabel('数据包/个', fontproperties=font)
    # plt.ylabel('幅值', fontproperties=font)
    # plt.show()

    # 原始数据
    plot_nature_style(sub2_data, '原始CSI信号', font_path)

    # sub_data = filt_csi[start_idx:end_idx, :]
    # print(sub_data.shape)
    # print(time_diff.shape)
    # print(timestamps_in_seconds.shape)
    # print(interp_stamp.shape)
    # print(filt_csi.shape)

if __name__ == '__main__':
    get_csi()