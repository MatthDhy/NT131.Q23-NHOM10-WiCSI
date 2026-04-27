# NT131.Q23-NHOM10-WiCSI

# 📡 Netfilter Latency Monitor (LKM)

Module kernel Linux sử dụng **Netfilter hook** để đo **latency** và **jitter** của packet trực tiếp trong kernel.

---

## 🚀 Chức năng

- Hook vào 2 điểm:
  - `NF_INET_PRE_ROUTING` → ghi timestamp T0
  - `NF_INET_LOCAL_IN` → ghi timestamp T1
- Tính toán:
  - ⏱️ Kernel latency = T1 - T0 (μs)
  - 📉 Jitter = khoảng cách giữa 2 packet liên tiếp
- Phát hiện bất thường (delay lớn)
- Log trực tiếp bằng `dmesg`

---

## ⚙️ Tham số

- `target_port` (mặc định: `5500`) → lọc UDP port
- `proto`:
  - `"udp"` (mặc định)
  - `"icmp"` (test bằng ping)

---

## 🛠️ Build & Load

```bash
make
sudo insmod netfilter_plain.ko
```

## Xem Log

```bash
sudo dmesg -w | grep NF_LAT
```

## 🧪 Test
- UDP
```bash
iperf3 -u -c <IP_target> -p 5500 -b 100k
```
- ICMP
```bash
ping <IP_target> -i 0.2
```
