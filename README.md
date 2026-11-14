# Pixsee TUTK LAN client

以 Python 連接自己的 Pixsee 攝影機，直接在區域網路接收畫面、音訊與傳送對講音訊。
也可啟動 RTSP／ONVIF 閘道，供 Scrypted、Home Assistant／Frigate、NAS／NVR
與 VLC 接入。不需要執行原廠 APK 或載入 Android 函式庫。

此專案由 [Fredde87/cuboai-tutk](https://github.com/Fredde87/cuboai-tutk) 衍生，
保留其 MIT 授權的封包重組與 MPEG-TS 基礎，另實作 Pixsee 的認證和媒體流程。

## 功能

- 指定單一 IP 的裝置探索、IOTC 預檢、DTLS-PSK 與 AV 登入。
- H.264 影像；PCM16LE、8 kHz、單聲道音訊。
- 純影像 MPEG-TS／H.264、音訊 WAV／PCM、H.264＋AAC MPEG-TS。
- 檔案或 stdin 對講音訊，40 ms 節奏傳送、重送與逾時清理。
- `serve`：共用一條攝影機連線，提供 RTSP TCP／UDP、HLS 與 JPEG 快照。
- 唯讀 ONVIF Device／Media1、可選的區網探索，以及串流中斷後重新連線。
- 僅使用明確選定的憑證，不自動輪試密碼或呼叫 Pixsee 雲端。

實機測試範圍：Pixsee App `4.030.006`、攝影機回報 TUTK SDK `4.3.8.1`，
使用者回報韌體 `1.006.25`。這台設備需明確指定 `--profile legacy`；
韌體版本本身不能保證憑證設定。其他韌體尚未驗證。

## 開始使用

需要 Python 3.10+、OpenSSL 3.2+。合併影音與一般音訊檔轉換另需 FFmpeg。
macOS 可使用已安裝的 Homebrew OpenSSL；Linux 需確保載入的是符合版本的 libssl。
`serve` 另需 **[MediaMTX v1.21.3](https://github.com/bluenviron/mediamtx/releases/tag/v1.21.3)**、
FFmpeg 與 FFprobe；閘道會檢查 MediaMTX 版本並管理自己的服務程序。

```bash
git clone https://github.com/knowlet/pixsee-tutk.git
cd pixsee-tutk
python3 pixsee.py discover --camera-ip 192.168.0.7
python3 pixsee.py probe --camera-ip 192.168.0.7 --profile legacy

# 錄製 30 秒影音
python3 pixsee.py stream --camera-ip 192.168.0.7 --profile legacy \
  --audio --duration 30 --output recording.ts

# 錄製 10 秒音訊
python3 pixsee.py audio --camera-ip 192.168.0.7 --profile legacy \
  --duration 10 --output audio.wav

# 將自己的音訊檔送到攝影機喇叭
python3 pixsee.py talk --camera-ip 192.168.0.7 --profile legacy --input message.wav
```

`192.168.0.7` 是範例／本機驗證目標，請替換成自己的攝影機 IP。
輸出檔預設不得已存在；確定要覆寫時加 `--overwrite`。

## 接到播放器或 NVR

安裝上述依賴後，先在執行閘道的電腦上測試：

```bash
python3 pixsee.py serve --camera-ip 192.168.0.7 --profile legacy
```

收到 `"event": "ready"` 後，可在同一台電腦的 VLC 開啟
`rtsp://127.0.0.1:8554/pixsee`。影像保留 H.264；音訊在閘道轉為 AAC、
24 kb/s、8 kHz、單聲道。預設只接受本機連線。

其他電腦、NAS 或容器需依 [閘道設定與整合範例](docs/usage.md#rtsp-onvif-gateway)
設定 `--listen 0.0.0.0`、閘道電腦的 `--advertise-ip` 與獨立觀看帳密。
需要 ONVIF 自動探索時再加 `--discovery`。所有 RTSP／ONVIF／快照網址都指向
**閘道電腦**，不是 Pixsee 攝影機 IP。

Scrypted 使用 ONVIF 外掛時，請關閉自動調整攝影機編碼，並啟用
`Disable ONVIF Events`。此閘道沒有事件、PTZ、攝影機設定寫入或 ONVIF／RTSP
雙向對講；原有 `talk` 指令獨立提供對講功能。這是相容性介面，未取得 ONVIF
Profile S／T 認證；各產品實際 UI 加入與錄影驗收仍需在目標環境進行。

## 連線與驗證邊界

與 Pixsee 之間的影像、收音與控制指令使用 DTLS。原廠 App 的反向對講通道使用 **未加密 AV**；
本實作依相同格式傳送，限於信任的區域網路。對講回傳的 high-water 是
攝影機看到的最高封包序號，不等同逐包完整交付或喇叭實際發聲。

目前已實測影音接收、解碼與對講。修正首個 global frame 編號後，
使用者已在攝影機旁確認能清楚聽到「Hello」；此結果限於上述設備與韌體。
掉包時會丟棄受損影格並等候完整關鍵影格，影像可能短暫停頓。

閘道的 RTSP 與 HTTP 服務使用觀看帳密，但目前不提供 TLS；請部署在信任的區域網路。
觀看端帳密與 Pixsee 登入憑證分開設定。

詳見 [操作說明](docs/usage.md)、[協定分析與實測範圍](docs/protocol.md)、
[來源與授權](NOTICE.md)。錄影、音訊、APK、裝置 UID 與原始分析資料不納入此儲存庫。

## 開發

```bash
python3 -m unittest discover -s tests -v
python3 cuboai_messages.py
```

本機完整 182 項測試通過、無跳過，包含真實影音協議與斷線恢復測試。
測試包含本機 OpenSSL DTLS 往返、錯誤 PSK、FFmpeg 轉碼、封包驗證、
對講重送／逾時／清理、CLI、ONVIF 驗證與本機迴路的 WS-Discovery 多播。
測試不會自動連線家中攝影機。分階段驗證紀錄見 [協定文件](docs/protocol.md)。
完整 RTSP／HLS／快照／重連驗證需指定已安裝的 MediaMTX；GitHub CI 會執行此項：

```bash
PIXSEE_TEST_MEDIAMTX=/path/to/mediamtx python3 -m unittest discover -s tests -v
```

未設定此變數時，會明確跳過該端到端測試，不代表已驗證協議轉送。
DTLS 測試另需 `lsof` 確認本機測試伺服器已開始監聽；macOS 內建此工具。
`cuboai_*.py` 為保留的上游支援模組；本專案支援的入口為 `pixsee.py` 和
`PixseeSession` 的探索、影音接收及對講 API。
