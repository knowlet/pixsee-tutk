# 使用方式

## 環境

Python 3.10+、OpenSSL 3.2+。Python 原生 ssl 模組沒有此處需要的 DTLS API，
本程式透過 ctypes 使用已安裝的 OpenSSL datagram BIO；不需要 Python 套件依賴。
macOS 自動尋找 Homebrew 的 libssl.3.dylib，其他平台使用系統 library lookup。
必要時指定 `--openssl-library /path/to/libssl.so.3`。

FFmpeg 用於 `stream --audio` 的 AAC 編碼、`talk --input-format auto` 的音訊轉換，
以及 `serve` 的轉送與 JPEG 快照。`serve` 另需 FFprobe 與 MediaMTX v1.21.3。
音訊 WAV／PCM 接收、純影像輸出與原始 PCM 對講不需要 FFmpeg。
可以直接執行 `python3 pixsee.py`，或在自己的虛擬環境執行
`python -m pip install .`，之後使用 `pixsee` 指令。

## 探索與認證

```bash
python3 pixsee.py discover --camera-ip 192.168.0.7
python3 pixsee.py probe --camera-ip 192.168.0.7 --profile legacy
```

`discover` 只聯絡指定 IP、不登入，預設遮罩 UID。
`probe` 必須完成 IOTC、DTLS、AV 驗證並收到完整影格才算成功。
`legacy`／`current` 為 APK 內公開預設參數；本次測試的設備實際使用 `legacy`，
即使 App 的韌體分支會建議 `current`。不做自動憑證輪試。

自訂憑證放在 Git 排除的 `.pixsee-credentials.json`，例如：

```json
{"account":"admin","password":"YOUR_DEVICE_PASSWORD","auth_key":"YOURKEY8"}
```

```bash
python3 pixsee.py probe --camera-ip 192.168.0.7 \
  --profile custom --credentials .pixsee-credentials.json
```

UID 可省略，從指定 IP 探索。也接受 JSON 的 `newPassword`、`newAuthKey`；
不把 `newAvToken` 當成密碼。環境變數為 `PIXSEE_CAMERA_IP`、`PIXSEE_UID`、
`PIXSEE_ACCOUNT`、`PIXSEE_PASSWORD`、`PIXSEE_AUTH_KEY`。
優先序：明確參數 > 環境變數 > JSON > profile。
密碼和 auth key 不接受命令列參數，避免出現在程序列表。

## 影音接收

```bash
# 影音 MPEG-TS，音訊由原生 PCM 轉為 AAC，影像不重新編碼
python3 pixsee.py stream --camera-ip 192.168.0.7 --profile legacy \
  --audio --duration 30 --output recording.ts

# 純影像；未指定 duration 會持續至 Ctrl-C
python3 pixsee.py stream --camera-ip 192.168.0.7 --profile legacy > live.ts

# 原始 H.264（不支援 --audio）
python3 pixsee.py stream --camera-ip 192.168.0.7 --profile legacy \
  --format h264 --duration 10 --output video.h264

# 音訊 WAV
python3 pixsee.py audio --camera-ip 192.168.0.7 --profile legacy \
  --duration 10 --output audio.wav

# 即時播放：需要另裝 ffplay
python3 pixsee.py audio --camera-ip 192.168.0.7 --profile legacy --format s16le | \
  ffplay -nodisp -f s16le -ar 8000 -ch_layout mono -i pipe:0
```

WAV 寫入 stdout 時必須設定 duration，會先完成錄音再輸出正確長度的 WAV；
即時音訊 pipe 請選 `--format s16le`。原始 PCM 格式固定為 8000 Hz、
mono、signed 16-bit little-endian。所有診斷寫入 stderr，不混入媒體 stdout。
指定 duration/timeout 必須大於 0 且不超過 120 秒；省略 duration 可持續執行。
預設拒絕覆寫現有檔案，需加 `--overwrite` 才會覆寫。

MPEG-TS 可直接播放，或用 FFmpeg 封裝成 MP4：

```bash
ffmpeg -i recording.ts -c copy -movflags +faststart recording.mp4
```

go2rtc 的 exec 來源範例（本專案沒有啟動或實測 go2rtc）：

```yaml
streams:
  pixsee:
    - exec:python3 /path/to/pixsee-tutk/pixsee.py stream --camera-ip 192.168.0.7 --profile legacy --audio#killsignal=SIGINT
```

<a id="rtsp-onvif-gateway"></a>

## RTSP、ONVIF、HLS 閘道

`serve` 在 macOS／Linux 上持續接收一台 Pixsee 的影音，供多個觀看端共用。
影像保留原始 H.264；音訊在閘道重新編碼為 AAC、24 kb/s、8 kHz、單聲道。
不重新編碼影像，也不建立額外低解析度子串流。`--no-audio` 可改為純影像。

### 安裝依賴與本機啟動

從 [MediaMTX v1.21.3 官方版本頁](https://github.com/bluenviron/mediamtx/releases/tag/v1.21.3)
下載符合電腦作業系統與架構的壓縮檔，依該版本的 checksum 核對後解壓。
將 `mediamtx` 加入 `PATH`，或用 `--mediamtx /path/to/mediamtx` 指定執行檔。
版本須為 **v1.21.3**；閘道不會自動下載、升級或使用任意其他版本。
另安裝包含 AAC 編碼、H.264 解碼及 JPEG 編碼的 FFmpeg 與同套 FFprobe。

```bash
mediamtx --version
ffmpeg -version
ffprobe -version

python3 pixsee.py serve --camera-ip 192.168.0.7 --profile legacy
```

不需另開 MediaMTX，也不需編寫它的設定檔；`serve` 會啟動與關閉自己管理的程序。
執行檔不在 `PATH` 時，可另加 `--ffmpeg /path/to/ffmpeg --ffprobe /path/to/ffprobe`。
攝影機的 `--profile`／`--credentials` 用法與前節相同。

預設只監聽 `127.0.0.1`，不傳送 ONVIF 探索公告。收到 JSON 的 `"event": "ready"`
才表示已收到持續進入的媒體、讀取實際編碼資訊並啟動 ONVIF 服務。
同一台電腦可使用 `rtsp://127.0.0.1:8554/pixsee`；省略 `--duration` 會持續至 Ctrl-C。

### 開放給區域網路觀看

以下假設攝影機 IP 為 `192.168.0.7`，**執行閘道的電腦** IP 為 `192.168.0.10`。
請換成自己的位址，並讓閘道電腦保有固定或 DHCP 保留位址。

先建立 `.pixsee-gateway-credentials.json`，將範例密碼換成自己產生的密碼：

```json
{"username":"viewer","password":"REPLACE_WITH_A_LONG_RANDOM_ASCII_PASSWORD"}
```

```bash
chmod 600 .pixsee-gateway-credentials.json
python3 pixsee.py serve --camera-ip 192.168.0.7 --profile legacy \
  --listen 0.0.0.0 --advertise-ip 192.168.0.10 \
  --gateway-credentials .pixsee-gateway-credentials.json --discovery
```

`--listen 0.0.0.0` 會監聽所有 IPv4 介面，且要求明確的廣告位址與觀看帳密。
`--advertise-ip` 應是觀看端可連到的閘道電腦位址；啟用探索時也用它選擇多播介面。
只想手動加入網址時可省略 `--discovery`，RTSP 與 ONVIF 手動連線仍可使用。

觀看帳密供 RTSP、HLS、ONVIF 與 JPEG 使用，**與攝影機的 `--credentials` 分開**。
亦可透過 `PIXSEE_GATEWAY_USERNAME`、`PIXSEE_GATEWAY_PASSWORD` 設定；指定觀看帳密
JSON 時，該檔案整組取代環境變數。JSON 僅接受 `username`、`password` 兩個欄位。
帳號限 1–64 個英數字、點、連字號或底線，且不得為 `any`。

Scrypted 的已研究版本使用 [node-onvif 0.7.4](https://github.com/agsh/onvif/blob/90ef2770bef5aa000ec54eab97e71fa76074625a/lib/cam.js)，
會以 ASCII 編碼密碼計算驗證值，
因此搭配此版本時請使用足夠長的隨機 ASCII 密碼，避免中文或其他非 ASCII 字元。
這是該客戶端的限制；閘道本身接受 UTF-8 密碼。
若把帳密放進 RTSP URL，密碼中的 `@`、`:`、`/`、`%` 等保留字元需先做 URL 編碼；
有獨立帳密欄位的應用程式應直接使用欄位。

本機 `127.0.0.1` 的 RTSP／HLS 存取供閘道內部轉送使用，允許免帳密；
其他來源只能使用觀看帳號讀取串流，不能發布串流或使用管理 API。
設定觀看帳密後，ONVIF／JPEG 的受保護操作仍會要求驗證。
此版本提供 HTTP 與 RTSP，未設定 HTTPS／RTSPS；請部署在信任的區域網路。

### 連線網址與連接埠

維持上述位址、預設連接埠及串流名稱時：

| 用途 | 網址 |
|---|---|
| RTSP 影音 | `rtsp://192.168.0.10:8554/pixsee` |
| ONVIF 裝置服務 | `http://192.168.0.10:8080/onvif/device_service` |
| ONVIF Media1 服務 | `http://192.168.0.10:8080/onvif/media_service` |
| JPEG 快照 | `http://192.168.0.10:8080/snapshot.jpg` |
| HLS 播放清單 | `http://192.168.0.10:8888/pixsee/index.m3u8` |

ONVIF 服務接受 SOAP 請求，不是一般網頁。JPEG 與 HLS 可交給支援其格式與驗證方式的
觀看端；並非所有瀏覽器都能直接播放 HLS。`--no-hls` 可關閉 HLS。
`--stream-name` 可修改 RTSP／HLS 路徑，啟動輸出的 JSON 會列出實際網址，不夾帶帳密。

| 預設埠 | 用途 | 參數／開放範圍 |
|---|---|---|
| TCP 8554 | RTSP 控制與 TCP 影音 | `--rtsp-port` |
| UDP 8000／8001 | RTSP 的 RTP／RTCP 影音 | `--rtp-port`／`--rtcp-port`；TCP 播放不需使用 |
| TCP 8080 | ONVIF 與 JPEG | `--onvif-port` |
| TCP 8888 | HLS | `--hls-port`；可用 `--no-hls` 停用 |
| UDP 3702 | ONVIF WS-Discovery | 僅 `--discovery` 啟用；多播 `239.255.255.250` |
| TCP 9997 | 內部媒體狀態檢查 | `--api-port`；固定只監聽 `127.0.0.1` |

自訂服務埠需互不重複，範圍為 1024–65535；RTP 埠必須為偶數，RTCP 埠必須緊接其後（例如 18000／18001）；啟用探索時也不能占用 3702。
防火牆可先允許觀看端連到 TCP 8554、8080，按需要加上 HLS、UDP 影音與探索。
探索使用單一 IPv4 介面的區網多播，通常不會跨 VLAN、路由器或容器網路；
無法探索時先用 ONVIF 位址手動加入。容器內的 `127.0.0.1` 是容器自身，
應填入可從容器連線的閘道電腦 IP。

### Scrypted

依 [Scrypted 官方加入攝影機說明](https://docs.scrypted.app/add-camera.html)，
安裝 ONVIF 外掛，手動填入閘道電腦 `192.168.0.10`、ONVIF 埠 `8080` 與觀看帳密；
同一區網也可從探索結果加入。

- 關閉自動調整攝影機編碼設定；此閘道只回報目前串流，不接受編碼寫入。
- 啟用 `Disable ONVIF Events`；目前沒有事件訂閱或攝影機動作偵測事件。
- 串流傳輸先選 RTSP TCP，確認畫面、收音與快照；目前只有一條主串流。
- 若使用 RTSP 外掛，填入上表 RTSP URL，並設定觀看帳密；需要靜態影像時使用 JPEG URL。

收音可透過 AAC 音軌傳入，但 Scrypted／HomeKit 的雙向對講不會接上本專案的 `talk`。
需要動作偵測時，由 Scrypted 自己的影像分析或其他事件來源提供。
以上為依客戶端介面設計的接法；Scrypted 完整 UI、HomeKit、NVR 錄影仍需實際驗收。

### Home Assistant

在「設定 → 裝置與服務」新增 [ONVIF 整合](https://www.home-assistant.io/integrations/onvif/)，
使用閘道電腦 IP、ONVIF 埠 `8080` 與觀看帳密，RTSP transport 選 `tcp`。
啟用探索時也可從已發現裝置加入。此閘道只提供影音與快照，不會產生 ONVIF
事件感測器或 PTZ 控制；Home Assistant 的 ONVIF 整合以完整 Profile S 裝置為目標，
本專案的子集仍須在使用的版本驗證。

若 ONVIF 加入流程不接受此子集，可用 [Generic Camera](https://www.home-assistant.io/integrations/generic/)：
Stream Source 填 RTSP URL，Still Image URL 填 JPEG URL，快照驗證選 Digest 並填觀看帳密。
RTSP 來源若需在 URL 內提供帳密，依前節進行 URL 編碼。

### Frigate

可在新增攝影機流程選擇自訂 RTSP URL，或把以下片段合併進現有設定。
將 `FRIGATE_PIXSEE_PASSWORD` 傳入 Frigate 的執行環境；其值為已做必要 URL 編碼的
觀看密碼，範例帳號對應前面的 `viewer`。

```yaml
cameras:
  pixsee:
    ffmpeg:
      inputs:
        - path: "rtsp://viewer:{FRIGATE_PIXSEE_PASSWORD}@192.168.0.10:8554/pixsee"
          input_args: preset-rtsp-generic
          roles:
            - detect
            - record
      output_args:
        record: preset-record-generic-audio-copy
    detect:
      enabled: true
    record:
      enabled: true
```

此片段不包含既有 MQTT、偵測器、儲存保留或硬體加速設定。
閘道預設已輸出 AAC，因此錄影可直接複製音軌；使用 `--no-audio` 時改用
`preset-record-generic`。只有主串流，請依主機效能調整 Frigate 的偵測解析度／影格率。
不需設定 ONVIF PTZ。設定格式參見 [Frigate camera inputs](https://docs.frigate.video/configuration/cameras/)
與 [FFmpeg presets](https://docs.frigate.video/configuration/ffmpeg_presets/)。

### NAS／NVR 與 VLC

NAS／NVR 可先選一般 ONVIF 裝置，輸入閘道電腦 IP、ONVIF 埠及觀看帳密。
如果該產品要求未提供的 ONVIF 操作，改用自訂 RTSP 來源，選 H.264、RTSP TCP，
需要音訊時選 AAC。錄影排程、保存時間與告警由 NVR 設定；此閘道本身不保存錄影。
各廠牌的加入流程及是否接受 8 kHz AAC 仍需驗證。

VLC 使用「開啟網路串流」填入 RTSP URL，再依提示輸入觀看帳密。
同一台電腦上的免帳密播放也可使用：

```bash
vlc --rtsp-tcp rtsp://127.0.0.1:8554/pixsee
```

### 持續執行與故障檢查

閘道保留 `.pixsee-gateway-state.json` 內的虛擬裝置 UUID 與重啟序號。
請保留此檔，避免 NVR 在重啟後把它當成另一台裝置；可用 `--state-file` 指定固定路徑。
同一狀態檔不可同時供兩個閘道使用。觀看帳密檔與狀態檔預設都排除在 Git 之外。

第一次可播放串流的等待上限預設為 30 秒（`--startup-timeout`）。
持續接收期間若總媒體流量停滯超過預設 15 秒（`--media-timeout`），會重新建立來源與轉送連線；
認證遭拒會停止，請確認選定的攝影機憑證，不會自動輪試其他密碼。
來源中斷期間，ONVIF 媒體查詢／快照會回報不可用，觀看端也需能重連。
Ctrl-C 會關閉探索、HTTP 與本次啟動的媒體程序。`ready` 是啟動時的確認，並非永久健康保證。
此監控目前檢查影音合計流量；若只有一條音軌或影像軌停滯，另一條仍持續傳送，
不保證會觸發重連。錄影端仍應監測實際畫面與收音是否持續更新。

| 現象 | 先檢查 |
|---|---|
| 缺少執行檔／MediaMTX 版本錯誤 | `--mediamtx`、`--ffmpeg`、`--ffprobe` 與 v1.21.3 |
| 連接埠已使用 | 既有 MediaMTX、go2rtc 或 Frigate；改用另一組互異服務埠 |
| 本機可播，NAS／容器無法連線 | LAN 監聽、觀看帳密、防火牆與閘道 IP；不要填相機 IP 或容器的 loopback |
| 手動加入成功，但探索找不到 | UDP 3702、多播介面、網段或容器網路；保持手動加入即可 |
| Scrypted 驗證失敗 | 觀看帳密、ASCII 密碼與雙方系統時間 |
| 設定／事件操作出現 SOAP Fault | 關閉自動改編碼與事件；此版本沒有寫入、PTZ、事件或標準雙向對講 |

## 對講

```bash
# 讀取自己的 WAV／MP3 等音訊；FFmpeg 轉成設備需要的格式
python3 pixsee.py talk --camera-ip 192.168.0.7 --profile legacy --input message.wav

# 從 stdin 接收已轉好的 PCM（可串接自行設定的麥克風擷取程式）
python3 pixsee.py talk --camera-ip 192.168.0.7 --profile legacy \
  --input - --input-format s16le
```

程式不會擅自開啟電腦麥克風。file/stdin 皆以最多 640 bytes／40 ms 傳送，
沿用來源長度而非一次塞完；Ctrl-C 結束會嘗試送出 SPEAKERSTOP 並關閉連線。
不修改攝影機喇叭音量。反向對講 AV 通道沒有 DTLS，請使用信任的區網。

輸出 JSON 的 `sent_frames` 是送出影格數；`camera_high_water_frames` 是
攝影機回報看過的最高片段序號加一，可能跨越缺片；
`pending_missing_frames` 是最近有效回覆仍要求補送的片數；
`final_high_water_observed` 只表示看到尾端序號，不代表聲學播放成功。
沒有登入或沒有收到任何有效音訊進度回覆時會報錯。

Python API 可用 `session.talk_pcm(chunks, on_audio=callback)` 同時接收完整音訊；
callback 接受 `(pcm_bytes, metadata)`。同一 session 的串流與對講不能由不同
執行緒同時讀取 socket。對講時由單一迴圈負責收發、ACK 和重送。

## 檢查輸出

```bash
ffprobe -v error -show_streams -show_format recording.ts
ffmpeg -v warning -i recording.ts -map 0:v:0 -map 0:a:0 \
  -fps_mode:v passthrough -enc_time_base:v 1:90000 -f null -
```

保留 90 kHz 時間基準，避免 FFmpeg 預設固定影格率輸出造成 DTS 四捨五入警告。
解碼成功與無掉幀是不同條件：本程式會捨棄不完整 GOP，音訊遺失也可能形成間隙。
實機驗證範圍與未確認項目見 [協定紀錄](protocol.md)。

### ONVIF 虛擬硬體識別

`GetNetworkInterfaces` 的 `HwAddress` 由完整裝置 UUID 的 SHA-256 前六個位元組
派生，並設定為 locally administered unicast。相同 UUID（包含 URN／大小寫寫法）
在重啟後維持相同識別；不同 bridge 應使用不同的持久化 UUID。
這消除了只截取 UUID 前綴造成的系統性碰撞，但 46-bit 位址空間無法保證全球唯一，
也未偵測其他主機使用的本地管理位址。若確認發生碰撞，請為其中一個 bridge
重新產生並持久保存 UUID，再重新加入 ONVIF 客戶端。
從最初的 UUID 前綴演算法更新到本版時，`HwAddress` 會改變；若已用舊版加入
Home Assistant，可能需要移除舊整合並重新加入。這不是實體網卡 MAC 的變更。
