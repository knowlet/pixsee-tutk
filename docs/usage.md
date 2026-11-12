# 使用方式

## 環境

Python 3.10+、OpenSSL 3.2+。Python 原生 ssl 模組沒有此處需要的 DTLS API，
本程式透過 ctypes 使用已安裝的 OpenSSL datagram BIO；不需要 Python 套件依賴。
macOS 自動尋找 Homebrew 的 libssl.3.dylib，其他平台使用系統 library lookup。
必要時指定 `--openssl-library /path/to/libssl.so.3`。

FFmpeg 僅用於 `stream --audio` 的 AAC 編碼、`talk --input-format auto` 的音訊轉換。
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
