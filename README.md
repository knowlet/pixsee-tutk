# Pixsee TUTK LAN client

以 Python 連接自己的 Pixsee 攝影機，直接在區域網路接收畫面、音訊與傳送對講音訊。
不需要執行原廠 APK 或載入 Android 函式庫。

此專案由 [Fredde87/cuboai-tutk](https://github.com/Fredde87/cuboai-tutk) 衍生，
保留其 MIT 授權的封包重組與 MPEG-TS 基礎，另實作 Pixsee 的認證和媒體流程。

## 功能

- 指定單一 IP 的裝置探索、IOTC 預檢、DTLS-PSK 與 AV 登入。
- H.264 影像；PCM16LE、8 kHz、單聲道音訊。
- 純影像 MPEG-TS／H.264、音訊 WAV／PCM、H.264＋AAC MPEG-TS。
- 檔案或 stdin 對講音訊，40 ms 節奏傳送、重送與逾時清理。
- 僅使用明確選定的憑證，不自動輪試密碼或呼叫 Pixsee 雲端。

實機測試範圍：Pixsee App `4.030.006`、攝影機回報 TUTK SDK `4.3.8.1`，
使用者回報韌體 `1.006.25`。這台設備需明確指定 `--profile legacy`；
韌體版本本身不能保證憑證設定。其他韌體尚未驗證。

## 開始使用

需要 Python 3.10+、OpenSSL 3.2+。合併影音與一般音訊檔轉換另需 FFmpeg。
macOS 可使用已安裝的 Homebrew OpenSSL；Linux 需確保載入的是符合版本的 libssl。

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

## 連線與驗證邊界

影像、收音與控制指令使用 DTLS。原廠 App 的反向對講通道使用 **未加密 AV**；
本實作依相同格式傳送，限於信任的區域網路。對講回傳的 high-water 是
攝影機看到的最高封包序號，不等同逐包完整交付或喇叭實際發聲。

目前已實測影音接收、解碼與對講。修正首個 global frame 編號後，
使用者已在攝影機旁確認能清楚聽到「Hello」；此結果限於上述設備與韌體。
掉包時會丟棄受損影格並等候完整關鍵影格，影像可能短暫停頓。

詳見 [操作說明](docs/usage.md)、[協定分析與實測範圍](docs/protocol.md)、
[來源與授權](NOTICE.md)。錄影、音訊、APK、裝置 UID 與原始分析資料不納入此儲存庫。

## 開發

```bash
python3 -m unittest discover -s tests -v
python3 cuboai_messages.py
```

本機 111 項測試通過。測試包含本機 OpenSSL DTLS 往返、錯誤 PSK、FFmpeg 轉碼、封包驗證、
對講重送／逾時／清理與 CLI。測試不會自動連線家中攝影機。
DTLS 測試另需 `lsof` 確認本機測試伺服器已開始監聽；macOS 內建此工具。
`cuboai_*.py` 為保留的上游支援模組；本專案支援的入口為 `pixsee.py` 和
`PixseeSession` 的探索、影音接收及對講 API。
