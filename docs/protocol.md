# 協定分析與實機驗證

## RTSP／ONVIF 閘道增補（2026-11-12）

`serve` 將既有 Pixsee 接收器接到 FFmpeg 與固定版本的 MediaMTX v1.21.3，
由一條攝影機來源供多個讀取端使用。RTSP 轉送以 `-c:v copy` 保留 H.264，
音訊則重新編碼為 AAC、24 kb/s、8000 Hz、mono；JPEG 快照另外擷取，HLS 使用 MPEG-TS 分段。
來源的 PCM → AAC 編碼仍由原有影音流程負責，RTSP 發布端再做一次音訊編碼，
建立 RTSP 標頭需要的 AAC codec configuration；不能將整條閘道流程稱為影音無損複製。
依賴、啟動與產品接法見 [使用方式](usage.md#rtsp-onvif-gateway)，
候選比較與固定來源見 [研究決策](research/protocol-gateway.md)。

| 介面 | 實作範圍 |
|---|---|
| RTSP | TCP interleaved 與 UDP unicast；外部帳號僅有讀取權限 |
| HLS／JPEG | 可選 HLS 播放清單；經驗證的 HTTP JPEG 快照，來源中斷時不回傳舊快照冒充成功 |
| ONVIF Device | 時間、服務、能力、識別、scopes 與唯讀網路資訊 |
| ONVIF Media1 | 實際影音 profile、來源／編碼設定查詢、串流與快照 URI |
| ONVIF 驗證 | HTTP Digest 與 WS-Security UsernameToken PasswordDigest；時間／重送檢查 |
| WS-Discovery | 選定 IPv4 介面的 Hello／Bye、Probe／Resolve 與對應回覆；Types／Scopes 比對、穩定 UUID 與重啟序號 |
| 尚未提供 | Media2、PTZ、Imaging 設定、事件訂閱、動作偵測事件、編碼設定寫入、重啟、ONVIF／RTSP backchannel |

ONVIF 回報閘道由 FFprobe 讀到的編碼與解析度；已知的攝影機原始影像為 1920×1088，
不硬填為 1920×1080／30 fps。未確認的影格率、bitrate 或 GOP 不自行補成測量值。
總媒體流量停滯時會將媒體狀態設為不可用，重連後重新查驗；只看到服務埠開啟不算串流健康。
目前監控總流量，不能保證偵測「一條軌道停滯、另一條仍傳送」的部分故障。
不支援的 SOAP 操作、未知 token 或傳輸設定會回傳 fault，沒有假裝成功變更攝影機。

SOAP 使用 1.2；探索使用 WS-Addressing 2004/08 與 WS-Discovery 2005/04。
這是供影音接入的唯讀 ONVIF 子集，**沒有宣稱完整 Profile S／T 相容或認證**。
原有 `talk` CLI 的實機發聲證據不代表標準 ONVIF／RTSP 雙向對講已接通。

已完成的分項測試包括 ONVIF 請求／回應與驗證，以及本機迴路 UDP 多播、
Probe／Resolve 關聯、重送、QName／scope 比對、停止與連接埠釋放。
合成媒體、實機閘道、獨立客戶端與產品 UI 屬不同驗證層級；不能由上述分項測試
推論 Scrypted、Home Assistant、Frigate 或任一 NAS／NVR 已成功加入及錄影。
目前未進行這些產品完整 UI 驗收，也未驗證其 HomeKit 或標準雙向對講流程。

實機閘道已驗證 H.264 1920×1088、標稱 15 fps、AAC 8 kHz 單聲道：
RTSP TCP／UDP 並行影音解碼、HLS 影音解碼與 Digest JPEG 快照均成功且無解碼警告。
另外以 Scrypted 採用的 node-onvif 0.7.4 完成初始化、裝置資訊、profiles、串流與快照 URI 查詢。
RTSP 缺少／錯誤觀看帳密均回傳 401，正確帳密回傳 200；實際 FFmpeg 發布請求遭 401 拒絕。
停止後已確認六個影音／HTTP／內部 API 連接埠可重新綁定。
這些結果限於本次設備及測試時段；詳見 [閘道驗證摘要](validation-gateway-2026-11-12.json)。

完整 180 項本機測試通過、無跳過。合成影音測試使用真實 MediaMTX／FFmpeg，
驗證並行讀取、強制中斷來源後的一次重連、恢復後重新解碼，以及所有程序與服務埠清理。
保留的上游封包檢查、套件安裝與獨立目錄中的 `pixsee serve --help` 也已通過。

## 音訊與對講增補（2026-11-12）

此音訊／對講階段的本機 111 項測試通過；可安裝套件與獨立目錄中的 CLI 入口已驗證。
結果摘要見 [validation-2026-11-12.json](validation-2026-11-12.json)。

本階段新增 PCM 音訊接收、WAV／raw 輸出、AAC 影音封裝與檔案／stdin 對講。
20 秒實機影音錄製取得 247 個可解碼 H.264 影格與 154 個 AAC 音框；
H.264 為 1920×1088，AAC 為 8000 Hz mono。保留 90 kHz 時間基準進行
全片解碼，warning/error 為 0 bytes。AAC PTS 相鄰差固定 11520 ticks／128 ms，
沒有重疊；音訊與影像使用同一攝影機時間基準。這不證明無掉幀。

對講已通過使用者現場驗證：修正起始影格編號後，傳送同一段「Hello」音檔，
使用者確認「有，清楚聽到了」。音檔為 PCM16、8000 Hz mono，含前後靜音共
2.283 秒；送出 58 個影格，攝影機 high-water 為 58，沒有待補片請求。
ACK 的 D 是 high-water，能跨越缺洞，**仍不能單靠 ACK 推論完整交付或實際發聲**；
本次播放證據來自使用者聆聽。

修正前，即使傳輸回覆正常，使用者兩次都聽不到 Hello；調高攝影機實體音量後仍無聲，
原廠 App 則可正常對講。原因是 global frame 誤從 1 開始：原生接收端等待第 0 幀，
阻擋後續音訊交付。將 global frame 改從 0 開始、audio frame 保持從 1 開始後，
在同一設備與音檔上成功發聲。測試新增首幀及 32-bit counter rollover 回歸。

程式未修改喇叭音量；使用者自行操作攝影機的實體音量鍵。較早的唯讀音量查詢值為 3，
不是使用者調整後的讀值。正式 CLI 不需要切換麥克風設定，也未呼叫雲端 talk token API。

### 接收音訊

- `AudioThreadRunnable` 使用 AudioTrack，PCM16 little-endian、mono、8000 Hz。
- 實測每個音訊單元為 1024 bytes PCM 加 16-byte FRAMEINFO，codec `0x008c`；
  時間戳在 FRAMEINFO offset 12，是與影像一致的 uint32 毫秒值。
- 只輸出完整音訊單元，不把缺少片段的 PCM 接起來當成有效聲音。
- 音訊時間軸用三區塊的中位數排除單點抖動；持續缺口補靜音、持續重疊裁除。
  保留 32 ms 容忍範圍，約增加 128 ms 緩衝；AAC 依實際樣本數計時。
- FFmpeg AAC encoder 的 1024-sample priming 保留在首批來源音訊前 128 ms。

### 對講

- 加密控制通道送 `SPEAKERSTART 0x0350`，8-byte payload 的 byte 0 為 channel 1。
- 攝影機在相同 IP／port／nonce／fingerprint 的 channel 1 反向登入。
- 原廠 `avServStart3(session, NULL, NULL, 5, 60, channel, ...)`：
  此通道為 **datatype 0、未加密 AV**；不是 DTLS，也沒有對講通道自身的認證。
  僅在已認證主連線、使用者啟動對講期間接受，固定核對來源與 session identity。
- primary 570-byte 登入與 572-byte resend companion 均為空帳密；
  僅對有效 companion 回覆 62-byte `0x21` grant，完整回送 token。
  grant offset 4 是 service type **60**，不是主通道 camera grant 的值。
- PCM 640 bytes／40 ms，對應 App 的 `AudioSpeaker.CHUNK_SIZE`。
  compact audio subtype 3、AV flags 5、20-byte frame header，尾端為
  codec `0x008c`、flags 2、16-byte FRAMEINFO；原廠對講 timestamp 為 0。
- compact packet offset 20 的 global frame 從 **0** 開始；offset 24 的 audio frame 從 **1** 開始。
  重送保持兩個影格編號不變；傳輸序號可前進。
- 以攝影機 SACK 缺片列表重送，有限緩衝、格式檢查與節流；結束送 `0x0351`＋8 zeros。
  沒有登入、沒有有效進度、來源停滯或攝影機停止回覆均會逾時並清理。
- 尚未實作需要雲端 talk token 的 `0x0352` V2 認證流程。

Native 靜態位址：`avServStart3 0xfd90` → `avServStart2_inner 0xf3ea` →
`serverConnect 0x1e1e8` → grant `0x125a8`，證明 service type 的傳遞。
`_sendAVFrameFifo 0x13078`、`avPutDataToAVFrameFifo 0x13dbc` 對應音訊封裝。
`0x123d6..0x12492` 顯示 high-water 與 missing FIFO 分開維護。
初始化 `0x1ff4e/52` 將 global send/consumed 設為 `0xffffffff`，`0x13126/28`
先加一，因此首幀是 0。`0x148e4` 將音訊移至共用排序佇列，`0x1452e..56`
等待下一個 global frame；通過後 `0x1462a..70` 才將資料交付音訊佇列。

本階段使用已取得的 LLVM Thumb 輸出、既有 REA evidence 與目標 JADX 輸出。
新的 REA Hopper session 啟動失敗，沒有把補充分析冒充新的 REA Evidence；
沒有執行原廠 ARM binary。聲學結果由使用者在設備旁確認。

以下保留初始純影像階段的紀錄；其中 57 tests／純影像 scope 為當時結果。

---

日期：2026-11-12（Asia/Taipei）。範圍：使用者提供的 XAPK、指定家用攝影機
指定的區網攝影機；韌體版本 `1.006.25` 由使用者提供。未執行原廠 APK／ARM 函式庫，
未變更配對、密碼、Wi-Fi、韌體或其他設備設定。

## 結果

| 問題 | 結果 | 依據 |
|---|---|---|
| 是否使用 TUTK？ | 已回答：SDK 4.3.8.1 | APK native libraries、區網探索回覆 |
| Cubo 連線是否可直接套用？ | 已回答：需要獨立認證與封裝 | Auth key、DTLS、Pixsee IOCTRL／FRAMEINFO 不同 |
| 能否從指定攝影機接出畫面？ | 已回答：加密登入、接收與解碼成功 | 30 秒實測錄影，360 影格，H.264 1920×1088 |
| 音訊／對講是否完成？ | 未回答／未實作 | 此次入口輸出純影像 |
| 任意 Pixsee 韌體是否相容？ | 未回答 | 僅此設備／版本經實測 |

最終測試輸出 29.771333 秒 MPEG-TS；FFmpeg 全片解碼成功，warning/error log 為
0 bytes。檔案也已無重新編碼封裝為 MP4。安全影格輸出機制丟棄 73 個不完整或
依賴受損 GOP 的影格；這是可播放性驗證，**不是無掉幀或所有來源影格均收到的證明**。

57 項測試通過，包含本機 OpenSSL 真實 DTLS PSK server/client 往返、錯誤 PSK
不通過、MTU／重傳、封包來源與 session/token 驗證、登入失敗／中斷清理、
影格完整性與 IDR 恢復、CLI 二進位輸出。既有 `cuboai_messages.py` 自我測試亦通過。
Cubo 攝影機未做新的實機回歸；其唯一程式變更是預設保留原行為的重組後 hook。

## 樣本與工具

| 樣本 | SHA-256 |
|---|---|
| `pixsee_4.030.006_APKPure.xapk` | `ad1b0057fe53ba6a4f691ce8342b6ab158f3563264b9b6640a2adaaad2988211` |
| `config.armeabi_v7a.apk` | `66d43d3c487f32eff7b360433c7414ca99985b5b5a533badfd72cf93cd3839e6` |
| `libIOTCAPIs.so` | `580b10a539121ef7ec6c1280f7becd5836181ce058f30458427f81985f999f88` |
| `libAVAPIs.so` | `d18743eae45ee45bfc5d42e6194569118520f007a22d25e2439b7634456d9c39` |

Package：`com.compal.bioslab.pixsee.pixm01`，App 版本 `4.030.006`，version code 410。
XAPK 包含 base APK、armeabi-v7a／語系／資源 splits。Native 目標為 ARMv7 Thumb。

實際使用 REA 的 archive inventory、Hopper procedure search／pseudocode／assembly，
匯出 26 筆 Evidence。可用的 REA Android bridge 缺少 `jadx-headless-mcp` 設定，
因此 Java/Kotlin 路徑以已安裝 JADX 1.5.6 補足；沒有安裝新分析引擎。
JADX 整體處理回報 417 個反編譯錯誤，不能宣稱全 App 完整還原。
下列使用的目標方法有可讀輸出，並與 native／實機封包交叉確認。
Hopper 部分 pseudocode 未保留完整分支，必要欄位另外以 Thumb assembly 核對。

## 連線與資料流

```text
單一 IP UDP/32761 探索（0x0601，無 UID）
  → 200-byte 0x0602：UID、SDK、實際服務埠
  → 帶 auth key 的 0x0601 precheck（operation 1）
  → 比對 IP、UID、nonce、fingerprint，要求 status 1／7
  → ACK（operation 2）
  → IOTC datatype 1 內封裝 DTLS 1.2 PSK
  → 加密的 AV normal/resend login，要求成功狀態及正確 token
  → video start 0x01FF，audio start 0x0300（均 8 bytes 零）
  → AV fragment ACK／復原／重組
  → H.264 + 16-byte FRAMEINFO
  → 完整 IDR／GOP 篩選 → 純影像 MPEG-TS
```

### IOTC 協定

- 無 UID 探索與連線預檢不同：byte 15 分別為 1／0；operation 在 offset 64。
- UID 在 `[16:36]`，nonce／fingerprint 在 `[56:64]`，8-byte auth key 在 `[74:82]`。
- SDK 4.3.8.1 使用 native tail Swap；auth key 的後兩 bytes 跨越 80-byte 邊界，
  不可沿用 Cubo pre-session 的 no-swap 路徑。
- 回覆 nonce／fingerprint 位於 `[188:196]`，status 位於 `[196:200]`。
  status 1／7 僅允許建立 IOTC，不能當成 AV 認證成功；5／6 為驗證拒絕。
- DTLS record 的外層是 28-byte IOTC header，payload 最大 1388 bytes。
  flag bit 0 設定時僅轉換前 64 bytes，其餘保持原樣。
- 後續每個封包固定 IP/port，並驗證完整 nonce／fingerprint；keepalive 回覆 0x0427、
  session close 0x0417。

### 認證

Java `stream/TUTKClient.java` 的 `connectToDevice` 使用
`IOTC_Connect_ByUIDEx(authenticationType=0, authKey=...)`；
`getAVClientStartInConfig` 最後設定 `security_mode=AUTO(2)`、`auth_type=0`、channel 0。
`utils/TUTKUtils.java:getConfigValue` 依韌體選擇 app 內的 default profile，
也支援 `TUTKAuthConfig.newAuthKey/newPassword`。沒有使用 `newAvToken` 作本次登入。

本機測試觀察：依 `1.006.25` 選出的 current auth key 被 status 5 拒絕；
legacy auth key 則 status 1，legacy 密碼完成 DTLS 與 AV 驗證。
原因尚未由設備端原始碼證明；不把 App 的版本分支當成設備實際憑證的保證。

DTLS identity 為 `AUTHPWD_` 加帳號。PSK 為密碼的 SHA-256 原始 32 bytes；
原生程式使用 C `strncpy(...,32)`，因此遇到第一個 NUL 後剩餘部分填零，
實作依此重建。使用已安裝的 OpenSSL 3.5.9；與
[OpenSSL datagram BIO](https://docs.openssl.org/3.5/man3/BIO_s_dgram_pair/) 和
[PSK callback](https://docs.openssl.org/3.0/man3/SSL_CTX_set_psk_client_callback/) 的公開 API 整合。
沒有把原廠 `.so` 當作可執行依賴。

DTLS 內的 AV primary login 為 570 bytes；resend companion 為 572 bytes，token 加 1。
Grant 的非零 status 不接受；token 不符的回覆不接受。

### 影像

活動路徑 `VideoThreadRunnable.java:113` 呼叫 `avRecvFrameData2` 並指定 16-byte info；
`:211` 以 H.264 NAL 判斷 IDR。Live AU tail 與此相符。另一個 Java `AVFrame` 的
24-byte 型別不代表這台設備的串流 trailer。

實測 trailer：codec `0x004e`、timestamp 位於 offset 12，為 32-bit 毫秒值。
metadata keyframe bit 在 P-frame 上也為 1，故實作必須以 NAL type 5 判斷真正 IDR。
獨立的 SPS/PPS 不會讓丟失影格後的 GOP 恢復輸出。

## Evidence ledger

完整本機檔：`artifacts/pixsee/rea-evidence.json`。下列 ID 為真實 REA 回傳；
LLVM/JADX 補充分析與 live JSON 不冒充 REA Evidence。

| 項目 | REA Evidence ID | 範圍／限制 |
|---|---|---|
| XAPK inventory | `ev_ecc20b538c2999549b54cfaae386ab1ed7a6b28acddcf41eae5614742f1b7d6e` | ZIP entries；不等於程式語意 |
| ARM split inventory | `ev_bf81b7805f074802378262330346a66ecf8c461eb946fe925162a58b5c15c7db` | 20 occurrences；靜態封裝資訊 |
| LAN search symbols | `ev_905f3cd2d761f4f70e74a38bf6de49ca5c205a4f1798d00ad9b8ffd4135cf516` | Hopper static names |
| LAN request builder 0x14124 | `ev_5554d0bd85a179633ac5d65aa90f60e9cd7ac7cd593f0e07e9f2548d4b6e990e` | Pseudocode，欄位再由 assembly 核對 |
| Connect ByUIDEx | `ev_d850ef2d87bc240b9df09f2cbf3f2e5ba481dba8dead38c6c14d8bbf82d06307` | 靜態 auth input 路徑 |
| IOTC inner assembly | `ev_0bea12c9547e6b8814aa8678d26fab8ef5881d4e41f8cdefc939993724ccf57f` | Hopper 已分析部分；補充 LLVM Thumb |
| DTLS identity helper assembly | `ev_1ee8238e2a75378bc2b6703754ebaa2d24b74af482fb770d37141f0c55b65b3c` | 0x1dfb0，format literals 另以 bytes 核對 |
| DTLS PSK helper | `ev_cbdf4ed1c4d7f43bf64502e95b40f69400d315d56eae77b8fdd6901c544ec711` | 0x1dff4，SHA256／strncpy |
| Client DTLS creation | `ev_d299658183dcf4a9515581ca478e27705dde1718ef2610aff27a88316b5b4d7f` | PSK callback 與 channel setup |

補充 notes：`artifacts/pixsee/discovery-analysis/README.md`、
`artifacts/pixsee/av-analysis/README.md`。原始探索／登入回覆可能包含 UID，
僅保留在 ignored 本機 artifacts，報告與測試 fixtures 不放入真實裝置 UID。

Live 驗證檔：

- `validation-summary.json`：結果、輸出與 Evidence SHA-256。
- `dtls-live.json`：成功握手的收發長度／record type，不含 PSK。
- `final-stream.log`：30 秒串流與輸出／丟棄影格統計。
- `final-ffprobe.json`、`final-decode.log`：影片資訊及解碼結果。
- `tests-final.log`：57 tests passed。
- `pixsee-2026-11-12.ts`、`pixsee-2026-11-12.mp4`：本機測試錄影。
