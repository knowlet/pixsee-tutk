# RTSP／ONVIF gateway：研究與實作決策

研究日期：2026-11-12，Asia/Taipei。實作基底：`35688d98975b702acad75b6321d107f8c34f8591`。
目標為 Home Assistant／Frigate、NAS／NVR、VLC 與 Scrypted 的區網影音接入。
本文件在首次實作修改前建立；後續驗證結果另列，不能把上游功能描述當成本次驗收。

## 決定

直接使用 MediaMTX v1.21.3 作 RTSP TCP／UDP 與 HLS 伺服器。
沿用 Python 的 `stream --audio`，由 FFmpeg 保留 H.264 影像並轉送至本機 RTSP publisher；
一個攝影機連線供多個讀取端共用。新增 Python ONVIF Device／Media、JPEG 快照與
WS-Discovery 轉接層，回報實際串流資料，不宣稱完整 Profile S／T 認證。

監督程式一起重啟失敗或停止輸出媒體的 producer／publisher，保留 MediaMTX；
相機憑證與觀看端憑證分離。預設只監聽 loopback，對外監聽需明確指定地址與觀看帳密。
ONVIF 的設定變更、PTZ、事件、標準雙向對講尚不在此介面範圍；原有 `talk` CLI 保留。

執行驗證後的修正：最初規劃影音皆使用 `-c copy`，但 MPEG-TS／ADTS 輸入在
RTSP 寫入標頭時缺少 AAC extradata，單加 `aac_adtstoasc` 未能解決。
最終發布參數改為 `-c:v copy -c:a aac -ar 8000 -ac 1 -b:a 24k`：影像仍不重新編碼，
音訊在閘道重新編碼為 AAC、24 kb/s、8 kHz、單聲道。

## 候選比較

| 候選 | 已核對來源／授權 | 採用判斷 |
|---|---|---|
| MediaMTX v1.21.3 | 固定 commit `9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc`，MIT | 直接使用獨立執行檔；提供成熟的 RTSP、驗證、多客戶端與 HLS，無 ONVIF server |
| go2rtc | 固定 commit `990f4de3cc21d1cca917d02d0bc40f2fabe75a49`，MIT | 已讀 exec 與 ONVIF server；RTSP 只支援 TCP，ONVIF profile 固定 1080p／30 fps、缺音訊與探索 responder，不採作此次完整轉接層 |
| onvif_simple_server | 固定 commit `18651b4a145606db3126ce520b797a3c1f799be0`，GPL-3.0 | C／CGI＋額外 daemon，偏向嵌入式 Linux；僅參考架構，不複製程式或模板進 MIT 專案 |
| GStreamer RTSP server | 官方函式庫文件、LGPL framework | 需要額外 framework、plugins 及 host code；文件層篩選後不採用，未聲稱做過原始碼驗證 |

實際研究使用 GitHub connector、官方文件與本機程式碼；查詢同時涵蓋 RTSP 發布／驗證、
ONVIF server／discovery，以及 Scrypted client bootstrap。沒有使用 XERJ。

## 實際閱讀與介面契約

- [MediaMTX 設定](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/mediamtx.yml)、
  [驗證管理](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/internal/auth/manager.go)：
  明確覆蓋匿名預設；loopback publisher／reader／API 與外部僅讀使用者分開。
- [MediaMTX path API](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/internal/api/api_paths.go)、
  [path 狀態](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/internal/core/path.go)：
  `online`、`available`、`tracks2` 與持續增加的 `inboundBytes` 區分伺服器存活和媒體進度。
- [MediaMTX lifecycle](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/internal/core/core.go)：
  macOS 先以 SIGINT 關閉，再有界限地終止、回收子程序。
- [go2rtc exec](https://github.com/AlexxIT/go2rtc/blob/990f4de3cc21d1cca917d02d0bc40f2fabe75a49/internal/exec/exec.go)、
  [ONVIF server](https://github.com/AlexxIT/go2rtc/blob/990f4de3cc21d1cca917d02d0bc40f2fabe75a49/pkg/onvif/server.go)、
  [discovery helper](https://github.com/AlexxIT/go2rtc/blob/990f4de3cc21d1cca917d02d0bc40f2fabe75a49/pkg/onvif/helpers.go)：
  僅作設計比較；不使用固定 profile，也不將 client Probe 誤認為裝置探索 responder。
- [onvif_simple_server media](https://github.com/roleoroleo/onvif_simple_server/blob/18651b4a145606db3126ce520b797a3c1f799be0/media_service.c)、
  [discovery daemon](https://github.com/roleoroleo/onvif_simple_server/blob/18651b4a145606db3126ce520b797a3c1f799be0/wsd_simple_server.c)：
  僅參考服務拆分；本專案依標準獨立實作 Python 介面，不複製 GPL 程式。
- [Scrypted ONVIF plugin](https://github.com/koush/scrypted/blob/6edeec1b8fc1c7768e8b2f53d62affd7f2a0b62d/plugins/onvif/src/main.ts)
  及其 node-onvif 0.7.4：使用 WS-Security PasswordDigest，先查時間、服務，再查 profiles、
  video sources 與裝置資料。AAC 的 bitrate 使用 kb/s、sample rate 使用 kHz。
  Scrypted 需關閉自動調整攝影機編碼與 ONVIF events；本階段沒有這些可寫介面／事件來源。

## 標準依據與驗證範圍

- [ONVIF Core](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)、
  [Media](https://www.onvif.org/specs/srv/media/ONVIF-Media-Service-Spec.pdf)：
  SOAP 1.2、Device／Media1 namespaces、真實 capabilities、有效 profile token、MediaUri lifetime。
- [WS-Discovery 2005/04](https://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf)：
  Hello／Bye、Probe／Resolve、Types／Scopes 匹配、MessageID／RelatesTo／AppSequence；
  明確選定 IPv4 interface，保留穩定 UUID 與遞增 restart instance ID。
- [OASIS UsernameToken](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-UsernameTokenProfile-v1.1.1-os.html)：
  PasswordDigest、nonce／Created freshness、重送防護；HTTP Digest 用於相容的 SOAP／JPEG clients。

驗證將包含真實 MediaMTX＋FFmpeg 的合成影音 TCP／UDP 解碼、HLS 與 JPEG、獨立 ONVIF
client bootstrap、探索封包、正反驗證、並行讀取、斷線重連、停止後的資源清理，及指定攝影機實測。
產品自己的 UI／NVR 驗收與 ONVIF 認證另列，不由單元測試或上游測試結果代替。

## 授權與分發

MediaMTX 為獨立使用的 MIT 元件；本專案不提交其 binary 或 FFmpeg binary。
本機 FFmpeg 實際 build 另有 GPL／version3 選項，若未來重新分發需另外核對該 build。
現有 MIT 授權與上游來源通知保留。
