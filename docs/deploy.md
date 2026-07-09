# amane デプロイ手順

## 1. ビルド

```sh
go build -o amane ./cmd/amane
# クロスビルド
GOOS=linux  GOARCH=amd64 go build -o dist/build/amane-linux-amd64  ./cmd/amane   # サーバ(Rocky等)
GOOS=darwin GOARCH=arm64 go build -o dist/build/amane-darwin-arm64 ./cmd/amane   # macOS (Apple Silicon)
GOOS=linux  GOARCH=arm64 go build -o dist/build/amane-linux-arm64  ./cmd/amane   # OpenWrt (GL-MT3000等)
```

cgo不使用の静的バイナリなので、コピーするだけで動作します。

## 2. 鍵の生成と交換

鍵ペアは**それぞれのマシンで生成**し、**公開鍵だけ**を相手の設定ファイルに書きます。
秘密鍵(`*.key` ファイルの中身)はマシンの外に出しません。

**サーバ側で:**

```sh
sudo mkdir -p /etc/amane
amane genkey | sudo tee /etc/amane/server.key >/dev/null
sudo chmod 600 /etc/amane/server.key
amane pubkey < /etc/amane/server.key     # ← 表示された文字列が「サーバ公開鍵」
```

**クライアント側で:**

```sh
sudo mkdir -p /etc/amane
amane genkey | sudo tee /etc/amane/client.key >/dev/null
sudo chmod 600 /etc/amane/client.key
amane pubkey < /etc/amane/client.key     # ← 表示された文字列が「クライアント公開鍵」
```

**配置マトリクス:**

| 生成物 | 置き場所 | 設定ファイルでの参照 |
|---|---|---|
| サーバ秘密鍵 (`server.key`) | サーバのみ | サーバ `server.toml` → `[server] private_key_file` |
| **サーバ公開鍵**(表示された文字列) | クライアントへ渡す | クライアント `client.toml` → `[client] server_public_key = "..."` |
| クライアント秘密鍵 (`client.key`) | クライアントのみ | クライアント `client.toml` → `[client] private_key_file` |
| **クライアント公開鍵**(表示された文字列) | サーバへ渡す | サーバ `server.toml` → `[[peer]] public_key = "..."` |

**任意: 事前共有鍵(PSK)** — 追加の防御層。こちらは公開鍵と違い**同じ内容を両側に**置きます:

```sh
amane genkey | sudo tee /etc/amane/psk >/dev/null && sudo chmod 600 /etc/amane/psk
# 安全な経路で相手にもコピーし、
#   クライアント: [client] preshared_key_file = "/etc/amane/psk"
#   サーバ:       [[peer]]  preshared_key_file = "/etc/amane/psk-unit1"
```

## 3. サーバ (Rocky Linux / RHEL系)

```sh
sudo cp amane /usr/local/bin/
sudo cp docs/examples/server.toml /etc/amane/server.toml    # 編集すること
sudo cp dist/amane-server.service /etc/systemd/system/
sudo systemctl enable --now amane-server
```

- UDP 51820 を開放: `sudo firewall-cmd --add-port=51820/udp --permanent && sudo firewall-cmd --reload`
- `[server.nat] enabled = true` なら ip_forward・nftables masquerade・MSSクランプは自動投入されます
  (専用テーブル `inet amane`、終了時に自動削除)。
- firewalld と併用する場合の手動設定:
  ```sh
  sudo firewall-cmd --add-masquerade --permanent
  sudo firewall-cmd --reload
  sudo sysctl -w net.ipv4.ip_forward=1
  ```
  この場合は `enabled = false` にしてください。

## 4. クライアント (macOS)

```sh
sudo cp amane /usr/local/bin/
sudo mkdir -p /etc/amane && sudo cp docs/examples/client.toml /etc/amane/client.toml  # 編集
sudo amane client -c /etc/amane/client.toml        # 手動起動(rootが必要: utun作成のため)
```

常駐させる場合:

```sh
sudo cp dist/dev.tkycraft.amane.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.tkycraft.amane.plist
```

- `links.auto = true` で Wi-Fi/USBテザリング/LTEドングルを自動検出します。
  仮想IFは `exclude` で除外してください(例に含めてあります)。
- USBドングルの抜き差し・アドレス変更には自動追従します。

## 5. クライアント (Linux / OpenWrt)

```sh
amane client -c /etc/amane/client.toml    # root または CAP_NET_ADMIN
```

systemd 環境では `dist/amane-client.service` を利用。OpenWrt ipk パッケージングは今後対応。

## 6. 運用

```sh
amane status            # パスごとの状態・RTT・ロス・帯域・重み
amane status --watch    # 1秒更新
amane status --json     # 監視システム連携用
amane link add en12 30  # リンクを手動追加(初期帯域ヒント30Mbps)
amane link remove en12
amane mode redundant    # 冗長モードへ切替(クライアント側で実行)
amane mode bonding
```

## 7. ルーティングパターン(何をトンネルに流すか)

クライアントのルーティングは2パターンあります。**ライブ配信が目的ならパターンAを推奨**します。

### パターンA(推奨): デフォルトルートは変えず、配信だけトンネルへ

`client.toml` の `routes` を**指定しない**(既定)。この場合トンネルに入るのは
トンネルサブネット(例 `10.77.0.0/24`)宛だけです。配信ソフトの送信先を
**サーバのトンネルIP(10.77.0.1)** にすれば、その通信だけが自動的に束ねられます。

- デフォルトルートを触らないので「amane自身の通信が吸い込まれる」問題が構造的に発生しない
- OS・他アプリの通信は今まで通り(会場Wi-Fiのcaptive portal等とも干渉しない)
- macOSでアプリ単位のポリシールーティングを組む必要もない

### パターンB: 全トラフィックをトンネルへ

`routes = ["0.0.0.0/0"]` を指定。既定経路の差し替えは `/1 + /1` 分割ルート方式
(0.0.0.0/1 と 128.0.0.0/1 を追加、WireGuardの定石)で行うため、**既存のデフォルト
ルートは消しません**。amane 自身のトンネル外側通信は、各WANソケットを物理
インターフェースへバインド(macOS: `IP_BOUND_IF`、Linux: `SO_BINDTODEVICE`)して
送出するため、/1ルートには吸い込まれずループしない設計です。
また `links.auto` は `utun*` 等を除外するので、自分のTUNをWANと誤認することもありません。

## 8. ライブ配信の推奨構成(OBS → YouTube 等)

YouTube Live のインジェストは RTMP / RTMPS / HLS / DASH のみで、**SRTでの直接
打ち上げはできません**(公式: ingestion-protocol-comparison)。一方、RTMP(S)=TCP を
そのままトンネルに通すと **TCPをRTT差のある複数パスで束ねると性能が出にくい**という
既知の制限に当たります(docs/protocol.md参照)。本トンネルが最も性能を発揮するのは
SRTのようなCBR/UDP系です。そこで LiveU/BELABOX と同じ2段構成を推奨します:

```
[OBS] --SRT(UDP)--> [amaneトンネル(束ね)] --> [リレーサーバ] --RTMP(TCP)--> YouTube
        10.77.0.1:9000宛                        サーバの安定回線から送出
```

**クライアント側(OBS):** 出力先を `srt://10.77.0.1:9000?latency=400` に設定
(パターンAならルーティング設定は不要)。SRTの `latency` はパス間RTT差+リオーダ
待ちを吸収するため **300〜500ms** 程度を推奨。

**サーバ側:** ffmpeg で SRT を受けて YouTube のプライマリ + バックアップ両方へ
`tee` muxer で同時送出(フェイルオーバー用。同じストリームキーを両サーバに送る):

```sh
ffmpeg -hide_banner -loglevel warning \
  -i "srt://10.77.0.1:9000?mode=listener&latency=400" \
  -c copy \
  -f tee "[f=flv:onfail=ignore:use_fifo=1]rtmps://a.rtmps.youtube.com/live2/<STREAM_KEY>|[f=flv:onfail=ignore:use_fifo=1]rtmps://b.rtmps.youtube.com/live2/<STREAM_KEY>?backup=1"
```

- `onfail=ignore` で片方の接続断が全体を巻き込まないようにする
- `use_fifo=1` で出力を独立バッファに切り離す(遅い側が他方に影響しない)
- バックアップURLの `?backup=1` は必須(YouTube側の識別用)
- 上り帯域は約2倍必要(1080p60 12Mbps なら 24Mbps + マージン)

この構成の利点:
- 束ねる区間はUDP(SRT)なので、bondingスケジューラの性能がフルに出る
- YouTubeから見た送信元はサーバの固定グローバルIP(回線切替の影響なし)
- SRT区間の再送・遅延吸収とamaneのマルチパスが役割分担する

RTMPを直接トンネルに通すことも可能ですが(パターンB + MSSクランプ自動適用)、
スループットは束ねた合計まで伸びないことがあります。確実性最優先の場面では
`amane mode redundant`(全回線複製)も有効です。

なお**SRTを直接受けられる配信先**(自前メディアサーバ、SRT対応CDN等)であれば、
2段構成にせずSRTを直接トンネル越しに打ち上げても問題ありません(UDPなので相性は
良好)。その場合は宛先がトンネル外IPになるため、パターンBにするか配信先IPを
`routes` に追加してください。ただしSRTの再送ループが全区間に伸びるため、必要な
`latency` は2段構成より大きめになります。

## 9. MTUの決め方

トンネルMTUは「**WAN経路のMTUの最小値 − 68**」に設定します(内訳: 外側IPv4 20 +
UDP 8 + amaneヘッダ/タグ 40)。既定値 1400 は WAN MTU ≥ 1468 を前提にしています。

| WAN経路MTU(最小のリンク) | 設定すべき `mtu` |
|---|---|
| 1500 (一般的なEthernet/光) | 1432 以下(既定1400で可) |
| **1460 (例: 一部のVPS/PPPoE)** | **1392** |
| 1400 台前半のモバイル網 | 1332 など、実測に合わせて |

- `mtu` は**クライアントとサーバの両方の toml で同じ値**に設定してください。
- サーバのNAT自動設定にはMSSクランプ(`rt mtu` 追従)が含まれるため、TCPは
  自動調整されます。UDP系(SRT等)はトンネルMTU以下のパケットしか通れないため、
  この計算が重要です。
- 「pingは通るのに特定サイト/配信だけ失敗する」場合はMTU黒穴を疑い、
  `mtu = 1280` まで下げて切り分けてください。
- **パスごとの実測MTUは `amane status` のMTU列**で確認できます(起動後十数秒で
  自動計測)。実測値が「設定MTU+68」未満のパスにはフルサイズのパケットが
  流れなくなる(自動迂回)ので、全パスで下回っている場合は設定 `mtu` を
  下げてください(警告ログも出ます)。

## 10. レイテンシ差と並べ替え待ちのチューニング

RTTの異なる回線を束ねると、受信側で「遅い回線のパケット待ち」が発生します。
amane は待ち時間を最小化するために次の仕組みを持っています:

1. **動的タイムアウト**: ギャップ待ちは固定値ではなく
   `clamp(パス間sRTT差 + 4×最大RTT分散, 10ms, max_reorder_delay_ms)` を都度計算。
   回線が均質なら数十msも待ちません。
2. **late pass**: 待ちを諦めた後に届いたパケットは破棄せず順序無視で即通過。
   IPは順序保証を要求しないため、上位(SRT等)の再送・並べ替えに委ねます。
3. **RTT差ペナルティ**: 最速パス+150ms(`max_rtt_spread`)を超える遅いパスは
   実効重みを半減し、そもそも遅延の混入を抑えます。

現場での調整指針:

- **低遅延最優先**: `[tuning] max_reorder_delay_ms = 30〜50` に下げる。
  順序乱れは増えるが、SRTの `latency` バッファが吸収する(SRT latency ≥
  パス間RTT差×2 + max_reorder_delay を目安に)。
- **極端に遅い回線を混ぜない**: 衛星回線(600ms)とLTE(40ms)のような組は
  集約効率が落ちます。`amane status` のRTT列を見て、外すなら `amane link remove`。
- **`amane status` の REORDER 行**が診断の手がかり:
  `timeout_flush` が多い=ロスまたは待ち時間不足、`late_pass` が多い=RTT差が
  タイムアウトを超えている、`buffer=NNpkt/NNms` = 現在の待ち行列。

## トラブルシューティング

- **ハンドシェイクが通らない**: サーバは未知の鍵に無応答です。公開鍵の対応
  (クライアント秘密鍵 → `amane pubkey` → サーバ `[[peer]].public_key`)を確認。
  UDPポートの開放、`server = host:port` のDNS解決も確認。
- **特定サイトだけ繋がらない**: MTU黒穴の可能性。`mtu = 1280` を試す。
  NAT自動設定にはMSSクランプが含まれますが、手動NATの場合は
  `nft 'add rule inet amane forward tcp flags syn tcp option maxseg size set rt mtu'` 相当を追加。
- **パスがdegradedのまま**: `amane status` のLOSS/RTTを確認。閾値は `[tuning]` で調整可能。
- **会場Wi-FiでUDPが絞られる**: サーバの `listen` を `0.0.0.0:443` に変える(または
  複数サーバ待受)。TCP/QUICフォールバックは今後対応。
