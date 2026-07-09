# amane

複数のモバイル回線(LTE/5G/Wi-Fi)を束ねて1本の安定した回線にする、
マルチパス回線ボンディングトンネル。屋外イベントのライブ配信のように
「単一キャリアでは帯域も安定性も足りない」場面のための、
セルフホスト型・WireGuard風のツールです。

```
[クライアント]                                  [リレーサーバ]
   TUN (10.77.0.2)                                TUN (10.77.0.1)
    │ パケット単位で分散                           │ 並べ替え・再構成
    ├─ LTE #1 ──┐                                 │
    ├─ LTE #2 ──┼── 暗号化UDP(Noise IKpsk2) ──→ ├─→ NAT → インターネット
    └─ Wi-Fi ───┘                                 │   (単一のグローバルIP)
```

- **帯域集約**: パス品質(RTT/ロス/実測レート)を常時プロービングし、
  重み付きストライドスケジューラで分散。20+30Mbpsの2回線で単一回線の**1.64倍**の
  実効スループット(netns統合テスト実測)。
- **フェイルオーバー**: 回線断を約1秒で検知して残りの回線へ即時再配分。
  復帰も自動(統合テスト実測: 10Hz ping 219発中欠落9)。
- **冗長モード**: 全回線に同一パケットを複製し受信側で重複排除。
  片側15%ロス×2回線でもpingロス約3〜5%(単一回線なら往復28%相当)。
- **FECモード**: Reed-Solomonパリティで再送なしのロス回復。両回線5%ロスでも
  残留ロス0.5%(素の1/10)、オーバーヘッドは約20%(冗長モードは100%)。
  ロス率に応じてパリティ数を自動調整。
- **パスごとPMTUD**: 回線ごとの実効MTUをICMP非依存で自動計測(RFC 8899方式)し、
  通らないサイズのパケットをそのパスから自動迂回。MTU黒穴による
  「小さいパケットは通るのに配信だけ死ぬ」を構造的に回避。
- **WireGuard風の運用感**: base64鍵ペア+TOML設定1枚。Noise_IKpsk2による
  公開鍵認証、未知の鍵には無応答(ステルス)、120秒ごとの自動鍵ローテーション。
- **クロスプラットフォーム**: サーバ=Linux(Rocky等)、クライアント=macOS/Linux。
  純Go・cgo不使用の単一バイナリ(OpenWrt/GL-MT3000向けarm64ビルド対応)。

## クイックスタート

```sh
# 手軽に1バイナリ
go build -o amane ./cmd/amane

# リリース同等の全ターゲット同時ビルド (Docker必要、CIと同じ手順)
make dist            # -> dist/build/amane-{linux,darwin}-{amd64,arm64} + SHA256SUMS

# [サーバ側] 鍵生成 — 表示される公開鍵をクライアントの client.toml (server_public_key) へ
amane genkey | sudo tee /etc/amane/server.key | amane pubkey

# [クライアント側] 鍵生成 — 表示される公開鍵をサーバの server.toml ([[peer]].public_key) へ
amane genkey | sudo tee /etc/amane/client.key | amane pubkey

# サーバ (グローバルIPのあるLinux)
sudo amane server -c server.toml

# クライアント (macOS / Linux)
sudo amane client -c client.toml

# 状態確認
amane status --watch
```

秘密鍵(`*.key`)は生成したマシンから外に出さず、**公開鍵の文字列だけ**を相手の設定に書きます。
詳しい配置は [docs/deploy.md](docs/deploy.md) の配置マトリクスを参照。

設定例は [docs/examples/](docs/examples/)、詳しい手順は [docs/deploy.md](docs/deploy.md)、
プロトコル仕様は [docs/protocol.md](docs/protocol.md) を参照。

```
$ amane status
SESSION  server → relay.example.com:51820   state=up  mode=bonding  key_age=34s
PATH IF         ENDPOINT               STATE     RTT      LOSS   TX         RX         WEIGHT
0    en10       203.0.113.7:51820      active    41.2ms   0.1%   18.3Mbps   1.1Mbps    41%
1    en12       203.0.113.7:51820      active    61.1ms   0.0%   26.7Mbps   0.6Mbps    59%
REORDER  timeout_flush=0  late_pass=0  dup_drop=0  buffer=0pkt/0ms
```

## コマンド

| コマンド | 説明 |
|---|---|
| `amane server -c <toml>` | リレーサーバ起動 |
| `amane client -c <toml>` | クライアント起動 |
| `amane genkey` / `amane pubkey` | 鍵の生成・公開鍵導出 |
| `amane status [--json] [--watch]` | パスごとの状態表示 |
| `amane link add <if> [mbps]` / `remove <if>` | リンクの動的追加・削除 |
| `amane mode <bonding\|redundant\|fec>` | スケジューリングモード切替(実行中に可) |

## テスト

```sh
go test ./...                                  # 単体テスト
go build -o /tmp/amane-lab/amane ./cmd/amane   # 統合テスト用バイナリ
sudo bash test/lab/scenario_basic.sh           # netns疎通 + iperf3
sudo bash test/lab/scenario_bonding.sh         # 帯域集約 (>1.6x)
sudo bash test/lab/scenario_failover.sh        # 回線断・復帰
sudo bash test/lab/scenario_redundant.sh       # 冗長モード
sudo bash test/lab/scenario_fec.sh             # FECロス回復
sudo bash test/lab/scenario_pmtud.sh           # パスごとMTU探索と迂回
sudo bash test/lab/scenario_rekey.sh           # 鍵ローテーション透過性
```

統合テストは network namespace + tc netem で複数WAN環境をエミュレートします(要root)。

## ロードマップ

- OpenWrt ipk パッケージ(GL-MT3000等)
- TCP/QUIC フォールバック(UDPが絞られる会場対策)
- Web UI、WireGuard式cookie DoS対策
- batched I/O (sendmmsg/recvmmsg) と TUNオフロード活用

## ライセンス

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0)