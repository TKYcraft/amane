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

## 2. 鍵生成(サーバ・クライアント両方で)

```sh
sudo mkdir -p /etc/amane
amane genkey | sudo tee /etc/amane/server.key >/dev/null   # サーバ側
sudo chmod 600 /etc/amane/server.key
amane pubkey < /etc/amane/server.key                        # 公開鍵を表示 → クライアント設定へ
```

クライアント側も同様に `client.key` を生成し、公開鍵をサーバの `[[peer]]` に登録。

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

## 7. ライブ配信での使い方(例: SRT)

トンネルは通常のL3経路なので、配信ソフトからはサーバのトンネルIP(またはサーバで
公開したポート)へ送るだけです:

```sh
# クライアント側 (OBS/ffmpeg): サーバのトンネルIPへSRT送信
ffmpeg -re -i input -c copy -f mpegts "srt://10.77.0.1:9000?latency=200"
# サーバ側で受けて配信基盤へ
```

冗長モード(`amane mode redundant`)は帯域より確実性を優先したい低ビットレート時や
本番切替の保険に使えます。

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
