# amane ワイヤプロトコル v1

UDPベースのマルチパストンネル。1クライアント=1論理セッションがN本のパス
(物理インターフェース×サーバendpoint)を持ち、パケット単位で分散する。

## ハンドシェイク

- **Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s**(WireGuardと同構成、prologue = `"amane v1"`)
- クライアント(イニシエータ)はサーバの静的公開鍵を事前に知っている。1-RTT。
- PSK未設定時は全ゼロPSKで psk2 として動作(プロトコル名を固定するため)。
- サーバは未知の静的鍵からの HandshakeInit に**無応答**(ステルス)。
- HandshakeInit ペイロード: `version(1) + client_seed(32) + timestamp_ns(8)`。
  timestamp はピアごとに単調増加を要求(ハンドシェイクリプレイ防止)。
- HandshakeResp ペイロード: `server_seed(32) + server_session_id(4)`。
- ハンドシェイクはそのとき最良のパス上で行い、レート制限(トークンバケット)で
  DoS を緩和。WireGuard式 cookie は将来項目。

## 鍵スケジュール

```
prk = HKDF-Extract(BLAKE2s, ikm = client_seed ‖ server_seed, salt = handshake_hash)
key(dir, path) = HKDF-Expand(prk, "amane-v1 " + dir + " path " + path_id)   # dir ∈ {c2s, s2c}
```

両シードは Noise ハンドシェイク暗号で保護される(msg1 は es、msg2 は ee+se)。
エポック秘密は両シードを要するため前方秘匿性はエフェメラルDHに依存する。
パス×方向ごとに独立した ChaCha20-Poly1305 鍵・nonce空間・リプレイウィンドウを持つ。

- **rekey**: 既定120秒ごとにクライアント発で新ハンドシェイク。旧エポックは
  90秒間**受信のみ**受理。サーバは新エポックでの最初の正当な受信(鍵確認)まで
  送信を旧エポックで継続する。global_seq はエポックをまたいで継続。

## パケットフォーマット

外部ヘッダ 16B(AEADのAD):

| offset | size | field |
|---|---|---|
| 0 | 1 | type (1=HsInit 2=HsResp 3=Data 4=Probe 5=PathInit 6=PathAck 7=Close) |
| 1 | 1 | path_id (最大32パス) |
| 2 | 2 | reserved |
| 4 | 4 | session_id (LE; 受信側が採番した receiver index) |
| 8 | 8 | counter (LE; パス×方向ごとの送信カウンタ = AEAD nonce 下位64bit) |

Data 平文(AEAD内部): `global_seq(48bit LE) + flags(1) + reserved(1) + 内部IPパケット`
- `flags bit0 = duplicate`(redundantモード送信。サーバはこれを見てクライアントの
  モードを下り方向にミラーする)
- global_seq が暗号化内部にあるのはトラフィック解析耐性のため。
- リプレイ防御: RFC 6479 方式スライディングウィンドウ(幅2048)/パス×エポック。

オーバーヘッド: 外部ヘッダ16 + 内部ヘッダ8 + AEADタグ16 = **40B**(+外側IP/UDP 28B)。
既定TUN MTU 1400。

## パス管理

- **PathInit/PathAck**: パス鍵での復号成功がセッション鍵所持の証明になるため、
  パス追加に再ハンドシェイク不要。ペイロードは `magic(4) + timestamp_us(8)`。
  クライアントは PathAck を受けるまで1秒間隔で再送。
- **roaming**: 復号成功したパケットの送信元が変われば endpoint を即時更新
  (LTEのNATリバインド・アドレス変更に追従)。
- **Probe**(既定200ms、AEAD保護でDataと区別不能): キープアライブ兼品質測定。
  - RTT: monotonicタイムスタンプのエコー + 相手処理遅延の申告(時計同期不要)
  - ロス率・デリバリーレート: 累積受信カウンタ(データ+制御パケット両方を計上。
    無通信時もロス推定が陳腐化しない)。窓に20パケット貯まるまでアンカーを
    進めない(プローブのみでも約4秒ごとに更新)。
- **状態機械**: probing → active ⇄ degraded → down → (revive) active
  - down: 無受信が probe_interval×5 継続
  - down中も5倍間隔でプローブ継続、3回連続受信で復帰(スロースタート)
  - degraded: ロス>10% または sRTT>1s が15チェック(3秒)持続。回復はロス<5%で即時

## スケジューラ

- **bonding**: ストライド・スケジューリング(バイト重み付き公平)。
  重み = 推定容量[bytes/s]:
  - ロス>2% かつ 稼働率≥50%: `w = 0.95 × 実測デリバリーレート`(飽和時の実測は
    容量の直接証拠 — 双方向スナップで数秒収束)
  - ロス>2% かつ 低稼働(TCP等の弾性トラフィックがバックオフした場合): `w ×= 0.7`
  - ロス<2% かつ デリバリー≥0.9w: `w ×= 1.05`、さらに `w = max(w, delivery)`
  - sRTT > 3×minRTT(bufferbloat): `w ×= 0.85`
  - 最速パス+150ms超のパスは実効重み50%に制限
- **redundant**: 全activeパスへ複製。受信側は global_seq ビットマップで重複排除。
  サーバは duplicate フラグを観測してセッション単位で自動ミラー(5秒観測なしで
  bondingへ復帰)。
- **fec**: パス選択はbondingと同一。FEC層(下記)がReed-Solomonパリティを追加する。
  データパケットの `flags bit1 (fec)` をサーバが観測して下り方向も自動ミラー。

## FEC(Reed-Solomon、mode = "fec")

bonding(保護なし)とredundant(帯域2倍)の中間: 再送RTTを待たずにバースト損失を
回復しつつ、オーバーヘッドは設定可能な10〜40%程度に抑える。

- **系統的符号**: データパケットは無変更で流れ、パリティパケット(type=8)だけが
  追加される。無損失時は受信側のFEC処理コストゼロ。
- **グループ**: 連続する global_seq の K 個(既定10、`fec.group`)を1グループとし、
  R 個のパリティを生成。**Kに満たないまま `fec.flush_ms`(既定8ms)経過したら
  その本数で締める**(低ビットレート時の遅延上限)。seq不連続でも即締め。
- **パリティのシャードは内側IPパケットのみ**を対象にゼロパディング
  (シャード長=グループ内最大パケット)。FECヘッダは8B=データの内部ヘッダと
  同サイズなので、**パリティが最大データパケットを超えることはなく、MTU計算は
  変わらない**。復元後の長さはIPヘッダ自身から、seqは `base_seq+index` から回復
  (全入力はAEAD認証済みなので信頼できる)。
- **パリティヘッダ(AEAD内部)**: `base_seq(48bit) + K(4bit)|R(4bit) + index(4bit)`。
  K, R ≤ 15。
- **適応パリティ数**: `fec.parity = 0`(既定)なら実測ロス率から
  `R = 1 + round(K × 2 × loss)`(上限4)。固定値も指定可。
- **パス分散**: パリティはそのグループのデータを最も運ばなかったactiveパスへ
  優先配置(パス単位バースト損失との相関を最小化)。
- **受信側**: 直近256seq分のデータパケットをシャード候補として保持。パリティ到着
  時に不足分が解けるなら復元し、リオーダバッファへ通常受信と同様に注入
  (重複排除が二重配送を吸収)。
- 実測(netns、両リンク5%ロス、15Mbps UDP): 残留ロス 0.5%(素の1/10)、
  オーバーヘッド約23%。redundantなら100%増で往復2.25%相当。

## リオーダリングバッファ

L3トンネルなので順序保証はしない方針(「待ちすぎない」):
- global_seq リングバッファ(8192)。ギャップは動的タイムアウト
  `clamp(パス間sRTT差 + 4×max rttvar, 10ms, max_reorder_delay=100ms)` まで待って諦める。
- 諦めた後に届いた遅延パケットは**破棄せず即時通過**(late pass)。
- 溢れ(4096保持 or リング範囲超)は最古ギャップを即諦める。

## 既知の制限(ロードマップ)

- TCPの弾性トラフィックはRTT差のあるパス束ね上で性能が出にくい
  (MPTCP相当のパス別輻輳制御は将来項目)。主用途のCBR/UDP系(SRT等)は良好。
- OpenWrt ipk、Web UI、TCP/QUICフォールバック、cookie DoS対策、
  パスごとPMTUD、全パスdown時の送信キューは M6 以降。
