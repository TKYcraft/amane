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

## パスごとPMTUD(RFC 8899 DPLPMTUD方式)

パスごとに「実際に通る」最大ワイヤMTUを、ICMPに依存せず実測する。

- **プローブ**: type=9 (MTUProbe)。`id(4)+size(2)` +ゼロパディングで外側IPパケットを
  目標サイズちょうどに合わせ、DF付きで送る。受信側は小さな type=10 (MTUAck) で
  idをエコー(ACKは小さいので逆方向MTUの影響を受けない)。往復成功=そのサイズが
  通る証明。ICMP不要なので、ICMPを落とす網や無通知ドロップ(veth等)でも機能する。
- **探索**: まず天井(ローカルIF MTU)を試す(非制約なら1プローブで完了)→
  失敗なら 1200 → 576 で下限を確保 → 二分探索(粒度8B、タイムアウト1秒×3回/サイズ)。
  576も通らないパスは dead(データ配分停止、制御パケットのみ)。10分ごとに再検証、
  ソケット再作成・endpoint変化(roaming)時は即再探索。
- **DF常時付与**: 全ソケットで DF を立てる(Linux: `IP_PMTUDISC_PROBE`、
  macOS: `IP_DONTFRAG`)。従来サイレントに断片化して通っていた経路では、代わりに
  ドロップ→PMTUDが検出→迂回・警告ログという挙動になる(意図した変更)。
- **結果の利用**: `maxInner = wireMTU - 68(v4)/88(v6)` を超える内側パケットは
  スケジューラがそのパスに割り当てない(bonding/redundant/FECパリティすべて)。
  小さいパケットは制約パスも使い続ける。TUN MTUの動的変更はしない(既存TCPフローの
  MSSと衝突するため)。`amane status` のMTU列に表示("-"=未発見、"!"=dead)。
- **ICMP PTBフォールバック**: 内側パケットがどのパスの `maxInner` にも収まらない
  とき、amane は内側送信元へ ICMP Fragmentation Needed (v4 type=3 code=4、
  next-hop MTU = 全パスの `maxInner` 最小) または ICMPv6 Packet Too Big
  (v6 type=2、MTU = 同値) を合成して自TUNへ書き戻す。カーネルが受け取り、
  内側TCPソケットのPMTUキャッシュを更新させる→次セグメントから収まるサイズで
  送られる。これが無いと TUN MTU 固定方針のもと、縮退パス上の TCP バーストが
  サイレントドロップ(dropNoPath)で停滞する(いわゆる PMTU ブラックホール、
  SSHは通るのに tmux の大画面再描画で壊れる症状)。
  - 返送元: 元の内側パケットの宛先アドレスをそのままICMPの送信元に流用する
    (トンネル端点自身は内側サブネットで固有IPを持たず、自分自身のアドレスを
    送信元にするとカーネルがエラー配達を拒否するため)。
  - 制約: 内側がICMPエラー自身・IPv4で非初頭フラグメント・DF未セット・v4送信元が
    multicast/link-local/0.0.0.0 の場合は送らない(ICMP増殖防止・RFC 1191 準拠)。
  - レート制限: 内側送信元ごとにトークンバケット(4/秒、burst 8)。
  - 統計: `amane status --json` の `sessions[].icmp_ptb_sent`。
  - トグル: `[tuning] notify_too_big = false` で無効化可能(既定は有効)。
- **ロス統計の非汚染**: MTUプローブ/ACKは探索中に落ちて当然のパケットなので、
  両側ともロス・帯域推定のカウンタから除外している(片側だけ数えるとロス率が歪む)。
- 実測(netns、ルータ区間のみMTU 1300): 上下方向とも粒度内で発見、フルサイズUDPは
  制約パスを自動回避してロス0%(PMTUDなしなら約半分がブラックホール)。

## DiffServ マーキング(DSCP)

外側UDPパケットの IPヘッダ ToS / Traffic Class バイトの上位6bitに DSCP
code point を乗せる。`[client] dscp = "ef"` または `[server] dscp = "ef"` で
有効化。シンボル名(RFC 2474/4594)または 0..63 の整数で指定。既定 `be`。

### 実装
- socket オプション 1 本: Linux `IP_TOS` / `IPV6_TCLASS`、macOS 同名。
  実際にバイトに書く値は `dscp << 2`(下位2bitはECN用)。
- 全パスの outer UDP socket(クライアント per-path)と server listen socket に
  同じ値を適用。fast path のオーバーヘッドは無し。

### 効くか効かないか

経路上の各ノード(ルータ/スイッチ/ISPコア)が「DSCPを見て優先キューに振る」
設定になっている場合にのみ効く。amane 自身は L3 ヘッダに書くだけ。

- **効くことがある**: 家庭用ルータのローカル QoS、企業LAN、法人閉域WAN、
  一部 ISP のコア、データセンタ内 L3 スイッチ
- **効かない**: 日本の 4G/5G 一般APN(docomo/au/SBM の spmode/au-net/plala等)
  — P-GW/UPF で剥がす or 無視するのが通例。QCI/5QI による
  キャリア側ベアラ分類が優先される
- **悪影響の可能性**: 稀に ISP が「ユーザが EF を立てていい権限は無い」と
  判定し、むしろ shaping キューに落とす。本番前に実経路で切り替え比較を推奨

### 値の意味

RFC 2474/4594 の標準コードポイント。カッコ内は実際に TOS バイトの上位6bit
に書かれる 10進 DSCP 値。

| 名前 | 用途 | 値 |
|---|---|---|
| `be` / `cs0` | Best Effort。無指定と同じ | 0 |
| `ef` | Expedited Forwarding。最低遅延/最低ロス待遇、VoIP の標準値 | 46 |
| `af41` | Assured Forwarding クラス4-1、インタラクティブ映像。EFよりドロップ耐性寄り、帯域取りやすい | 34 |
| `af42` / `af43` | 同クラス、輻輳時のドロップ優先度が1段/2段上がる | 36 / 38 |
| `af31`-`af33` | 放送映像(非対話) | 26 / 28 / 30 |
| `af21`-`af23` | 低遅延データ(短トランザクション) | 18 / 20 / 22 |
| `af11`-`af13` | 高スループット・遅延許容(大容量転送) | 10 / 12 / 14 |
| `cs1` | Lower-than-BE / Scavenger。空き帯域を拾う。バックアップ・BG同期 | 8 |
| `cs4` | Realtime Interactive。AF41の前身 | 32 |
| `cs5` | 放送映像(旧式。AF3x相当) | 40 |
| `cs6` / `cs7` | Network Control(ルータ間制御専用)。ユーザアプリでの使用は非推奨 | 48 / 56 |
| `voice-admit` | VoIP admission control (RFC 5865) | 44 |

### 選び方(amane 用途)

- ライブ配信(SRT/業務映像など): **`ef`** または **`af41`** が順当
  - `ef` はキュー最優先だが輻輳時にはドロップ扱い。超低遅延で量が少ない音声・制御向け
  - `af41` は映像バースト向け。EFよりドロップに強く、帯域確保寄り
- 法人閉域で DSCP ポリシーが決まっている場合は**その指示に従う**(別クラスを
  指定するとかえって低優先キューに回される)
- 一般ISP経由でよくわからない場合は **`ef`** から試して、スループット・遅延に
  変化が無ければ既定(`be`)で問題無い

## リンクごとの公開IP/ASN表示(client のみ)

`amane status` に、各リンクが**実際に外に出ている公開IPとASN**を表示する。
クライアント起動時に自動的に有効(設定は不要)。

- **仕組み**: クライアントがリンクごとに TCP ソケットを `SO_BINDTODEVICE`(Linux)
  / `IP_BOUND_IF`(macOS)でそのインターフェースに縛って、`https://ip.alicey.dev`
  へ HTTPS GET。レスポンスは
  `{"ip":..., "asn":..., "asOrganization":..., "country":...}` を期待
  (他のフィールドは無視)。各リンク別に独立に走るので、同じサーバを
  叩いていても到着する公開IPがリンクごとに異なる(=キャリアごとに違う)
- **User-Agent**: `amane/<version>`(ビルド時の VERSION)。lookup サーバ側で
  バージョン別アクセス数を集計できる
- **タイミング**: 15秒ごとのスイープで、WAN info 未取得の Active パスにのみ
  フェッチ。一度成功すればパス消滅または rebind(DHCP renumber, roaming)で
  クリアされるまで再取得しない — IF が変化しないなら公開IPも変わらない前提
- **タイムアウト**: dial 3秒 + TLS 3秒 + total 5秒
- **プライバシ**: amane のクライアント公開IPが `ip.alicey.dev` に送られる
  (当該ホスト側で aggregate 利用統計取得のため)
- **サーバ側**: 対象外(リレーサーバのWANは単一・既知のため)

status 表示例:
```
PATH IF         WAN                                      STATE   ...
0    wwan0      198.51.100.10 AS64500 ExampleTelecom     active  ...
1    wwan1      203.0.113.42 AS64501 OtherCarrier Inc.   active  ...
```

## 既知の制限(ロードマップ)

- TCPの弾性トラフィックはRTT差のあるパス束ね上で性能が出にくい
  (MPTCP相当のパス別輻輳制御は将来項目)。主用途のCBR/UDP系(SRT等)は良好。
- OpenWrt ipk、Web UI、TCP/QUICフォールバック、cookie DoS対策、
  全パスdown時の送信キューは M6 以降。
