"""Seeded generators for the v5 code/log hard negatives (task RF-437128e9).

    python3 train/data/gen_codelog_v5.py            # prints the md5 of a fixed sample per kind and set
    python3 train/data/gen_codelog_v5.py --check    # exits 1 unless two runs give the same bytes

Benign tool output of the kinds coding and CI agents read: application logs in English and Vietnamese
(including Vietnamese log windows where one line repeats 2-30 times), stack traces (Python, Java, Go,
Node; English and Vietnamese messages), JSON and CSV in both languages, SQL (DDL, DML, migrations),
terminal sessions, and Vietnamese-commented source code. `build_v5.py` cuts ~256-token windows from the
units these functions return.

Every kind has three template sets with disjoint catalogs (services, messages, field names, formats):

    A  training (set A of build_v5.py: train + a 12% group-hash validation split)
    B  val_v5          (arm selection and calibration)
    C  val_v5_holdout  (never used for selection)

The catalogs were written for this file. They share no message, service list or seed with
eval/codelog/build.py or with the synthetic genres of bench/long/build.py, which are evaluation data
(train/tests/test_gen_codelog_v5.py checks the message catalogs against both). Only the standard library
is used, and every random choice comes from `unit_rng(kind, set, i)`, so the output is byte-identical
between runs and machines.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys

SEED = 43712895  # not the seed of eval/codelog (4764030) or bench/long (20261109)
SETS = ("A", "B", "C")


def unit_rng(kind: str, tset: str, i: int) -> random.Random:
    h = hashlib.sha256(f"{SEED}\x1f{kind}\x1f{tset}\x1f{i}".encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def ts_iso(r: random.Random, year=2025, tz="Z") -> str:
    return (f"{year}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:"
            f"{r.randint(0, 59):02d}.{r.randint(0, 999999):06d}{tz}")


MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def fill(r: random.Random, tpl: str, words: dict) -> str:
    """Format a catalog line: {n} number, {k} small number, {id} hex id, {f} file name, {w} catalog word."""
    return tpl.format(n=r.randint(10, 98765), k=r.randint(2, 12), id=f"{r.getrandbits(32):08x}",
                      f=r.choice(words["files"]), w=r.choice(words["words"]), u=r.choice(words["users"]),
                      ms=r.randint(3, 4800), pct=r.randint(1, 99), ip=f"172.{r.randint(16, 31)}.{r.randint(0, 255)}.{r.randint(1, 254)}")


# ---------------------------------------------------------------------------
# Log catalogs. Domains differ per set: A fulfilment, media transcoding, IoT fleet, mail delivery;
# B ledger and payroll; C clinic scheduling and freight.
# ---------------------------------------------------------------------------

LOG_EN = {
    "A": [
        "picked {n} items for wave {k} in zone {w}", "label printed for parcel PX{n}", "carrier pickup window confirmed for dock {k}",
        "transcode job {id} finished: 1080p h264 in {ms} ms", "thumbnail sprite generated for asset {n}",
        "segment {k} uploaded to origin bucket media-{w}", "device sensor-{n} reported battery at {pct}%",
        "firmware {k}.{k}.{n} rollout paused at {pct}% of fleet", "telemetry batch of {n} points accepted",
        "heartbeat missed from gateway gw-{id}, marking degraded", "smtp relay accepted message {id} for {u}",
        "bounce received for {u}: mailbox full", "dkim signature verified for domain {w}.example",
        "skipping already processed file {f}", "override applied: shipping class set to oversize for order {n}",
        "admin {u} rotated the signing key", "password reset link sent to {u}", "cron task purge-tmp removed {n} files",
        "connection pool resized from {k} to {n}", "retry budget exhausted for webhook {id}",
        "request to {ip} timed out after {ms} ms", "feature flag {w} enabled for {pct}% of users",
        "backfill of table shipments at {pct}%", "lock acquired on inventory row {n}", "ignored duplicate event {id}",
        "worker pool drained, {k} jobs remain", "cache warmup finished: {n} keys", "replica lag is {ms} ms",
        "rendered invoice {n} as PDF ({k} pages)", "geocoding fallback used for postcode {n}",
        "queue {w} paused by operator {u}", "batch commit of {n} rows took {ms} ms", "manifest {f} reloaded",
        "user {u} exported report {n}", "dead letter queue holds {n} messages", "disk usage on /var/lib/data at {pct}%",
    ],
    "B": [
        "journal entry {n} posted to ledger {w}", "reconciliation for account {n} matched {k} lines",
        "payroll run {id} computed for {n} employees", "tax table {k} loaded for fiscal year 2025",
        "fx rate refreshed: {k}.{n} for pair {w}", "standing order {n} scheduled", "overdraft limit reviewed for {u}",
        "statement {n} generated in {ms} ms", "skipped closed account {n}", "audit export {f} written",
        "settlement file {f} received from clearing house", "interest accrual job processed {n} accounts",
        "approval required for transfer {id} above threshold", "batch {k} of payslips mailed to {u}",
    ],
    "C": [
        "appointment {n} booked with dr. {u} for room {k}", "waitlist promoted patient ref {id}",
        "reminder sms queued for slot {n}", "shift roster published for ward {w}", "lab result {id} attached to visit {n}",
        "trailer TR-{n} departed depot {k}", "pallet {id} scanned at cross-dock {w}", "eta recalculated: {ms} s delay",
        "customs declaration {n} accepted", "temperature probe in reefer {k} reads {pct}", "route {w} re-optimised",
        "cancelled slot {n} released back to schedule", "proof of delivery {f} stored", "driver {u} clocked in",
    ],
}

LOG_VI = {
    "A": [
        "đã soạn {n} sản phẩm cho đợt lấy hàng {k} tại khu {w}", "đã in nhãn cho kiện hàng PX{n}",
        "xác nhận khung giờ lấy hàng của hãng vận chuyển tại cửa {k}", "chuyển mã video {id} xong: 1080p trong {ms} ms",
        "tạo ảnh xem trước cho tệp {n}", "đã tải đoạn {k} lên kho media-{w}", "cảm biến sensor-{n} báo pin còn {pct}%",
        "tạm dừng cập nhật firmware ở mức {pct}% thiết bị", "nhận lô dữ liệu đo gồm {n} điểm",
        "mất tín hiệu từ cổng gw-{id}, chuyển sang trạng thái suy giảm", "máy chủ thư đã nhận thư {id} gửi tới {u}",
        "thư bị trả lại cho {u}: hộp thư đầy", "bỏ qua tệp {f} vì đã xử lý trước đó", "bỏ qua sự kiện trùng lặp {id}",
        "ghi đè hạng vận chuyển thành hàng cồng kềnh cho đơn {n}", "quản trị viên {u} đã đổi khóa ký",
        "đã gửi liên kết đặt lại mật khẩu tới {u}", "tác vụ dọn thư mục tạm đã xóa {n} tệp",
        "thay đổi kích thước nhóm kết nối từ {k} lên {n}", "hết số lần thử lại cho webhook {id}",
        "yêu cầu tới {ip} quá thời gian sau {ms} ms", "bật cờ tính năng {w} cho {pct}% người dùng",
        "đồng bộ bảng vận đơn đạt {pct}%", "đã khóa dòng tồn kho {n}", "nhóm tiến trình đã xả hết, còn {k} việc",
        "làm nóng bộ nhớ đệm xong: {n} khóa", "bản sao chậm {ms} ms so với bản chính", "xuất hóa đơn {n} ra PDF ({k} trang)",
        "dùng địa chỉ dự phòng cho mã bưu chính {n}", "người vận hành {u} tạm dừng hàng đợi {w}",
        "ghi {n} dòng trong một lô mất {ms} ms", "nạp lại tệp kê khai {f}", "người dùng {u} tải báo cáo {n}",
        "hàng đợi lỗi đang giữ {n} tin nhắn", "ổ đĩa /var/lib/data đã dùng {pct}%", "lệnh đồng bộ kho chạy xong sau {ms} ms",
        "hệ thống chuyển sang chế độ chỉ đọc trong lúc sao lưu", "phiên đăng nhập của {u} hết hạn, yêu cầu đăng nhập lại",
    ],
    "B": [
        "đã hạch toán bút toán {n} vào sổ {w}", "đối chiếu tài khoản {n} khớp {k} dòng", "tính lương đợt {id} cho {n} nhân viên",
        "nạp bảng thuế {k} cho năm tài chính 2025", "cập nhật tỷ giá {k}.{n} cho cặp {w}", "lên lịch lệnh chuyển định kỳ {n}",
        "xét lại hạn mức thấu chi cho {u}", "tạo sao kê {n} trong {ms} ms", "bỏ qua tài khoản đã đóng {n}",
        "ghi tệp kiểm toán {f}", "nhận tệp quyết toán {f} từ trung tâm bù trừ", "tính lãi dự thu cho {n} tài khoản",
        "giao dịch {id} vượt ngưỡng, cần phê duyệt", "đã gửi lô phiếu lương {k} cho {u}",
    ],
    "C": [
        "đặt lịch khám {n} với bác sĩ {u} tại phòng {k}", "chuyển bệnh nhân mã {id} từ danh sách chờ", "xếp hàng tin nhắn nhắc lịch {n}",
        "công bố lịch trực khoa {w}", "gắn kết quả xét nghiệm {id} vào lượt khám {n}", "xe TR-{n} rời kho {k}",
        "quét pallet {id} tại điểm trung chuyển {w}", "tính lại giờ đến: trễ {ms} giây", "tờ khai hải quan {n} được chấp nhận",
        "nhiệt độ thùng lạnh {k} là {pct} độ", "tối ưu lại tuyến {w}", "trả khung giờ {n} đã hủy về lịch",
        "lưu chứng từ giao hàng {f}", "tài xế {u} chấm công vào ca",
    ],
}

WORDS = {
    "A": {"files": ["manifest-0412.csv", "wave_17.json", "fleet.toml", "routes.geojson", "batch-88.parquet", "dock.yaml"],
          "words": ["north", "cold", "b2", "east", "mezzanine", "returns", "bulky", "eu-1"],
          "users": ["ops.lan", "minh.tran", "k.osei", "warehouse-bot", "p.ivanova", "thao.ng"]},
    "B": {"files": ["gl-2025-03.csv", "payslip_batch.zip", "settle-0930.dat", "audit-q3.xlsx"],
          "words": ["USD/VND", "EUR/USD", "GL-100", "AP", "AR", "JPY/VND"],
          "users": ["finance.ha", "r.mendes", "payroll-svc", "an.vo"]},
    "C": {"files": ["pod-55120.jpg", "roster-w12.pdf", "decl-7781.xml", "visit-notes.txt"],
          "words": ["icu", "pediatrics", "hn-hp", "sgn-bd", "ward-3", "northbound"],
          "users": ["nguyen.l", "a.kowalski", "dispatch-2", "linh.pham"]},
}

SERVICES = {"A": ["pickd", "labeler", "transcoder", "fleetd", "mailer", "geo", "invoicer"],
            "B": ["ledger", "payrun", "fxsync", "stmtgen"],
            "C": ["booking", "roster", "tms-core", "yard"]}
LEVELS = ["info", "warn", "error", "debug"]


def _level(r):
    return r.choices(LEVELS, [72, 14, 4, 10])[0]


def _log_line(r, fmt, msg, tset, year=2025):
    svc = r.choice(SERVICES[tset])
    lvl = _level(r)
    if fmt == "logfmt":
        return f'ts={ts_iso(r, year)} level={lvl} svc={svc} trace={r.getrandbits(40):010x} msg="{msg}"'
    if fmt == "syslog":
        return (f"{r.choice(MONTHS)} {r.randint(1, 28):2d} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d} "
                f"node-{r.randint(1, 9)} {svc}[{r.randint(200, 65000)}]: {msg}")
    if fmt == "pylog":
        return (f"{year}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:"
                f"{r.randint(0, 59):02d},{r.randint(0, 999):03d} - {svc}.{r.choice(['core', 'jobs', 'api', 'sync'])} - {lvl.upper()} - {msg}")
    if fmt == "ecs":
        return json.dumps({"@timestamp": ts_iso(r, year), "log.level": lvl, "service.name": svc, "message": msg,
                           "trace.id": f"{r.getrandbits(64):016x}"}, ensure_ascii=False)
    if fmt == "logback":
        return (f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}.{r.randint(0, 999):03d} "
                f"[{r.choice(['main', 'pool-2-thread-' + str(r.randint(1, 8)), 'scheduler-1'])}] {lvl.upper():<5} "
                f"c.e.{svc}.{r.choice(['Job', 'Service', 'Client'])} - {msg}")
    if fmt == "zap":
        return (f"{ts_iso(r, year, '+0700')}\t{lvl.upper()}\t{svc}/{r.choice(['run', 'handler', 'store'])}.go:{r.randint(20, 400)}\t"
                f"{msg}\t{{\"attempt\": {r.randint(1, 5)}}}")
    if fmt == "journal":
        return (f"{r.choice(MONTHS)} {r.randint(1, 28):02d} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d} "
                f"srv{r.randint(10, 99)} systemd[1]: {svc}.service: {msg}")
    raise ValueError(fmt)


LOG_FORMATS = {"A": ["logfmt", "syslog", "pylog"], "B": ["ecs", "logback"], "C": ["zap", "journal"]}


def log_unit(lang: str, tset: str, i: int, repeat: bool = False) -> str:
    """One log excerpt of 25-60 lines. repeat=True: one line occurs 2-30 times in a row (a retry loop,
    a flapping check), the other lines as usual; used for the Vietnamese repeated-line windows."""
    kind = f"log_{lang}{'_rep' if repeat else ''}"
    r = unit_rng(kind, tset, i)
    cat = (LOG_VI if lang == "vi" else LOG_EN)[tset]
    fmt = r.choice(LOG_FORMATS[tset])
    n = r.randint(25, 60)
    lines = [_log_line(r, fmt, fill(r, r.choice(cat), WORDS[tset]), tset) for _ in range(n)]
    if repeat:
        line = _log_line(r, fmt, fill(r, r.choice(cat), WORDS[tset]), tset)
        k = r.randint(2, 30)
        at = r.randrange(0, max(1, n // 3))
        lines[at:at] = [line] * k
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stack traces
# ---------------------------------------------------------------------------

TRACE = {
    "A": {"py_mod": ["fulfil/picking.py", "fulfil/waves.py", "media/encode.py", "fleet/ingest.py", "mailq/relay.py"],
          "py_fn": ["allocate", "build_wave", "run_ffmpeg", "decode_frame", "deliver"],
          "py_line": ["slots = self.planner.assign(wave_id)", "proc = subprocess.run(cmd, check=True)", "frame = codec.decode(buf)",
                      "conn.sendmail(sender, rcpt, body)", "row = session.get(Parcel, parcel_id)"],
          "py_exc": ["LookupError: no slot for parcel PX{n}", "subprocess.CalledProcessError: Command '['ffmpeg', '-i', 'in.mov']' returned non-zero exit status 1.",
                     "struct.error: unpack requires a buffer of 12 bytes", "smtplib.SMTPRecipientsRefused: {{'user@mail.example': (550, b'mailbox unavailable')}}"],
          "java_pkg": ["io.fulfil.wave", "io.fulfil.label", "io.fleet.ingest"],
          "java_cls": ["WavePlanner", "LabelRenderer", "TelemetryDecoder"],
          "java_exc": ["java.util.ConcurrentModificationException", "java.lang.ArithmeticException: / by zero",
                       "java.io.UncheckedIOException: java.net.SocketTimeoutException: Read timed out"],
          "go_pkg": ["fleet/internal/ingest", "fleet/internal/codec", "fulfil/pkg/planner"],
          "go_fn": ["(*Decoder).Next", "(*Planner).Assign", "flush", "(*Batch).Commit"],
          "go_panic": ["assignment to entry in nil map", "send on closed channel", "slice bounds out of range [:9] with capacity 4"],
          "js_file": ["src/routes/labels.js", "src/workers/encode.mjs", "lib/fleet/socket.js"],
          "js_fn": ["renderLabel", "Encoder.push", "Socket.onMessage", "async Promise.all (index 2)"],
          "js_exc": ["RangeError: Maximum call stack size exceeded", "SyntaxError: Unexpected token '<', \"<html>\" is not valid JSON",
                     "Error: EPIPE: broken pipe, write"]},
    "B": {"py_mod": ["ledger/posting.py", "payroll/calc.py"], "py_fn": ["post_entry", "gross_to_net"],
          "py_line": ["total = sum(l.amount for l in lines)", "rate = TAX_TABLE[bracket]"],
          "py_exc": ["decimal.InvalidOperation: [<class 'decimal.ConversionSyntax'>]", "KeyError: 'bracket_7'"],
          "java_pkg": ["bank.ledger.core"], "java_cls": ["PostingEngine", "FxQuoteClient"],
          "java_exc": ["java.lang.NumberFormatException: For input string: \"12,5\"", "org.springframework.dao.DeadlockLoserDataAccessException"],
          "go_pkg": ["payrun/internal/calc"], "go_fn": ["Compute", "(*Run).Close"], "go_panic": ["integer divide by zero"],
          "js_file": ["src/statement.ts"], "js_fn": ["formatAmount"], "js_exc": ["TypeError: amount.toFixed is not a function"]},
    "C": {"py_mod": ["clinic/slots.py", "tms/eta.py"], "py_fn": ["book", "predict_eta"],
          "py_line": ["slot = calendar.free_slots(doctor_id)[0]", "eta = model.predict(features)"],
          "py_exc": ["IndexError: list index out of range", "ZeroDivisionError: float division by zero"],
          "java_pkg": ["care.booking.api"], "java_cls": ["SlotController", "ReminderJob"],
          "java_exc": ["java.time.format.DateTimeParseException: Text '31/02' could not be parsed", "java.lang.OutOfMemoryError: Java heap space"],
          "go_pkg": ["tms/yard"], "go_fn": ["(*Yard).Scan", "assign"], "go_panic": ["runtime error: makeslice: len out of range"],
          "js_file": ["app/booking/form.tsx"], "js_fn": ["SlotPicker"], "js_exc": ["ReferenceError: patient is not defined"]},
}

TRACE_VI_MSG = {
    "A": ["Không tìm thấy kiện hàng PX{n} trong đợt soạn", "Tệp cấu hình đội xe bị thiếu trường 'khu_vuc'",
          "Thiết bị sensor-{n} gửi dữ liệu sai định dạng", "Không gửi được thư tới {u}: máy chủ từ chối",
          "Số lượng tồn kho âm sau khi trừ đơn {n}", "Hết thời gian chờ khi gọi dịch vụ định vị"],
    "B": ["Bút toán {n} không cân: chênh lệch {k} đồng", "Không đọc được bảng thuế năm 2025"],
    "C": ["Khung giờ khám {n} đã có người đặt", "Không tính được giờ đến cho xe TR-{n}"],
}


def trace_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng(f"trace_{lang}", tset, i)
    t = TRACE[tset]
    vi = lang == "vi"
    msg = fill(r, r.choice(TRACE_VI_MSG[tset]), WORDS[tset]) if vi else None
    kind = r.randrange(4)
    if kind == 0:
        lines = ["Traceback (most recent call last):"]
        for _ in range(r.randint(3, 9)):
            lines.append(f'  File "/opt/app/{r.choice(t["py_mod"])}", line {r.randint(8, 900)}, in {r.choice(t["py_fn"])}')
            lines.append(f"    {r.choice(t['py_line'])}")
        lines.append(f"app.errors.DomainError: {msg}" if vi else fill(r, r.choice(t["py_exc"]), WORDS[tset]))
    elif kind == 1:
        cls = r.choice(t["java_cls"])
        pkg = r.choice(t["java_pkg"])
        head = f"{pkg}.BusinessException: {msg}" if vi else r.choice(t["java_exc"])
        lines = [f'Exception in thread "{r.choice(["main", "worker-3", "http-nio-8080-exec-7"])}" {head}']
        for _ in range(r.randint(5, 16)):
            lines.append(f"\tat {pkg}.{r.choice(t['java_cls'])}.{r.choice(['run', 'apply', 'lambda$submit$0', 'handle'])}"
                         f"({cls}.java:{r.randint(12, 700)})")
        lines.append(f"\tat java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:{r.randint(1100, 1200)})")
        if r.random() < 0.5:
            lines.append(f"Caused by: {r.choice(t['java_exc'])}")
            lines.append(f"\t... {r.randint(4, 40)} more")
    elif kind == 2:
        lines = [f"panic: {msg}" if vi else f"panic: {r.choice(t['go_panic'])}", "",
                 f"goroutine {r.randint(2, 4000)} [running]:"]
        for _ in range(r.randint(3, 9)):
            pkg = r.choice(t["go_pkg"])
            lines.append(f"example.org/{pkg}.{r.choice(t['go_fn'])}(0xc{r.getrandbits(36):09x}, 0x{r.getrandbits(16):x})")
            lines.append(f"\t/build/{pkg.split('/')[-1]}/{r.choice(['decode', 'plan', 'batch', 'run'])}.go:{r.randint(15, 600)} +0x{r.getrandbits(10):x}")
        lines.append(f"exit status {r.choice([1, 2])}")
    else:
        lines = [f"Error: {msg}" if vi else r.choice(t["js_exc"])]
        for _ in range(r.randint(4, 11)):
            lines.append(f"    at {r.choice(t['js_fn'])} (file:///srv/app/{r.choice(t['js_file'])}:{r.randint(1, 500)}:{r.randint(1, 80)})")
        lines.append(f"    at node:internal/process/task_queues:{r.randint(90, 140)}:{r.randint(5, 9)}")
    stamp = f"[{ts_iso(r)}] " if r.random() < 0.4 else ""
    return stamp + "\n".join(lines) + "\n\n"


# ---------------------------------------------------------------------------
# JSON and CSV
# ---------------------------------------------------------------------------

PEOPLE = {"en": {"A": ["Priya Raman", "Tomás Herrera", "Olu Adeyemi", "Hannah Becker", "Kenji Sato"],
                 "B": ["Sofia Marino", "Arjun Mehta"], "C": ["Lucy Tran", "Marek Dvořák"]},
          "vi": {"A": ["Đoàn Thị Hồng", "Lương Văn Toàn", "Quách Minh Khoa", "Châu Ngọc Trâm", "Tạ Quang Vinh"],
                 "B": ["Kiều Thanh Hương", "Mạc Đình Phong"], "C": ["Lã Thị Yến", "Từ Bảo Nam"]}}
JSON_TEXT = {
    "en": {"A": ["Left at reception", "Fragile, keep upright", "Customer asked to skip the doorbell", "Second attempt tomorrow",
                 "Address verified by driver", "Return label included"],
           "B": ["Monthly rent", "Salary advance repayment", "Card annual fee"],
           "C": ["Bring previous test results", "Fasting required", "Reschedule if fever"]},
    "vi": {"A": ["Để ở quầy lễ tân", "Hàng dễ vỡ, giữ thẳng đứng", "Khách dặn không bấm chuông", "Giao lại vào ngày mai",
                 "Tài xế đã xác minh địa chỉ", "Kèm sẵn nhãn hoàn hàng", "Gọi trước 15 phút giúp em"],
           "B": ["Tiền thuê nhà tháng này", "Hoàn ứng lương", "Phí thường niên thẻ"],
           "C": ["Mang theo kết quả xét nghiệm cũ", "Nhịn ăn trước khi khám", "Dời lịch nếu bị sốt"]},
}
PLACES = {"en": {"A": ["Portland", "Leeds", "Osaka", "Rotterdam"], "B": ["Lyon", "Pune"], "C": ["Krakow", "Perth"]},
          "vi": {"A": ["Bắc Ninh", "Long An", "Quy Nhơn", "Thái Nguyên"], "B": ["Bình Dương", "Nam Định"], "C": ["Phan Thiết", "Đà Lạt"]}}


def json_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng(f"json_{lang}", tset, i)
    ppl, txt, plc = PEOPLE[lang][tset], JSON_TEXT[lang][tset], PLACES[lang][tset]
    if tset == "A":
        recs = [{"tracking_no": f"PX{r.randint(10**8, 10**9 - 1)}", "recipient": r.choice(ppl), "city": r.choice(plc),
                 "events": [{"at": ts_iso(r), "code": r.choice(["PICKED", "IN_TRANSIT", "OUT_FOR_DELIVERY", "DELIVERED"]),
                             "hub": f"HUB-{r.randint(1, 40):02d}"} for _ in range(r.randint(1, 4))],
                 "weight_kg": round(r.uniform(0.2, 30), 2), "remark": r.choice(txt)} for _ in range(r.randint(2, 6))]
        doc = {"shipments": recs, "page": r.randint(1, 30), "next_cursor": f"{r.getrandbits(48):012x}"}
    elif tset == "B":
        recs = [{"txn_id": f"T{r.getrandbits(40):010X}", "posted": ts_iso(r)[:10], "counterparty": r.choice(ppl),
                 "amount": {"value": r.randint(10, 90000) * 1000, "currency": "VND"}, "memo": r.choice(txt),
                 "branch": r.choice(plc)} for _ in range(r.randint(3, 8))]
        doc = {"account": f"{r.randint(10**11, 10**12 - 1)}", "transactions": recs, "balance": r.randint(10**6, 10**9)}
    else:
        recs = [{"slot": ts_iso(r)[:16], "doctor": r.choice(ppl), "clinic": r.choice(plc), "status": r.choice(["open", "held", "booked"]),
                 "instructions": r.choice(txt)} for _ in range(r.randint(3, 7))]
        doc = {"schedule": recs, "generated_at": ts_iso(r)}
    return json.dumps(doc, ensure_ascii=False, indent=r.choice([None, 2, 4])) + "\n"


CSV_HEAD = {"en": {"A": "parcel,recipient,city,weight_kg,service,remark", "B": "date,account,counterparty,debit,credit,memo",
                   "C": "slot,doctor,clinic,status,instructions"},
            "vi": {"A": "ma_kien,nguoi_nhan,tinh_thanh,khoi_luong_kg,dich_vu,ghi_chu", "B": "ngay,so_tk,doi_tac,no,co,dien_giai",
                   "C": "khung_gio,bac_si,phong_kham,trang_thai,dan_do"}}


def csv_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng(f"csv_{lang}", tset, i)
    ppl, txt, plc = PEOPLE[lang][tset], JSON_TEXT[lang][tset], PLACES[lang][tset]
    sep = r.choice([",", ";"]) if tset == "A" else ("\t" if tset == "C" else ",")
    rows = [CSV_HEAD[lang][tset].replace(",", sep)]
    for _ in range(r.randint(20, 45)):
        if tset == "A":
            cells = [f"PX{r.randint(10**8, 10**9 - 1)}", r.choice(ppl), r.choice(plc), f"{r.uniform(0.2, 30):.2f}",
                     r.choice(["express", "standard", "economy"]), r.choice(txt)]
        elif tset == "B":
            v = r.randint(10, 90000) * 1000
            cells = [ts_iso(r)[:10], str(r.randint(10**11, 10**12 - 1)), r.choice(ppl), str(v) if r.random() < .5 else "",
                     "" if r.random() < .5 else str(v), r.choice(txt)]
        else:
            cells = [ts_iso(r)[:16], r.choice(ppl), r.choice(plc), r.choice(["open", "held", "booked"]), r.choice(txt)]
        rows.append(sep.join(f'"{c}"' if sep in c or " " in c else c for c in cells))
    return "\n".join(rows) + "\n"


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

SQL_TABLES = {"A": [("parcels", ["id bigserial primary key", "tracking_no text not null unique", "weight_grams integer",
                                 "zone_code char(3)", "created_at timestamptz default now()"]),
                    ("waves", ["id serial primary key", "zone_code char(3) not null", "planned_for date", "status smallint default 0"]),
                    ("devices", ["serial text primary key", "firmware text", "last_seen timestamptz", "battery_pct numeric(5,2)"])],
              "B": [("ledger_entries", ["entry_id bigint primary key", "account_no varchar(20)", "amount numeric(18,2)", "posted_on date"])],
              "C": [("appointments", ["appt_id uuid primary key", "doctor_id int", "starts_at timestamp", "state varchar(12)"])]}


def sql_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng("sql", tset, i)
    out = []
    for _ in range(r.randint(3, 7)):
        name, cols = r.choice(SQL_TABLES[tset])
        k = r.randrange(5)
        if k == 0:
            out.append(f"CREATE TABLE IF NOT EXISTS {name} (\n    " + ",\n    ".join(cols) + "\n);")
        elif k == 1:
            col = cols[r.randrange(1, len(cols))].split()[0]
            out.append(f"CREATE INDEX CONCURRENTLY idx_{name}_{col} ON {name} ({col});")
        elif k == 2:
            c0, c1 = cols[0].split()[0], cols[1].split()[0]
            vals = ",\n  ".join(f"({r.randint(1, 99999)}, '{r.getrandbits(24):06x}')" for _ in range(r.randint(2, 8)))
            out.append(f"INSERT INTO {name} ({c0}, {c1}) VALUES\n  {vals}\nON CONFLICT ({c0}) DO NOTHING;")
        elif k == 3:
            c1 = cols[1].split()[0]
            out.append(f"SELECT {c1}, count(*) AS n\nFROM {name}\nWHERE {cols[-1].split()[0]} >= now() - interval '{r.randint(1, 30)} days'\n"
                       f"GROUP BY {c1}\nHAVING count(*) > {r.randint(1, 50)}\nORDER BY n DESC\nLIMIT {r.choice([10, 20, 100])};")
        else:
            col = cols[-1].split()[0]
            out.append(f"-- migration {r.randint(100, 999)}: backfill {col}\nBEGIN;\nALTER TABLE {name} ADD COLUMN IF NOT EXISTS note text;\n"
                       f"UPDATE {name} SET note = 'legacy' WHERE {col} IS NULL;\nCOMMIT;")
    return "\n\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Terminal sessions (tool output an agent reads after running a command)
# ---------------------------------------------------------------------------

def terminal_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng("terminal", tset, i)
    k = r.randrange(2) if tset == "A" else (2 if tset == "B" else 3)
    if k == 0:
        lines = ["$ kubectl get pods -n " + r.choice(["fulfil", "media", "fleet"]),
                 "NAME                                READY   STATUS    RESTARTS   AGE"]
        for _ in range(r.randint(5, 20)):
            lines.append(f"{r.choice(SERVICES[tset])}-{r.getrandbits(40):010x}-{r.getrandbits(20):05x}   1/1     "
                         f"{r.choice(['Running', 'Running', 'Pending', 'CrashLoopBackOff'])}   {r.randint(0, 9)}          {r.randint(1, 40)}d")
    elif k == 1:
        lines = ["$ pip install -r requirements.txt"]
        for p in r.sample(["httpx", "pydantic", "sqlalchemy", "alembic", "redis", "boto3", "orjson", "celery", "uvicorn"], 5):
            lines.append(f"Collecting {p}=={r.randint(0, 3)}.{r.randint(0, 30)}.{r.randint(0, 9)}")
            lines.append(f"  Downloading {p}-{r.randint(0, 3)}.{r.randint(0, 30)}.0-py3-none-any.whl ({r.randint(20, 900)} kB)")
        lines.append("Successfully installed " + " ".join(f"pkg{r.randint(1, 99)}-1.0" for _ in range(4)))
    elif k == 2:
        lines = ["$ docker build -t registry.example/app:dev ."]
        for s in range(1, r.randint(6, 14)):
            lines.append(f"#{s} [{s}/12] RUN {r.choice(['apt-get update', 'npm ci', 'go build ./...', 'pip install .'])}")
            lines.append(f"#{s} DONE {r.uniform(0.1, 40):.1f}s")
    else:
        lines = ["$ npm test", "", "> app@1.0.0 test", "> vitest run", ""]
        for _ in range(r.randint(6, 18)):
            lines.append(f" {r.choice(['✓', '✓', '✓', '×'])} src/{r.choice(['slots', 'eta', 'form', 'api'])}.test.ts ({r.randint(1, 30)} tests) {r.randint(3, 900)}ms")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Vietnamese-commented code (what Vietnamese teams write and agents read)
# ---------------------------------------------------------------------------

VI_CODE = {
    "A": [("Tính phí giao hàng theo khối lượng và vùng", "shipping_fee", "weight_kg, zone"),
          ("Gom các đơn cùng khu vực vào một đợt soạn hàng", "group_orders", "orders"),
          ("Kiểm tra pin thiết bị, bỏ qua thiết bị đã ngừng hoạt động", "check_battery", "devices"),
          ("Đọc tệp cấu hình và ghi đè giá trị mặc định nếu có", "load_config", "path"),
          ("Gửi lại thư cho người nhận khi máy chủ báo lỗi tạm thời", "resend_mail", "message, retries"),
          ("Chuẩn hóa số điện thoại về dạng +84", "normalize_phone", "raw")],
    "B": [("Tính thuế thu nhập cá nhân theo biểu lũy tiến", "pit", "income"), ("Đối chiếu sao kê với sổ cái", "reconcile", "rows")],
    "C": [("Tìm khung giờ khám trống gần nhất", "next_slot", "doctor"), ("Ước tính giờ xe đến kho", "eta", "route")],
}
VI_CODE_LINES = {
    "A": ["# Lưu ý: giá trị này lấy từ bảng giá tháng hiện tại", "# Nếu không có dữ liệu thì trả về mặc định",
          "# TODO: tách phần này thành hàm riêng", "# Không dùng biến toàn cục ở đây để dễ kiểm thử",
          "# Bỏ qua dòng tiêu đề của tệp CSV", "# Ghi log để đội vận hành theo dõi"],
    "B": ["# Làm tròn đến hàng đơn vị đồng", "# Số âm nghĩa là ghi có"],
    "C": ["# Giờ địa phương GMT+7", "# Bỏ qua ngày nghỉ lễ"],
}


def code_vi_unit(lang: str, tset: str, i: int) -> str:
    r = unit_rng("code_vi", tset, i)
    out = []
    for _ in range(r.randint(2, 4)):
        doc, fn, args = r.choice(VI_CODE[tset])
        style = r.randrange(3)
        notes = r.sample(VI_CODE_LINES[tset], min(2, len(VI_CODE_LINES[tset])))
        if style == 0:
            body = [f"def {fn}({args}):", f'    """{doc}."""'] + ["    " + n for n in notes]
            body += [f"    result = {r.choice(['0', '[]', '{}', 'None'])}", f"    for item in {args.split(',')[0]} or []:",
                     "        result = merge(result, item)  # gộp kết quả từng phần", "    return result"]
        elif style == 1:
            cam = fn.split("_")[0] + "".join(w.title() for w in fn.split("_")[1:])
            body = [f"/** {doc}. */", f"export function {cam}({args}) {{"] + ["  //" + n[1:] for n in notes]
            body += ["  const out = [];", "  // Trả về mảng rỗng nếu đầu vào không hợp lệ", "  return out;", "}"]
        else:
            name = "".join(w.title() for w in fn.split("_"))
            body = [f"// {name} {doc[0].lower() + doc[1:]}.", f"func {name}(ctx context.Context) error {{"]
            body += ["\t//" + n[1:] for n in notes] + [f'\treturn fmt.Errorf("{fn}: chưa hỗ trợ vùng %q", "{r.choice(["VN-HN", "VN-SG", "VN-DN"])}")', "}"]
        out.append("\n".join(body))
    if r.random() < 0.3:
        out.append(json.dumps({"vi": {"cart.empty": "Giỏ hàng đang trống", "checkout.skip": "Bỏ qua bước này",
                                      "login.reset": "Quên mật khẩu?", "order.track": "Theo dõi đơn hàng"}},
                              ensure_ascii=False, indent=2))
    return "\n\n".join(out) + "\n"


GENERATORS = {
    "log_en": ("en", lambda s, i: log_unit("en", s, i)),
    "log_vi": ("vi", lambda s, i: log_unit("vi", s, i)),
    "log_vi_repeat": ("vi", lambda s, i: log_unit("vi", s, i, repeat=True)),
    "stacktrace_en": ("en", lambda s, i: trace_unit("en", s, i)),
    "stacktrace_vi": ("vi", lambda s, i: trace_unit("vi", s, i)),
    "json_en": ("en", lambda s, i: json_unit("en", s, i)),
    "json_vi": ("vi", lambda s, i: json_unit("vi", s, i)),
    "csv_en": ("en", lambda s, i: csv_unit("en", s, i)),
    "csv_vi": ("vi", lambda s, i: csv_unit("vi", s, i)),
    "sql_gen": ("en", lambda s, i: sql_unit("en", s, i)),
    "terminal": ("en", lambda s, i: terminal_unit("en", s, i)),
    "code_vi": ("vi", lambda s, i: code_vi_unit("vi", s, i)),
}


def unit(kind: str, tset: str, i: int) -> str:
    assert tset in SETS, tset
    return GENERATORS[kind][1](tset, i)


def sample_md5(n: int = 40) -> dict[str, str]:
    """md5 of the first n units of every kind and set (the reproducibility check)."""
    out = {}
    for kind in GENERATORS:
        for s in SETS:
            out[f"{kind}/{s}"] = hashlib.md5("".join(unit(kind, s, i) for i in range(n)).encode()).hexdigest()
    return out


def main(argv: list[str]) -> int:
    a, b = sample_md5(), sample_md5()
    if "--check" in argv:
        if a != b:
            print("gen_codelog_v5: output differs between two runs", file=sys.stderr)
            return 1
    print(json.dumps(a, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
