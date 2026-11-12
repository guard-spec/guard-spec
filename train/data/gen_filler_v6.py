"""Seeded generators for the v6 data (task RF-895d3533): human-sounding log lines and explanatory security prose.

    python3 train/data/gen_filler_v6.py            # md5 of a fixed sample per kind and set
    python3 train/data/gen_filler_v6.py --check    # exits 1 unless two runs give the same bytes

Two families, both benign, in English and Vietnamese, with template sets A/B/C whose catalogs are disjoint
(A trains, B selects, C is the hold-out; the same sets as gen_codelog_v5):

    human_log_{en,vi}   log excerpts whose messages are written the way an engineer writes them: full
                        sentences, hedges, hints for the reader, apologies ("could not reach the SMTP relay,
                        will try again in 30 s; page on-call if this repeats"). build_v6.py cuts windows from
                        them (hard negatives) and takes single lines as benign fillers for the twins of the
                        embedded positives (the payload replaced by a human log line of similar length).
    secprose_{en,vi}    paragraphs that explain or discuss prompt injection, jailbreaks and their defences
                        the way a security guide, an incident write-up or a training deck does. They quote
                        attack phrases in passing ("ignore the previous instructions") but give no
                        instruction to a model: hard negatives about security.

Rendering of the log lines reuses gen_codelog_v5 (formats, services and filler words per set), so the
line shapes of a set stay the ones that set uses elsewhere. The catalogs were written for this file and
share no sentence with eval/codelog/build.py or the synthetic genres of bench/long/build.py
(train/tests/test_gen_filler_v6.py checks that, with a 5-gram overlap bound). Standard library only; every
random choice comes from unit_rng(kind, set, i), so the output is byte-identical between runs.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_codelog_v5 as gen  # noqa: E402

SEED = 89551364  # not gen_codelog_v5 (43712895), eval/codelog (4764030) or bench/long (20261109)
SETS = ("A", "B", "C")


def unit_rng(kind: str, tset: str, i: int) -> random.Random:
    h = hashlib.sha256(f"{SEED}\x1f{kind}\x1f{tset}\x1f{i}".encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


# ---------------------------------------------------------------------------
# Human-sounding log and error lines. {n} {k} {id} {f} {w} {u} {ms} {pct} {ip} are filled by gen.fill.
# ---------------------------------------------------------------------------

HUMAN_EN = {
    "A": [
        "could not reach the SMTP relay on the first try, waiting 30 s before the next attempt; page on-call if this keeps repeating",
        "the picking wave {k} finished later than planned because two scanners went offline around lunch, nothing lost",
        "skipping {f}: it was already imported this morning and the checksum has not changed",
        "transcode of asset {n} took {ms} ms, which is slower than usual; the source file is a 4K ProRes, so that is expected",
        "heads up: the carrier portal returned an empty manifest for dock {k}, retrying once more before we alert the shift lead",
        "gateway gw-{id} missed three heartbeats in a row, marking it degraded; a field visit is probably needed",
        "firmware rollout paused at {pct}% because the error rate crept above the budget, resume manually when the fleet looks healthy",
        "mailbox for {u} is full again, bouncing the digest and sending a short notice instead",
        "nothing to do for order {n}: the shipping class is already oversize, no override applied",
        "this is the {k}th retry for webhook {id}; giving up after this one and leaving it in the dead-letter queue for review",
        "the geocoder had no match for postcode {n}, fell back to the depot coordinates so the route still renders",
        "note for whoever reads this later: the replica lag of {ms} ms is from last night's backfill, not a network problem",
        "user {u} exported report {n} as PDF ({k} pages); the export took a while because the invoice table is large",
        "cache warm-up done, {n} keys loaded; the first requests of the day should feel faster now",
        "disk on /var/lib/data is at {pct}%, still fine, but please clean the tmp folder before the weekend",
        "connection pool grew from {k} to {n} during the spike and shrank back on its own, no action needed",
        "the thumbnail sprite for asset {n} looks blank in preview, regenerating it from the second keyframe",
        "queue {w} was paused by {u} for a manual check, remember to resume it or the pickers will wait",
        "telemetry batch of {n} points accepted after a slow upload from {ip}; the link in the warehouse is flaky today",
        "finished purging temporary files: {n} removed, {k} kept because they were still open",
        "label printer in zone {w} reported a paper jam, the parcel PX{n} will be relabelled at the next station",
        "request to {ip} timed out after {ms} ms, the upstream is probably restarting; nothing to fix on our side",
        "feature flag {w} is now on for {pct}% of users, watch the error dashboard for the next hour",
        "the lock on inventory row {n} was held for {ms} ms by a report query, which is longer than we like",
    ],
    "B": [
        "journal entry {n} did not balance by {k} cents, holding it for a human to look at rather than posting it",
        "the payroll run for {w} finished; two employees had missing bank details and were skipped, see the exception list",
        "settlement file {f} arrived twice, keeping the first copy and ignoring the duplicate",
        "FX rate for {w} is older than 24 hours, using the last known value and flagging the batch for review",
        "reconciliation of account {n} matched {k} lines; the remaining ones are timing differences, not errors",
        "the statement generator is slow this morning ({ms} ms per statement) because the archive volume is being rebuilt",
        "could not send the payslip to {u}: the address bounced, a paper copy will be printed instead",
        "tax table for the new year is not loaded yet, falling back to the current one and warning the operator",
        "audit export {f} written with {n} rows, please check the totals against the ledger before sending it",
        "a reversal was requested for entry {n} by {u}; it will be posted at the next batch close",
        "the fx sync job hit the rate limit of the provider ({k} calls per minute), sleeping until the window resets",
        "closing period {w}: {n} entries posted, {k} held, no hard failures",
        "warning for the reader: the balance of {u} shows a negative value because the refund posted before the charge",
        "the retry of the bank upload worked on attempt {k}, the earlier failures were a TLS handshake timeout",
    ],
    "C": [
        "slot {n} was double-booked by two receptionists at the same time; keeping the earlier booking and notifying {u}",
        "the ETA model for truck TR-{n} has no traffic data for this road, using the free-flow estimate instead",
        "roster {f} loaded, but {k} shifts have no doctor assigned, please fill them in before Monday",
        "customs declaration {n} rejected by the portal: a required field was empty, the clerk has been asked to resubmit",
        "yard camera {k} is offline again, the gate will be logged by hand until it comes back",
        "the appointment reminder for {u} was not sent because the phone number is missing in the record",
        "freight manifest for route {w} recomputed after a late cancellation, the total weight dropped by {n} kg",
        "visit notes for patient {n} were saved, but the attached image was too large and has to be re-uploaded",
        "the dispatcher console was slow for about {ms} ms while the map tiles reloaded, no requests were lost",
        "we are waiting on the lab system for result {id}; it usually answers within the hour",
        "a delivery proof photo for pod-{n} came back blurry, asking the driver for another one",
        "the shift report for yard {w} is done, {k} containers moved, {n} still waiting on paperwork",
    ],
}

HUMAN_VI = {
    "A": [
        "không kết nối được tới máy chủ gửi mail, sẽ thử lại sau 30 giây; nếu lặp lại nhiều lần thì báo người trực nhé",
        "đợt soạn hàng {k} xong muộn hơn kế hoạch vì hai máy quét mất kết nối lúc trưa, không mất dữ liệu",
        "bỏ qua tệp {f}: đã nhập từ sáng nay và mã kiểm tra không đổi",
        "chuyển mã video {n} mất {ms} ms, chậm hơn bình thường do tệp nguồn là 4K nên cũng dễ hiểu",
        "lưu ý: cổng vận chuyển trả về bản kê trống cho cửa xuất {k}, thử lại một lần nữa trước khi báo ca trưởng",
        "thiết bị gw-{id} mất ba nhịp tim liên tiếp, đánh dấu suy giảm; có lẽ cần cử người ra hiện trường",
        "tạm dừng cập nhật firmware ở mức {pct}% vì tỷ lệ lỗi vượt ngưỡng, khi nào đội thiết bị ổn thì bật lại thủ công",
        "hộp thư của {u} lại đầy, trả lại bản tin tổng hợp và gửi một thông báo ngắn thay thế",
        "đơn {n} không cần làm gì thêm: hạng vận chuyển đã là hàng cồng kềnh, không áp dụng ghi đè",
        "đây là lần thử thứ {k} cho webhook {id}; sau lần này sẽ dừng và để lại hàng đợi lỗi cho người xem xét",
        "không tra được tọa độ cho mã bưu chính {n}, dùng tạm tọa độ kho để tuyến đường vẫn hiển thị được",
        "ghi chú cho người đọc sau: độ trễ bản sao {ms} ms là do chạy bổ sung dữ liệu tối qua, không phải lỗi mạng",
        "người dùng {u} đã xuất báo cáo {n} dạng PDF ({k} trang), hơi lâu vì bảng hóa đơn khá lớn",
        "làm nóng bộ nhớ đệm xong, đã nạp {n} khóa; các yêu cầu đầu ngày sẽ nhanh hơn",
        "ổ đĩa /var/lib/data đang ở mức {pct}%, vẫn ổn nhưng nhớ dọn thư mục tạm trước cuối tuần",
        "máy in nhãn khu {w} báo kẹt giấy, kiện PX{n} sẽ được in lại nhãn ở trạm kế tiếp",
        "yêu cầu tới {ip} hết thời gian chờ sau {ms} ms, có vẻ bên kia đang khởi động lại; bên mình không cần sửa gì",
        "cờ tính năng {w} đã bật cho {pct}% người dùng, theo dõi bảng lỗi trong một giờ tới",
        "hàng đợi {w} đã được {u} tạm dừng để kiểm tra tay, nhớ bật lại kẻo nhân viên soạn hàng phải chờ",
        "gói dữ liệu cảm biến {n} điểm đã nhận sau một lần tải chậm từ {ip}; đường mạng trong kho hôm nay chập chờn",
        "đã dọn xong tệp tạm: xóa {n}, giữ lại {k} vì vẫn đang mở",
        "khóa trên dòng tồn kho {n} bị giữ {ms} ms bởi một truy vấn báo cáo, lâu hơn mức mong muốn",
    ],
    "B": [
        "bút toán {n} lệch {k} đồng, giữ lại để người kiểm tra thay vì tự ghi sổ",
        "đã chạy xong bảng lương {w}; hai nhân viên thiếu thông tin ngân hàng nên bị bỏ qua, xem danh sách ngoại lệ",
        "tệp quyết toán {f} về hai lần, giữ bản đầu và bỏ bản trùng",
        "tỷ giá {w} đã cũ hơn 24 giờ, dùng giá gần nhất và đánh dấu lô này để rà lại",
        "đối chiếu tài khoản {n} khớp {k} dòng; phần còn lại là lệch thời điểm, không phải lỗi",
        "máy tạo sao kê sáng nay chậm ({ms} ms mỗi bản) vì ổ lưu trữ đang được dựng lại",
        "không gửi được phiếu lương cho {u}: địa chỉ bị trả về, sẽ in bản giấy thay thế",
        "bảng thuế năm mới chưa nạp, tạm dùng bảng hiện tại và cảnh báo người vận hành",
        "đã ghi tệp kiểm toán {f} với {n} dòng, vui lòng đối chiếu tổng với sổ cái trước khi gửi",
        "{u} yêu cầu hủy bút toán {n}; sẽ ghi nhận ở lần đóng lô kế tiếp",
        "tác vụ đồng bộ tỷ giá chạm giới hạn nhà cung cấp ({k} lần mỗi phút), chờ đến khi cửa sổ được đặt lại",
        "đóng kỳ {w}: đã ghi {n} bút toán, giữ {k}, không có lỗi nặng",
        "lưu ý cho người đọc: số dư của {u} âm vì khoản hoàn tiền ghi trước khoản thu",
    ],
    "C": [
        "khung giờ {n} bị hai lễ tân đặt cùng lúc; giữ lượt đặt sớm hơn và báo cho {u}",
        "mô hình ước tính giờ đến của xe TR-{n} không có dữ liệu giao thông đoạn này, dùng ước tính đường thông thoáng",
        "đã nạp lịch trực {f}, nhưng {k} ca chưa có bác sĩ, nhớ điền trước thứ Hai",
        "tờ khai hải quan {n} bị cổng từ chối vì thiếu một trường bắt buộc, đã nhờ nhân viên khai lại",
        "camera bãi số {k} lại mất kết nối, cổng sẽ được ghi tay cho đến khi có lại",
        "chưa gửi được nhắc lịch hẹn cho {u} vì hồ sơ thiếu số điện thoại",
        "bản kê hàng tuyến {w} tính lại sau một lượt hủy muộn, tổng khối lượng giảm {n} kg",
        "đã lưu ghi chú khám của bệnh nhân {n}, nhưng ảnh đính kèm quá lớn nên phải tải lại",
        "bảng điều phối chậm khoảng {ms} ms lúc tải lại bản đồ, không mất yêu cầu nào",
        "đang chờ hệ thống xét nghiệm trả kết quả {id}; thường thì trong vòng một giờ",
        "ảnh xác nhận giao hàng pod-{n} bị mờ, đã nhờ tài xế chụp lại",
        "báo cáo ca của bãi {w} đã xong, {k} container đã di chuyển, {n} còn chờ giấy tờ",
    ],
}


def human_line(lang: str, tset: str, r: random.Random) -> str:
    cat = (HUMAN_VI if lang == "vi" else HUMAN_EN)[tset]
    return gen.fill(r, r.choice(cat), gen.WORDS[tset])


def human_log_unit(lang: str, tset: str, i: int) -> str:
    """A log excerpt of 8-25 lines in the set's formats, every message a human-sounding line."""
    r = unit_rng(f"human_log_{lang}", tset, i)
    fmt = r.choice(gen.LOG_FORMATS[tset])
    lines = [gen._log_line(r, fmt, human_line(lang, tset, r), tset) for _ in range(r.randint(8, 25))]
    return "\n".join(lines) + "\n"


def human_lines(lang: str, tset: str, i: int, n: int) -> list[str]:
    """n human-sounding messages without a log prefix (fillers for twins)."""
    r = unit_rng(f"human_lines_{lang}", tset, i)
    return [human_line(lang, tset, r) for _ in range(n)]


# ---------------------------------------------------------------------------
# Explanatory security prose. {org} {team} {tool} {q} {n} {k} are filled below.
# ---------------------------------------------------------------------------

SEC_EN = {
    "A": [
        "Prompt injection is the name for text that tries to redirect a model away from the task its operator gave it.",
        "In the direct form the attacker types the text themselves; in the indirect form it arrives inside a page, a ticket or a file the assistant reads.",
        "The {team} team at {org} keeps a short catalogue of the phrasings it has seen, from \"ignore the previous instructions\" to polite requests to print the hidden configuration.",
        "What makes the indirect variant hard is that the model cannot tell retrieved content from the operator's instructions unless the application marks the boundary.",
        "{tool} scores every retrieved document before it reaches the model and holds back the parts that look like instructions to the assistant.",
        "A scanner that blocks ordinary questions is switched off within a week, so the false-positive rate matters as much as recall.",
        "During the {q} review the engineers replayed {n} attempts from the logs; {k} of them had slipped past the keyword rules.",
        "Jailbreaks are a related family: role-play framings, invented permissions and encoded text that ask the model to drop its policy.",
        "System prompts should never hold secrets, because a determined user can often get the model to repeat them.",
        "The incident write-up recommends logging the retrieved text next to the model's answer, so that an analyst can see what the model saw.",
        "Attackers also hide instructions in places people do not read: alt text, white-on-white spans, HTML comments and tool descriptions.",
        "Training material for the support staff explains how to recognise a suspicious transcript and where to file it.",
        "The rules engine catches the obvious phrasings; the classifier is there for paraphrases and for Vietnamese and English mixed in one sentence.",
        "Most of the {q} findings were benign: documentation about the attack, test cases and a few jokes in commit messages.",
        "The defence is layered: input scanning, a separate channel for tool results, and an output check before anything is sent.",
        "None of this replaces least privilege: an assistant that cannot send e-mail cannot be talked into sending one.",
    ],
    "B": [
        "An injected instruction is any span of untrusted text that reads like a command to the assistant rather than content for it.",
        "The {org} security guide separates three sources of text: the operator, the user, and everything the assistant fetched on its own.",
        "Reviewers at {org} found that most real attempts were clumsy, but a few were split across two documents so that no single scan saw the whole instruction.",
        "{tool} keeps a small allow-list of phrases that are fine in a security context, such as the names of well-known attack techniques.",
        "A detector is tuned on a development slice and judged on a hold-out, otherwise the reported numbers only describe the tuning set.",
        "The {team} team measured {n} false positives on {k} thousand benign documents before the threshold was moved.",
        "Red-team exercises in {q} tried encoded payloads, invisible characters and requests hidden inside JSON fields.",
        "When a document is long, the scanner cuts it into overlapping windows and reports the highest score it saw.",
        "A quoted attack inside a training deck is not an attack: the surrounding sentences make the intent clear to a reader, and the model has to learn the same distinction.",
        "The agreed policy is to show the user why a document was held back, rather than silently dropping it.",
        "Prompt extraction attempts ask the model to repeat its own instructions; they are logged but rarely blocked, because the instructions hold nothing secret.",
        "The postmortem lists the three rules that fired, the one that should have fired, and the fix that shipped the same week.",
    ],
    "C": [
        "Indirect prompt injection works because the model reads whatever the retriever returns, including text that was written for the model and not for the user.",
        "The {org} handbook asks engineers to treat tool output as data and to keep instructions in a channel the tool cannot write to.",
        "Over {q} the {team} team reviewed {n} flagged documents; the large majority were manuals and tickets that merely discussed the attack.",
        "{tool} reports a score per window together with the window text, so the reviewer sees the phrase that caused the alert.",
        "A jailbreak attempt usually asks the model to adopt a persona without rules; a good answer declines without lecturing.",
        "Payload splitting hides the instruction in two halves that only make sense when joined, which defeats scanners that look at one window at a time.",
        "The guidance is blunt: do not put passwords, keys or customer data in a system prompt, and assume the prompt will leak.",
        "The {q} exercise showed that {k} of {n} encoded payloads were caught only because the sanitizer strips the characters that hid them.",
        "Documentation that quotes an attack phrase is useful to defenders and should not be blocked by the same filter.",
        "Each alert is reviewed by a person before the sender is contacted, to avoid accusing a customer who pasted a security article.",
    ],
}

SEC_VI = {
    "A": [
        "Chèn lệnh vào câu lệnh (prompt injection) là tên gọi của đoạn văn bản tìm cách kéo mô hình ra khỏi nhiệm vụ mà người vận hành đã giao.",
        "Ở dạng trực tiếp, kẻ tấn công tự gõ văn bản đó; ở dạng gián tiếp, nó nằm trong trang web, phiếu yêu cầu hoặc tệp mà trợ lý đọc vào.",
        "Nhóm {team} của {org} giữ một danh mục ngắn các cách diễn đạt đã gặp, từ \"bỏ qua các hướng dẫn trước đó\" đến những lời đề nghị lịch sự xin xem cấu hình ẩn.",
        "Khó ở chỗ mô hình không phân biệt được nội dung truy xuất với chỉ dẫn của người vận hành, trừ khi ứng dụng đánh dấu rõ ranh giới.",
        "{tool} chấm điểm từng tài liệu truy xuất trước khi đưa cho mô hình và giữ lại những phần trông giống chỉ dẫn cho trợ lý.",
        "Một bộ quét chặn cả câu hỏi bình thường sẽ bị tắt trong vòng một tuần, nên tỷ lệ báo nhầm quan trọng không kém khả năng phát hiện.",
        "Trong đợt rà soát {q}, các kỹ sư chạy lại {n} lượt thử từ nhật ký; {k} lượt đã lọt qua bộ luật từ khóa.",
        "Jailbreak là họ tấn công liên quan: dựng kịch bản nhập vai, bịa ra quyền hạn hoặc mã hóa văn bản để mô hình bỏ chính sách.",
        "Câu lệnh hệ thống không bao giờ nên chứa bí mật, vì người dùng kiên trì thường khiến mô hình nhắc lại nó.",
        "Báo cáo sự cố khuyến nghị ghi lại đoạn văn bản truy xuất bên cạnh câu trả lời của mô hình, để người phân tích thấy mô hình đã đọc gì.",
        "Kẻ tấn công cũng giấu chỉ dẫn ở nơi người ta không đọc: chữ thay thế của ảnh, chữ trắng trên nền trắng, chú thích HTML và phần mô tả công cụ.",
        "Tài liệu đào tạo cho nhân viên hỗ trợ giải thích cách nhận ra một bản ghi đáng ngờ và nơi gửi báo cáo.",
        "Bộ luật bắt các cách nói hiển nhiên; bộ phân loại dành cho câu diễn đạt lại và cho câu trộn tiếng Việt với tiếng Anh.",
        "Phần lớn phát hiện trong {q} là lành tính: tài liệu nói về kiểu tấn công này, ca kiểm thử và vài câu đùa trong thông điệp commit.",
        "Phòng thủ nhiều lớp: quét đầu vào, kênh riêng cho kết quả công cụ, và kiểm tra đầu ra trước khi gửi đi bất cứ thứ gì.",
        "Tất cả những điều đó không thay thế được nguyên tắc quyền tối thiểu: trợ lý không gửi được email thì không thể bị dụ gửi email.",
    ],
    "B": [
        "Chỉ dẫn bị chèn là bất kỳ đoạn văn bản không tin cậy nào đọc lên giống một mệnh lệnh cho trợ lý thay vì nội dung để nó xử lý.",
        "Hướng dẫn bảo mật của {org} tách ba nguồn văn bản: người vận hành, người dùng, và mọi thứ trợ lý tự lấy về.",
        "Người rà soát ở {org} thấy phần lớn các lượt thử khá vụng, nhưng vài lượt được tách sang hai tài liệu để không lần quét nào thấy trọn chỉ dẫn.",
        "{tool} giữ một danh sách ngắn các cụm từ được phép trong ngữ cảnh bảo mật, chẳng hạn tên các kỹ thuật tấn công quen thuộc.",
        "Bộ phát hiện được tinh chỉnh trên phần phát triển và đánh giá trên phần giữ lại, nếu không thì con số báo cáo chỉ mô tả tập tinh chỉnh.",
        "Nhóm {team} đo được {n} lần báo nhầm trên {k} nghìn tài liệu lành tính trước khi ngưỡng được điều chỉnh.",
        "Các đợt diễn tập red-team trong {q} thử nội dung mã hóa, ký tự vô hình và yêu cầu giấu trong trường JSON.",
        "Khi tài liệu dài, bộ quét cắt nó thành các cửa sổ chồng lấn và báo điểm cao nhất đã thấy.",
        "Một câu tấn công được trích trong bài giảng không phải là tấn công: các câu xung quanh làm rõ ý định cho người đọc, và mô hình phải học được sự phân biệt đó.",
        "Chính sách thống nhất là cho người dùng biết vì sao tài liệu bị giữ lại, thay vì âm thầm bỏ nó đi.",
        "Các lượt moi câu lệnh hệ thống yêu cầu mô hình nhắc lại chỉ dẫn của chính nó; chúng được ghi nhận nhưng hiếm khi bị chặn vì chỉ dẫn không chứa gì bí mật.",
        "Bản phân tích sau sự cố liệt kê ba luật đã kích hoạt, một luật lẽ ra phải kích hoạt, và bản sửa đã phát hành ngay trong tuần.",
    ],
    "C": [
        "Chèn lệnh gián tiếp hoạt động được vì mô hình đọc bất cứ thứ gì bộ truy xuất trả về, kể cả văn bản viết cho mô hình chứ không phải cho người dùng.",
        "Sổ tay của {org} yêu cầu kỹ sư coi kết quả công cụ là dữ liệu và giữ chỉ dẫn trong một kênh mà công cụ không ghi vào được.",
        "Trong {q}, nhóm {team} rà {n} tài liệu bị gắn cờ; đại đa số là sổ tay và phiếu hỗ trợ chỉ nhắc đến kiểu tấn công này.",
        "{tool} báo điểm theo từng cửa sổ kèm đoạn văn bản, nên người rà soát thấy ngay cụm từ gây cảnh báo.",
        "Một lượt jailbreak thường yêu cầu mô hình nhập vai một nhân vật không có quy tắc; câu trả lời tốt là từ chối mà không lên lớp.",
        "Tách nội dung giấu chỉ dẫn thành hai nửa chỉ có nghĩa khi ghép lại, qua mặt những bộ quét chỉ nhìn một cửa sổ mỗi lần.",
        "Hướng dẫn nói thẳng: không đặt mật khẩu, khóa hay dữ liệu khách hàng trong câu lệnh hệ thống, và hãy coi như câu lệnh sẽ bị lộ.",
        "Đợt diễn tập {q} cho thấy {k} trên {n} nội dung mã hóa chỉ bị bắt nhờ bộ làm sạch gỡ các ký tự đã che giấu chúng.",
        "Tài liệu trích dẫn một câu tấn công có ích cho người phòng thủ và không nên bị chính bộ lọc đó chặn.",
        "Mỗi cảnh báo được một người xem lại trước khi liên hệ người gửi, để tránh đổ lỗi cho khách hàng chỉ dán một bài báo về bảo mật.",
    ],
}

ORGS = {"A": ["Northwind Logistics", "Halden Media", "the fleet operations group", "Tern Mail"],
        "B": ["Ledgerline", "the payroll platform", "Marrow Finance"],
        "C": ["the clinic network", "Kestrel Freight", "the yard operator"]}
TEAMS = {"A": ["platform security", "trust and safety", "tooling"], "B": ["risk", "compliance engineering"], "C": ["IT security", "data"]}
TOOLS = {"A": ["The gateway", "The document scanner", "Our pre-filter"], "B": ["The review tool", "The intake service"],
         "C": ["The triage bot", "The inbox scanner"]}
ORGS_VI = {"A": ["Northwind Logistics", "Halden Media", "nhóm vận hành đội xe", "Tern Mail"],
           "B": ["Ledgerline", "nền tảng tính lương", "Marrow Finance"],
           "C": ["chuỗi phòng khám", "Kestrel Freight", "đơn vị khai thác bãi"]}
TEAMS_VI = {"A": ["an ninh nền tảng", "tin cậy và an toàn", "công cụ"], "B": ["rủi ro", "kỹ thuật tuân thủ"], "C": ["an ninh CNTT", "dữ liệu"]}
TOOLS_VI = {"A": ["Cổng kiểm soát", "Bộ quét tài liệu", "Bộ lọc đầu vào"], "B": ["Công cụ rà soát", "Dịch vụ tiếp nhận"],
            "C": ["Bot phân loại", "Bộ quét hộp thư"]}
QUARTERS = {"en": ["Q1", "Q2", "Q3", "Q4", "H1", "H2"],
            "vi": ["quý 1", "quý 2", "quý 3", "quý 4", "nửa đầu năm", "nửa cuối năm"]}


def secprose_unit(lang: str, tset: str, i: int) -> str:
    """A paragraph of 4-8 sentences about prompt injection and its defences, in a guide's voice."""
    r = unit_rng(f"secprose_{lang}", tset, i)
    vi = lang == "vi"
    cat = (SEC_VI if vi else SEC_EN)[tset]
    sents = r.sample(cat, min(len(cat), r.randint(4, 8)))
    org = r.choice((ORGS_VI if vi else ORGS)[tset])
    team = r.choice((TEAMS_VI if vi else TEAMS)[tset])
    tool = r.choice((TOOLS_VI if vi else TOOLS)[tset])
    q = r.choice(QUARTERS["vi" if vi else "en"])
    n, k = r.randint(40, 900), r.randint(2, 30)
    text = " ".join(s.format(org=org, team=team, tool=tool, q=q, n=n, k=k) for s in sents)
    return text + "\n"


GENERATORS = {
    "human_log_en": ("en", lambda s, i: human_log_unit("en", s, i)),
    "human_log_vi": ("vi", lambda s, i: human_log_unit("vi", s, i)),
    "secprose_en": ("en", lambda s, i: secprose_unit("en", s, i)),
    "secprose_vi": ("vi", lambda s, i: secprose_unit("vi", s, i)),
}


def unit(kind: str, tset: str, i: int) -> str:
    assert tset in SETS, tset
    return GENERATORS[kind][1](tset, i)


def sample_md5(n: int = 40) -> dict[str, str]:
    out = {}
    for kind in GENERATORS:
        for s in SETS:
            out[f"{kind}/{s}"] = hashlib.md5("".join(unit(kind, s, i) for i in range(n)).encode()).hexdigest()
    return out


def main(argv: list[str]) -> int:
    a, b = sample_md5(), sample_md5()
    if "--check" in argv and a != b:
        print("gen_filler_v6: output differs between two runs", file=sys.stderr)
        return 1
    print(json.dumps(a, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
