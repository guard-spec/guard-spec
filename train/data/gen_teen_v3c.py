"""v3c: benign Vietnamese chat-style (teencode) text, written in chat spelling from the start.

Written for classifier v3c after the eval set showed v3b blocking 3.5% of benign teencode rows (v2
1.4%). The rows are written from general knowledge of Vietnamese chat writing, not from eval/ rows
(eval/ was not read) and not from validation errors: everyday chat, shopping and school, plus the
admin and meta vocabulary that attacks also use ("ad", "bot", "lệnh", "pass", "hướng dẫn", "bỏ qua",
"quên", "prompt", "AI", "hệ thống"), in ordinary senses. Rows are bases in chat spelling; build_data
adds a second randomized spelling with common.teencode_v2 (table A) for half of them.

Training only (template set A); validation is unchanged so v3c arms are compared on the same rows.

Returns rows: dict(text, labels, lang, group).
"""

from __future__ import annotations

from common import pick, rng

B = ["benign"]

FRAMES = [
    # everyday chat
    "{ten} ơi tối nay đi {di} ko, {ly} :))",
    "ê {ten}, mai {viec} chưa, nhắc tui vs",
    "bỏ qua tin nhắn lúc nãy nha, tui gửi nhầm {nham} r",
    "quên mất hnay sn {ng}, h mua quà j kịp ta",
    "trời ơi {than}, mệt xỉu luôn á",
    "cho hỏi {sp} còn size {size} ko shop, mk lấy {sl} cái",
    "shop ơi đơn {ma} sao chưa giao z, đợi {lau} r á",
    "ai có đề cương {mon} ko cho mk xin vs, mai thi r",
    "cô dặn nộp bài {mon} qua {kenh} trc {gio} nha cả lớp",
    "nhóm mk họp lúc {gio} nha, đứa nào bận thì ib",
    # admin / tech vocabulary in ordinary senses
    "ad ơi duyệt bài giúp e vs, đăng từ {lau} r mà chưa lên",
    "ad nhóm ơi cho e hỏi nội quy là ko đc đăng {cam} đúng ko ạ",
    "mk quên pass {tk} r, lấy lại kiểu j z mn",
    "lệnh {lenh} chạy báo lỗi {loi} là sao ae, cứu vs",
    "máy e cài {app} cứ bắt nhập pass admin, nhập của ai ạ",
    "hệ thống {ht} bảo trì tới {gio} hả mn, vô ko đc",
    "đổi pass wifi nhà xong h tivi ko kết nối đc, chỉ mk vs",
    "bot của shop rep sai giá {sp} kìa, ai báo shop giùm",
    "con bot cskh ko hiểu j hết, toàn rep câu mẫu :((",
    "hướng dẫn mk cài {app} trên điện thoại vs, làm mãi ko đc",
    "e mới vô làm, sếp bảo xin quyền admin {ht} thì hỏi ai ạ",
    "ko nhận đc mã otp {tk} thì làm sao mn, chờ {lau} r",
    # meta talk about AI / prompts / rules
    "mn ơi prompt là j z, thấy ai cũng nói mà ko hiểu",
    "chatgpt viết văn hay ghê, mk nhờ nó sửa bài {mon} luôn",
    "có ai dùng ai để học {mon} ko, chỉ mk cách hỏi cho nó trả lời đúng vs",
    "đọc báo thấy nói jailbreak chatbot là j z mn, nghe ghê quá",
    "bot nhóm mk có luật ko rep tin nhắn sau 10h tối, ai chỉnh lại giúp",
    "mk muốn viết hướng dẫn cho bot trả lời khách lịch sự hơn, viết kiểu j",
    "sao con ai nó ko chịu trả lời câu {cau} z, bảo vi phạm j đó",
    "bỏ qua phần mở đầu đi, đọc từ chương {so} là hiểu r",
    "quên hết công thức {mon} r, ai chỉ lại vs huhu",
    "thôi kệ đi, bỏ qua chuyện hôm qua nha bạn ơi",
    "nhờ bạn tóm tắt giùm mk bài {mon} trang {so} vs",
]
SLOTS = dict(
    ten=["Lan", "Tùng", "Vy", "Khoa", "Ngân", "Huy", "Thảo", "Bin", "Mít", "Su"],
    di=["ăn lẩu", "trà sữa", "xem phim", "đá banh", "karaoke", "hồ Tây", "chợ đêm"],
    ly=["tui bao", "lâu r ko gặp", "đang sale á", "chán quá"],
    viec=["nộp bài", "đóng quỹ lớp", "đi khám", "chuyển tiền nhà", "trả sách thư viện"],
    nham=["nhóm", "ảnh", "file", "sticker"],
    ng=["mẹ", "con bạn thân", "sếp", "em gái", "cô chủ nhiệm"],
    than=["kẹt xe quá", "mưa to quá", "deadline dí quá", "nóng quá"],
    sp=["áo khoác", "giày", "tai nghe", "nồi chiên", "son"],
    size=["M", "L", "38", "40"], sl=["1", "2", "3"],
    ma=["DH5521", "A1029", "#4471", "SP-883"], lau=["3 ngày", "1 tuần", "2 tiếng", "hôm qua"],
    mon=["toán", "văn", "lý", "hóa", "anh", "sử", "tin"],
    kenh=["zalo nhóm", "classroom", "email cô", "LMS"], gio=["8h", "9h tối", "trưa mai", "chủ nhật"],
    cam=["link bán hàng", "tin giả", "quảng cáo"], tk=["fb", "zalo", "gmail", "app ngân hàng", "shopee"],
    lenh=["npm install", "git push", "pip install", "ipconfig", "sudo apt update"],
    loi=["permission denied", "not found", "timeout", "access denied"],
    app=["zoom", "unikey", "office", "vpn công ty", "app ngân hàng"],
    ht=["chấm công", "email công ty", "CRM", "kho"], cau=["toán", "lịch sử", "về thuốc"],
    so=["3", "5", "12", "45"],
)
TAILS = ["", "", "", " :))", " =))", " hihi", " nha", " ạ", " huhu", " ^^", " kkk", " :v"]


def generate(n=700):
    r = rng("v3c.teen.train")
    seen, out, tries = set(), [], 0
    while len(out) < n and tries < n * 40:
        tries += 1
        fr = pick(r, FRAMES)
        t = fr.format(**{k: pick(r, v) for k, v in SLOTS.items() if "{" + k + "}" in fr}) + pick(r, TAILS)
        if t in seen:
            continue
        seen.add(t)
        out.append(dict(text=t, labels=B, lang="vi", group=f"v3c.vi.teen.train.{len(out)}"))
    return out
