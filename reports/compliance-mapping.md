# CP5 — Mapping control và bằng chứng

Đối chiếu ngày 12/10/2026. Các trang Chính phủ xác nhận tên và số hiệu văn bản;
điều khoản cụ thể **chưa xác minh** từ toàn văn nên không nêu nghĩa vụ theo điều.
Các chủ đề/control dưới đây là liên hệ học tập của lab, không phải chứng nhận tuân thủ.

| Nguồn / chủ đề | Control đã làm | Bằng chứng file:dòng thật | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?pageid=27160&docid=214590); chủ đề bảo vệ dữ liệu | Detect/redact 4 loại PII; không gửi restricted ra sink | `agent/pii.py:51`, `agent/pii.py:74`, `agent/policy.py:68`; POST trước ở `reports/attack-before.log:1`; deny sau ở `reports/ledger.jsonl:46` | Điều khoản chưa xác minh. Regex chỉ được đo trên dữ liệu giả, không nhận diện mọi PII. |
| [NĐ 356/2025/NĐ-CP — Thi hành Luật Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?pageid=27160&docid=216387); chủ đề giới hạn truy cập, ghi nhận xử lý | Kiểm principal/purpose/scope/expiry trước đọc; ledger có reason và hash tham số | `agent/policy.py:61`, `agent/runner.py:100`, `agent/runner.py:131`, `agent/ledger.py:50` | Điều khoản chưa xác minh. Không triển khai quy trình pháp lý, thông báo, consent hoặc quyền chủ thể dữ liệu. |
| [Luật 134/2025/QH15 — Trí tuệ nhân tạo](https://vanban.chinhphu.vn/?pageid=27160&docid=216334); chủ đề kiểm soát và giải thích hành động agent | Tách đọc ticket/đọc hồ sơ; giải thích từng allow/deny bằng ledger | `agent/runner.py:115`, `agent/runner.py:131`, `agent/runner.py:167`; `reports/ledger.jsonl:46` | Điều khoản chưa xác minh. Mock, quyền giả lập và test không chứng minh an toàn của hệ thống AI thực tế. |
| [OWASP ASI01 — Agent Goal Hijack](https://genai.owasp.org/download/52117/) | Run B nhận số ticket từ tên file; chỉ map qua related_tickets; chặn gửi riêng | `agent/runner.py:115`, `agent/runner.py:131`, `agent/runner.py:167`; `tests/test_split.py:75` | Chỉ replay 4 lure và tình huống khách không liên quan của lab; nhận diện lure vẫn dựa marker. |
| [OWASP ASI03 — Identity & Privilege Abuse](https://genai.owasp.org/download/52117/) | Giao quyền principal/agent/cha, purpose và UTC expiry; support bị chặn, DPO vẫn đọc hợp lệ | `agent/policy.py:94`, `agent/policy.py:99`, `agent/policy.py:114`; `data/principals.json:2`; `tests/test_obo.py:51` | `--as` không xác thực người dùng; scope do runner local tạo, không phải delegation có chữ ký. |
| [OWASP ASI04 — Agentic Supply Chain Vulnerabilities](https://genai.owasp.org/download/52117/) | Pin dependency có SHA-256; hook Gitleaks pin; quét lịch sử và ghi cách rotate | `requirements.lock:209`, `requirements.lock:213`, `.pre-commit-config.yaml:3`, `.gitleaks.toml:7`, `reports/secrets-incident.md:16` | Hash không chứng minh package an toàn; scanner không bắt mọi secret; không kiểm MCP/runtime rug pull. |

Sau lượt CLI DPO với sink thật: `reports/attack-after.log` rỗng **0 byte**,
không có dòng để trích. Ledger có 46 dòng và verify `True`; số dòng sẽ thay đổi
nếu chạy thêm. Bằng chứng và giới hạn chi tiết nằm trong `reports/verification.md`.
