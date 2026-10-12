# CP4 — Token giả trong lịch sử Git

Kiểm tra ngày 12/10/2026 bằng Gitleaks **8.30.1**, tải từ
[release chính thức](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).
SHA-256 của archive đã được đối chiếu với checksum cùng release. Chỉ dùng
`--redact`; không chép giá trị token vào báo cáo.

| Lệnh | Kết quả thực tế |
|---|---|
| `gitleaks version` | `8.30.1` |
| `gitleaks git --config .gitleaks.toml --redact .` | Exit 1; 6 commit đã quét, 1 finding mong đợi |
| `gitleaks dir --config .gitleaks.toml --redact .` lần đầu | Exit 1; 3 finding trong `.venv/` |
| Hai lệnh quét sau allowlist | Lịch sử vẫn exit 1, đúng 1 finding; file hiện tại exit 0, không finding |

Finding lịch sử: commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`
(`1bdd849`), file `lab-fake-secret.txt:1`, rule `lab24-synthetic-token`.
Đây là token tổng hợp vô hiệu được đề bài cài sẵn, không phải credential thật.

Ba finding đầu ở thư mục hiện tại là mẫu trong môi trường local:
`setuptools/_distutils/msvccompiler.py:45` (generic-api-key) và README của
Gitleaks tại dòng 47 (sidekiq-secret), 574 (generic-api-key), đều dưới `.venv/`.
File setuptools chứa alias hàm registry của win32api, không phải credential;
README chứa ví dụ minh họa finding, không phải secret đang sử dụng.
Đã xác định là false positive từ thư viện/ví dụ scanner và thêm allowlist chỉ
cho đường dẫn `.venv/` trong `.gitleaks.toml`. Không bỏ qua repo hoặc tắt rule
`lab24-synthetic-token`; quét lịch sử lại vẫn bắt đúng token giả.

Nếu là secret thật: thu hồi/rotate tại dịch vụ cấp token trước, kiểm log sử dụng
để tìm truy cập sai, thay credential ở các ứng dụng dùng nó, rồi xử lý bản sao
trong Git, cache, artifact và log. Xóa file ở HEAD không làm token cũ vô hiệu.

Hook dùng repo Gitleaks chính thức, pin `rev: v8.30.1`, `gitleaks-system`,
`pass_filenames: false`; entry quét thư mục repo hiện tại để cả thay đổi chưa
stage cũng được kiểm. `pre-commit install` và `pre-commit run --all-files`
đã chạy thành công. Scanner nằm trong `.venv/Scripts`; kích hoạt `.venv`
trước khi chạy hook thủ công. Quét lịch sử là bước độc lập với hook.

Lock pin phiên bản và SHA-256 giúp tái lập dependency và phát hiện artifact
khác hash; hook tìm chuỗi secret. Cả hai không bảo đảm package không có mã độc,
không kiểm toàn bộ hành vi runtime và không thay thế thu hồi token đã lộ.
