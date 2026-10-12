# CP5 — DPIA-lite cho lab

Bản mô tả học tập ngày 12/10/2026, không phải hồ sơ đánh giá tác động pháp lý chính thức.

1. **Dữ liệu nào?** Ticket trong `corpus/` là nội dung internal nhưng không tin cậy,
   có thể chứa lure và PII. `data/customers.json` là hồ sơ khách giả, gồm CCCD,
   SĐT, STK, email và `related_tickets`, được xử lý là restricted. Không dùng
   PII hoặc credential thật. Ledger lưu metadata và hash tham số, không lưu hồ sơ thô.

2. **Ai và mục đích nào?** `support_l1` được tìm/tóm tắt ticket, không mở private
   store. DPO được đọc hồ sơ liên quan để `support-reply`. Quyền lấy từ
   `data/principals.json`, kiểm giao với scope agent/cha và hạn UTC 5 phút.
   `--as dpo` chỉ chọn quyền giả lập, không xác minh danh tính người dùng.

3. **Đi qua đâu?** Run A kiểm policy và ghi ledger trước `search_docs`, lấy số
   ticket từ tên file và che PII trước khi tóm tắt. Run B chỉ nhận số ticket,
   kiểm quyền trước khi mở store, map qua `related_tickets`, rồi kiểm và ghi
   ledger trước mỗi `read_customer`. Hồ sơ không chuyển vào LLM hoặc lượt gửi.
   Khi phát hiện lure, một lượt kiểm riêng chỉ nhận URL; restricted + egress
   bị deny trước `http_post`. Sink thật chỉ nghe `127.0.0.1:10024`.

4. **Đã chặn/cho phép gì, còn giới hạn gì?** Baseline từng lure gửi một hồ sơ
   giả `KH-000999`, lưu 4 dòng trong `reports/attack-before.log`. Sau sửa, CLI
   DPO vẫn tổng hợp 45 ticket và có 21 quyết định đọc allow; `attack-after.log`
   là 0 byte. Ledger dòng 46 ghi deny `http_post`, reason và `on_behalf_of=dpo`,
   toàn bộ chain verify `True`. Test không đọc khách `KH-000777` chỉ được nêu
   trong lời attacker; support bị chặn nhưng DPO vẫn đọc hợp lệ. Tổng 58 test
   pass, không skip. Mock/marker không mô phỏng đầy đủ LLM thật; regex có thể
   bỏ sót PII; hash chain không phát hiện cắt đuôi hoặc tính lại cả chuỗi nếu
   thiếu mốc bên ngoài. Policy local chưa thay thế IAM, sandbox hay chặn mạng
   độc lập; lock/hook không bảo đảm mọi dependency/runtime an toàn.
