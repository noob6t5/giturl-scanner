from domain_filter import is_validurl

test_urls = [
    "http://example.com",
    "https://example.org/",
    "http://localhost:8080",
    "http://127.0.0.1:5000",
    "https://t.co/abc123",
    "https://stackoverflow.com/questions/123",
    "https://real-domain.com/page",
    "https://nonexistent.vulntrap.xyz/",
    "https://youtube.com/watch?v=abc",
    "https://github.com/noob6t5/repo",
]

print("Filtered Results:\n")
for url in test_urls:
    print(f"{url} => {'✔️ VALID' if is_validurl(url) else '❌ FILTERED'}")
