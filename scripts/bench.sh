#!/usr/bin/env bash
# Runs every performance budget check. PP_BENCH_SLACK relaxes time budgets
# (e.g. 3 on slow shared CI runners); memory and size budgets never relax.
set -euo pipefail
cd "$(dirname "$0")/.."
slack=${PP_BENCH_SLACK:-1}
cargo build --release --quiet
bin=target/release/pasteproof

echo "== engine"
cargo run --release --quiet -p pasteproof-engine --example bench -- --check

echo "== binary size"
size=$(stat -c %s "$bin" 2>/dev/null || stat -f %z "$bin")
echo "pasteproof binary: $((size / 1024)) KiB (budget 5120 KiB)"
(( size <= 5 * 1024 * 1024 )) || { echo "OVER"; exit 1; }

echo "== CLI cold start (200 runs)"
python3 - "$bin" "$slack" <<'PY'
import subprocess, sys, time
b, slack = sys.argv[1], float(sys.argv[2])
xs = []
for _ in range(200):
    s = time.perf_counter()
    subprocess.run([b, "guard", "--", "ls", "-la"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    xs.append((time.perf_counter() - s) * 1000)
xs.sort()
p50 = xs[100]
print(f"guard cold start p50 {p50:.2f} ms (budget {3*slack:.0f} ms)")
sys.exit(0 if p50 <= 3 * slack else 1)
PY

echo "== bash hook (Enter on an ordinary line, no process started)"
per=$(bash --norc -c "
  source <($bin init bash | sed -e '/^bind /d' -e 's/\[\[ \$- == \*i\* && /[[ /')
  s=\$EPOCHREALTIME; for ((i=0;i<2000;i++)); do READLINE_LINE='git status'; __pasteproof_check; done; e=\$EPOCHREALTIME
  echo \$(( (\${e/./}-\${s/./})/2000 ))")
echo "pre-filter: ${per} us per Enter (budget $((5000 * ${slack%.*})) us)"
(( per <= 5000 * ${slack%.*} )) || { echo "OVER"; exit 1; }
echo "all performance budgets met"
