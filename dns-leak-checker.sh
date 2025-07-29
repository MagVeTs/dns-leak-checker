#!/usr/bin/env bash
set -euo pipefail
##############################################################################
# DNS-Leak-Checker – discovers internal IP & suspicious CNAME leakage
# Works with: live Amass scan OR previously-generated Amass output file.
# Bash 3.2 compatible (macOS default).
##############################################################################

################################# 0. Globals #################################
DOMAIN=""; DOMAIN_LIST=""; INPUT_AMASS=""
OUTPUT_PREFIX=""; EXPORT_JSON=false; EXPORT_CSV=false
VERBOSE=false; LOG_FILE=""; FORCE_UPGRADE=false
ALLOWLIST_CNAME_FILE="allowlist_cnames.txt"
# NEW: Define the output folder name and a variable for its parent directory.
OUTPUT_PARENT_DIR="."
OUTPUT_FOLDER_NAME="dns-leak-checker-output"
OUTPUT_DIR="" # This will be constructed after arguments are parsed.

log()   { [[ "$VERBOSE" == true ]] && echo -e "[*] $*"; }
fatal() { echo "[✘] $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || fatal "$1 is required."; }

################################ 1. Upgrade Amass ############################
upgrade_amass_latest() {
  log "Upgrading / installing Amass …"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    need_cmd brew
    brew update >/dev/null
    brew list amass &>/dev/null && brew upgrade amass || brew install amass
  else
    need_cmd curl; need_cmd unzip; need_cmd sudo
    local url
    url=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest |
          grep linux_amd64.zip | cut -d '"' -f 4)
    if [[ -z "$url" ]]; then fatal "No linux_amd64 Amass release asset found."; fi
    local tmp; tmp=$(mktemp -d)
    curl -sSL "$url" -o "$tmp/amass.zip"
    unzip -q "$tmp/amass.zip" -d "$tmp"
    sudo install "$tmp"/*/amass /usr/local/bin/amass
    rm -rf "$tmp"
  fi
  log "✔ Amass installed/upgraded."
}

############################### 2. Locate Amass ##############################
select_best_amass() {
  local path_bin
  if path_bin=$(command -v amass 2>/dev/null); then
    echo "$path_bin"
    return 0
  fi
  local brew_bin=""
  if command -v brew >/dev/null 2>&1; then
    brew_bin="$(brew --prefix 2>/dev/null)/bin/amass"
  fi
  local -a candidates=(
    "$brew_bin"
    /opt/homebrew/bin/amass
    /usr/local/bin/amass
    /usr/bin/amass
  )
  local c
  for c in "${candidates[@]}"; do
    if [[ -x "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  fatal "Amass not found. Install it (brew install amass) or supply --input-amass."
}

################################ 4. Usage / CLI ##############################
usage() {
cat <<EOF
Usage:
  $0 --domain example.com [options]
  $0 --domain-list list.txt [options]
  $0 --input-amass amass.txt [options]

Options:
  --output-dir <path>      Specify a parent directory for the output folder (default: current directory)
  --output-prefix <name>   Prefix for all output report files
  --export-json            Write JSON report
  --export-csv             Write CSV report
  --upgrade-amass          Force upgrade of Amass before scanning
  --log-file <file>        Tee console output to file
  --verbose                Chatty output
  --help                   Show this help
EOF
exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)        DOMAIN="$2"; shift 2 ;;
    --domain-list)   DOMAIN_LIST="$2"; shift 2 ;;
    --input-amass)   INPUT_AMASS="$2"; shift 2 ;;
    # NEW: Add argument for setting the output directory path.
    --output-dir)    OUTPUT_PARENT_DIR="$2"; shift 2;;
    --output-prefix) OUTPUT_PREFIX="$2"; shift 2 ;;
    --export-json)   EXPORT_JSON=true; shift ;;
    --export-csv)    EXPORT_CSV=true; shift ;;
    --upgrade-amass) FORCE_UPGRADE=true; shift ;;
    --log-file)      LOG_FILE="$2"; shift 2 ;;
    --verbose)       VERBOSE=true; shift ;;
    --help)          usage ;;
    *)               echo "Unknown option: $1"; usage ;;
  esac
done
if [[ -z "$DOMAIN$DOMAIN_LIST$INPUT_AMASS" ]]; then
  usage
fi
if [[ -n "$LOG_FILE" ]]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
fi

# NEW: Construct the final output path and create the directory.
OUTPUT_DIR="${OUTPUT_PARENT_DIR}/${OUTPUT_FOLDER_NAME}"
mkdir -p "$OUTPUT_DIR"
log "All output will be saved in: $OUTPUT_DIR"

################################ 5. Amass gating #############################
NEED_AMASS=false
if [[ -n "$DOMAIN" || -n "$DOMAIN_LIST" ]]; then
  NEED_AMASS=true
fi
AMASS_BIN=""
if $NEED_AMASS; then
  if $FORCE_UPGRADE; then
    upgrade_amass_latest
  fi
  if ! command -v amass >/dev/null 2>&1; then
    upgrade_amass_latest
  fi
  AMASS_BIN=$(select_best_amass)
  log "Using Amass: $AMASS_BIN ($("$AMASS_BIN" -version 2>&1 | head -n1 || echo 'unknown version'))"
fi

############################### 6. Regexes ###################################
PRIV_IP_REGEX='^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|169\.254\.)'
CNAME_REGEX='(internal-.*\.elb\.amazonaws\.com$|\.rds\.amazonaws\.com$|\.cache\.amazonaws\.com$|\.internal\.cloudapp\.net$|\.database\.windows\.net$|\.redis\.cache\.windows\.net$|\.c\..*\.internal$|\.oraclevcn\.com$|\.internal[-.])'

################################ 7. Reporter #################################
report() {
  local prefix=$1 ia=$2 ca=$3 wa=$4
  eval "local -a I=(\"\${${ia}[@]:-}\")"
  eval "local -a C=(\"\${${ca}[@]:-}\")"
  eval "local -a W=(\"\${${wa}[@]:-}\")"

  local old_ifs=$IFS
  IFS=$'\n'
  # shellcheck disable=SC2207
  local -a UI=($(printf '%s\n' "${I[@]}" | sed '/^$/d' | sort -u))
  # shellcheck disable=SC2207
  local -a UC=($(printf '%s\n' "${C[@]}" | sed '/^$/d' | sort -u))
  # shellcheck disable=SC2207
  local -a UW=($(printf '%s\n' "${W[@]}" | sed '/^$/d' | sort -u))
  IFS=$old_ifs

  echo -e "\n================ 🧾  SUMMARY ================"
  echo "Internal IP leaks   : ${#UI[@]}"
  echo "Suspicious CNAMEs   : ${#UC[@]}"
  echo "Wildcard subdomains : ${#UW[@]}"
  echo "Total affected assets : $(( ${#UI[@]} + ${#UC[@]} + ${#UW[@]} ))"
  echo "============================================="

  if $EXPORT_JSON; then
    local -a jq_args=()
    if ((${#UI[@]} > 0)); then
      jq_args+=(--argjson i "$(printf '%s\n' "${UI[@]}" | jq -R 'split("\t") | {subdomain: .[0], ip_address: .[1]}' | jq -s .)")
    else
      jq_args+=(--argjson i '[]')
    fi
    if ((${#UC[@]} > 0)); then
      jq_args+=(--argjson c "$(printf '%s\n' "${UC[@]}" | jq -R 'split("\t") | {subdomain: .[0], target: .[1]}' | jq -s .)")
    else
      jq_args+=(--argjson c '[]')
    fi
    if ((${#UW[@]} > 0)); then
      jq_args+=(--argjson w "$(printf '%s\n' "${UW[@]}" | jq -R . | jq -s .)")
    else
      jq_args+=(--argjson w '[]')
    fi
    jq -n "${jq_args[@]}" \
      '{internal_leaks:$i, cname_leaks:$c, wildcard_leaks:$w}' \
      > "$OUTPUT_DIR/${prefix}.json"
    echo "[+] JSON → $OUTPUT_DIR/${prefix}.json"
  fi

  if $EXPORT_CSV; then
    {
      echo "Type,Subdomain,Target"
      if ((${#UI[@]} > 0)); then
        printf '%s\n' "${UI[@]}" | while IFS=$'\t' read -r sub ip; do echo "Internal IP,\"$sub\",\"$ip\""; done
      fi
      if ((${#UC[@]} > 0)); then
        printf '%s\n' "${UC[@]}" | while IFS=$'\t' read -r sub target; do echo "Suspicious CNAME,\"$sub\",\"$target\""; done
      fi
      if ((${#UW[@]} > 0)); then
        printf '%s\n' "${UW[@]}" | while read -r l; do echo "Wildcard,\"$l\",\"\""; done
      fi
    } > "$OUTPUT_DIR/${prefix}.csv"
    echo "[+] CSV  → $OUTPUT_DIR/${prefix}.csv"
  fi

  local md="$OUTPUT_DIR/${prefix}.md"
  {
    echo "# DNS Leak Report – $prefix"
    echo
    echo "## Internal IP leaks (${#UI[@]})"
    if ((${#UI[@]} > 0)); then
      echo
      echo "| Subdomain | IP Address |"
      echo "|---|---|"
      printf '%s\n' "${UI[@]}" | while IFS=$'\t' read -r sub ip; do
        echo "| \`$sub\` | \`$ip\` |"
      done
    fi
    echo
    echo "## Suspicious CNAMEs (${#UC[@]})"
    if ((${#UC[@]} > 0)); then
      echo
      echo "| Subdomain | CNAME Target |"
      echo "|---|---|"
      printf '%s\n' "${UC[@]}" | while IFS=$'\t' read -r sub target; do
        echo "| \`$sub\` | \`$target\` |"
      done
    fi
    echo
    echo "## Wildcard subdomains (${#UW[@]})"
    if ((${#UW[@]} > 0)); then
      printf '%s\n' "${UW[@]}" | sed 's/^/- `/' | sed 's/$/`/'
    fi
  } > "$md"
  echo "[+] Markdown → $md"

  if command -v pandoc >/dev/null 2>&1; then
    pandoc "$md" -f markdown -t html -o "$OUTPUT_DIR/${prefix}.html"
    echo "[+] HTML → $OUTPUT_DIR/${prefix}.html"
  fi
}

############################### 8. Parser ####################################
detect_leaks_text() {
  local txt=$1 prefix=$2
  local -a internal=() cname=() wild=()

  log "Parsing Amass data from '$txt'..."

  if [[ ! -s "$txt" ]]; then
    log "Warning: Amass output file is empty. No leaks to report."
    report "$prefix" internal cname wild
    return
  fi

  local line_type sub target
  while IFS=$'\t' read -r line_type sub target; do
    case "$line_type" in
      "IP")
        if [[ "$target" =~ $PRIV_IP_REGEX ]]; then
          internal+=("$sub"$'\t'"$target")
        fi
        ;;
      "CNAME")
        if [[ -f "$ALLOWLIST_CNAME_FILE" ]] && grep -qFx "$target" "$ALLOWLIST_CNAME_FILE"; then
          continue
        fi
        if [[ "$target" =~ $CNAME_REGEX ]]; then
          cname+=("$sub"$'\t'"$target")
        fi
        ;;
    esac
  done < <(sed -E 's/\x1b\[[0-9;]*m//g' "$txt" | awk '
      $4 == "a_record"     { print "IP\t" $1 "\t" $6 }
      $4 == "aaaa_record"  { print "IP\t" $1 "\t" $6 }
      $4 == "cname_record" { print "CNAME\t" $1 "\t" $6 }
    ')

  while IFS= read -r sub; do
    wild+=("$sub")
  done < <(sed -E 's/\x1b\[[0-9;]*m//g' "$txt" | grep '^\*\.' | awk '{print $1}')

  report "$prefix" internal cname wild
}

################################ 9. Scan orchestrator ########################
scan_domain() {
  local domain=$1
  local prefix="${OUTPUT_PREFIX:-$domain}"
  local amass_output_file="$OUTPUT_DIR/${prefix}.amass.txt"

  log "Running Amass against '$domain', saving full output to '$amass_output_file'..."
  "$AMASS_BIN" enum -d "$domain" -o "$amass_output_file" || true

  detect_leaks_text "$amass_output_file" "$prefix"
}

################################ 10. Main dispatcher #########################
need_cmd jq

if [[ -n "$DOMAIN" ]]; then
  scan_domain "$DOMAIN"
elif [[ -n "$DOMAIN_LIST" ]]; then
  while IFS= read -r d || [[ -n "$d" ]]; do
    if [[ -z "$d" || "$d" =~ ^# ]]; then
      continue
    fi
    scan_domain "$d"
  done < "$DOMAIN_LIST"
elif [[ -n "$INPUT_AMASS" ]]; then
  if [[ ! -f "$INPUT_AMASS" ]]; then
    fatal "File $INPUT_AMASS not found."
  fi
  prefix="${OUTPUT_PREFIX:-amass-report}"
  detect_leaks_text "$INPUT_AMASS" "$prefix"
fi

echo "[✔] Done."