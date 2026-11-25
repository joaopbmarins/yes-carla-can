#!/usr/bin/env bash
#
# run_receiver.sh - Executa o receptor AVTP no netns "receiver" salvando
#                   resultados em pasta dedicada (./results/<timestamp>/).
#
# Uso:
#   ./run_receiver.sh [-i IFACE] [-o OUT] [-n NETNS] [-p PYTHON]
#                     [-r RESULTS] [-f] [-x] [--dry-run]
#
# Opções:
#   -i  Interface no namespace       (default: veth-r)
#   -o  Pasta de saída explícita     (default: $RESULTS_ROOT/<timestamp>/)
#   -r  Raiz das execuções           (default: ./results)
#   -n  Network namespace            (default: receiver)
#   -p  Binário Python               (default: $CONDA_PREFIX/bin/python)
#   -f  "flat": sem subpasta timestamp
#   -x  Força 'xhost +local:sudo' mesmo em modo setpriv
#       --dry-run  Mostra caminhos e comando sem executar
#   -h  Ajuda
#

set -euo pipefail

# ---------- Configurações padrão ----------
NETNS="receiver"
IFACE="veth-r"
PYTHON_BIN="${CONDA_PREFIX:-}/bin/python"
SCRIPT_PATH="avtp_network/receiver.py"
RESULTS_ROOT="./results"
TIMESTAMPED=true
OUTPUT_DIR_OVERRIDE=""
FORCE_XHOST=false
DRY_RUN=false

TARGET_UID="$(id -u)"
TARGET_GID="$(id -g)"
ORIG_HOME="${HOME:-}"
ORIG_CWD="$(pwd)"

# ---------- Cores e logging ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_dry()   { echo -e "${CYAN}[DRY-RUN]${NC} $*"; }

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

# ---------- Parse (getopts + long option --dry-run) ----------
ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        DRY_RUN=true
    else
        ARGS+=("$arg")
    fi
done
set -- "${ARGS[@]}"

while getopts ":i:o:n:p:r:fxh" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        o) OUTPUT_DIR_OVERRIDE="$OPTARG" ;;
        n) NETNS="$OPTARG" ;;
        p) PYTHON_BIN="$OPTARG" ;;
        r) RESULTS_ROOT="$OPTARG" ;;
        f) TIMESTAMPED=false ;;
        x) FORCE_XHOST=true ;;
        h) usage ;;
        \?) log_error "Opção inválida: -$OPTARG"; usage ;;
        :)  log_error "Opção -$OPTARG requer argumento"; usage ;;
    esac
done

# ---------- Trava 1: não rodar de dentro de 'results/' ----------
if [[ "$(basename "$ORIG_CWD")" == "results" ]]; then
    log_error "Você está dentro de 'results/'. Rode da raiz do projeto."
    log_error "  cd ../ && ./run_receiver.sh $*"
    exit 1
fi

# ---------- Trava 2: rodar da raiz (onde existe avtp_network/) ----------
if [[ ! -d "avtp_network" ]]; then
    log_error "Pasta 'avtp_network/' não encontrada no CWD ($ORIG_CWD)."
    log_error "Rode este script a partir da raiz do projeto."
    exit 1
fi

# ---------- Validações básicas ----------
if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
    log_error "Python não encontrado em '$PYTHON_BIN'."
    log_error "Ative o ambiente conda: 'conda activate <env>'"
    exit 1
fi
[[ ! -f "$SCRIPT_PATH" ]] && { log_error "Script não encontrado: $SCRIPT_PATH"; exit 1; }

if ! sudo ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    log_error "Network namespace '$NETNS' não existe."
    log_error "Crie com: sudo ip netns add $NETNS"
    exit 1
fi
if ! sudo ip netns exec "$NETNS" ip link show "$IFACE" &>/dev/null; then
    log_error "Interface '$IFACE' não encontrada em '$NETNS'."
    exit 1
fi

# ---------- X11 ----------
USE_SETPRIV=false
command -v setpriv &>/dev/null && USE_SETPRIV=true

XAUTH="${XAUTHORITY:-$ORIG_HOME/.Xauthority}"

[[ -z "${DISPLAY:-}" ]] && log_warn "DISPLAY não definido — GUI pode não funcionar."

# ---------- Resolve pasta de saída ----------
if [[ -n "$OUTPUT_DIR_OVERRIDE" ]]; then
    OUTPUT_DIR="$OUTPUT_DIR_OVERRIDE"
elif $TIMESTAMPED; then
    OUTPUT_DIR="${RESULTS_ROOT}/$(date +%Y-%m-%d_%H-%M-%S)"
else
    OUTPUT_DIR="$RESULTS_ROOT"
fi

if $DRY_RUN; then
    log_dry "mkdir -p $OUTPUT_DIR"
else
    mkdir -p "$OUTPUT_DIR" || { log_error "Não foi possível criar '$OUTPUT_DIR'."; exit 1; }
fi
OUTPUT_DIR_ABS="$(realpath -m "$OUTPUT_DIR")"

# ---------- Symlink 'latest' defensivo ----------
if $TIMESTAMPED && [[ -z "$OUTPUT_DIR_OVERRIDE" ]]; then
    LATEST_LINK="${RESULTS_ROOT}/latest"
    if [[ -L "$LATEST_LINK" ]]; then
        if $DRY_RUN; then
            log_dry "ln -sfn $OUTPUT_DIR_ABS $LATEST_LINK"
        else
            ln -sfn "$OUTPUT_DIR_ABS" "$LATEST_LINK" \
                && log_info "latest -> $OUTPUT_DIR_ABS"
        fi
    elif [[ -e "$LATEST_LINK" ]]; then
        # 'latest' existe mas NÃO é symlink (é dir/arquivo real) → renomeia
        BAK="${LATEST_LINK}.bak-$(date +%Y-%m-%d_%H-%M-%S)"
        log_warn "'$LATEST_LINK' existe e não é symlink; renomeando para '$BAK'"
        if $DRY_RUN; then
            log_dry "mv $LATEST_LINK $BAK && ln -sfn $OUTPUT_DIR_ABS $LATEST_LINK"
        else
            mv "$LATEST_LINK" "$BAK"
            ln -sfn "$OUTPUT_DIR_ABS" "$LATEST_LINK" \
                && log_info "latest -> $OUTPUT_DIR_ABS"
        fi
    else
        if $DRY_RUN; then
            log_dry "ln -sfn $OUTPUT_DIR_ABS $LATEST_LINK"
        else
            ln -sfn "$OUTPUT_DIR_ABS" "$LATEST_LINK" \
                && log_info "latest -> $OUTPUT_DIR_ABS"
        fi
    fi
fi

# ---------- Monta env ----------
EXTRA_ENV=(
    "PYTHONPATH=."
    "HOME=$ORIG_HOME"
    "USER=$USER"
    "LOGNAME=$USER"
)
[[ -n "${DISPLAY:-}" ]] && EXTRA_ENV+=( "DISPLAY=$DISPLAY" )
[[ -f "$XAUTH"        ]] && EXTRA_ENV+=( "XAUTHORITY=$XAUTH" )

# Precisa de xhost?
NEED_XHOST=false
if ! $USE_SETPRIV; then
    NEED_XHOST=true
elif $FORCE_XHOST; then
    NEED_XHOST=true
fi

# ---------- Escolha do comando ----------
if $USE_SETPRIV; then
    if [[ ! -w "$OUTPUT_DIR_ABS" ]] && ! $DRY_RUN; then
        log_warn "Usuário UID=$TARGET_UID não tem escrita em $OUTPUT_DIR_ABS."
    fi
    CMD=(
        sudo -E ip netns exec "$NETNS"
        setpriv --reuid="$TARGET_UID" --regid="$TARGET_GID" --init-groups \
                --inh-caps=+net_raw --ambient-caps=+net_raw
        env "${EXTRA_ENV[@]}"
        "$PYTHON_BIN" "$SCRIPT_PATH"
        -i "$IFACE" -o "$OUTPUT_DIR_ABS"
    )
    MODE_DESC="setpriv + CAP_NET_RAW → UID=$TARGET_UID GID=$TARGET_GID"
else
    CMD=(
        sudo -E ip netns exec "$NETNS"
        env "${EXTRA_ENV[@]}"
        "$PYTHON_BIN" "$SCRIPT_PATH"
        -i "$IFACE" -o "$OUTPUT_DIR_ABS"
    )
    MODE_DESC="fallback root + xhost (chown ao final)"
    log_warn "setpriv não encontrado; fallback exige xhost e fará chown ao final."
fi

# ---------- Cleanup / traps ----------
cleanup() {
    if ! $DRY_RUN; then
        if ! $USE_SETPRIV; then
            log_info "Ajustando dono dos arquivos em $OUTPUT_DIR_ABS..."
            sudo chown -R "$TARGET_UID:$TARGET_GID" "$OUTPUT_DIR_ABS" 2>/dev/null \
                || log_warn "Falha ao ajustar dono de alguns arquivos."
        fi
        if $NEED_XHOST && command -v xhost &>/dev/null; then
            xhost -local:sudo >/dev/null 2>&1 || true
            log_info "Revogado 'xhost -local:sudo'."
        fi
    fi
}
trap cleanup EXIT
trap 'log_warn "Interrompido."; exit 130' INT TERM

# ---------- Sumário ----------
echo
log_info "CWD       : $ORIG_CWD"
log_info "Namespace : $NETNS"
log_info "Interface : $IFACE"
log_info "Output    : $OUTPUT_DIR_ABS"
log_info "Python    : $PYTHON_BIN"
log_info "Script    : $SCRIPT_PATH"
log_info "DISPLAY   : ${DISPLAY:-<não definido>}"
log_info "XAUTHORITY: ${XAUTH} $([[ -f "$XAUTH" ]] && echo '(ok)' || echo '(NÃO EXISTE)')"
log_info "Modo      : $MODE_DESC"
echo

if $NEED_XHOST; then
    if $DRY_RUN; then
        log_dry "xhost +local:sudo"
    elif command -v xhost &>/dev/null; then
        log_info "Aplicando 'xhost +local:sudo'."
        xhost +local:sudo >/dev/null 2>&1 || log_warn "Falha ao executar xhost."
    else
        log_warn "xhost indisponível; X11 como root pode falhar."
    fi
fi

log_info "Comando:"
printf '  %q ' "${CMD[@]}"
echo -e "\n"

# ---------- Dry-run para aqui ----------
if $DRY_RUN; then
    log_dry "Nada foi executado (--dry-run)."
    exit 0
fi

# ---------- Execução ----------
if "${CMD[@]}"; then
    RC=0
else
    RC=$?
    log_error "Receiver terminou com código $RC."
fi

log_info "Resultados em: $OUTPUT_DIR_ABS"
exit "$RC"