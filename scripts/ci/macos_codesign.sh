# Shared codesign with Apple timestamp retries.
# Source from other scripts: # shellcheck source=scripts/ci/macos_codesign.sh
# Usage: macos_codesign --force --options runtime --timestamp --sign "$ID" "$path"

macos_codesign() {
	local out rc attempt=1 max=6 delay=5
	local -a fallback=()
	local skip_next=0 a
	while ((attempt <= max)); do
		set +e
		out="$(/usr/bin/codesign "$@" 2>&1)"
		rc=$?
		set -e
		if ((rc == 0)); then
			[[ -n "${out}" ]] && printf '%s\n' "${out}"
			return 0
		fi
		printf '%s\n' "${out}" >&2
		if printf '%s' "${out}" | grep -Eiq 'timestamp service is not available|timestamp server'; then
			echo "codesign TSA unavailable (attempt ${attempt}/${max}); retry in ${delay}s" >&2
			sleep "${delay}"
			if ((delay < 30)); then
				delay=$((delay * 2))
			fi
			attempt=$((attempt + 1))
			continue
		fi
		return "${rc}"
	done
	echo "warning: Apple timestamp service still down; signing without --timestamp" >&2
	fallback=()
	skip_next=0
	for a in "$@"; do
		if ((skip_next)); then
			skip_next=0
			continue
		fi
		case "${a}" in
		--timestamp | --timestamp=*) continue ;;
		esac
		fallback+=("${a}")
	done
	/usr/bin/codesign "${fallback[@]}" --timestamp=none
}
