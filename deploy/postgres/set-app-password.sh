#!/bin/sh
# Sets the password of the application role ps_app from PS_APP_PASSWORD.
# Run it after the migrations, with superuser credentials in the libpq
# environment (PGHOST, PGUSER, PGDATABASE, PGPASSWORD). It is idempotent, so it
# also rotates the password.
#
# Outside development (GUARD_ENV other than "dev") it refuses known default or
# short passwords for both the superuser and ps_app.
set -eu

min_len=12

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# weak VALUE: true when VALUE is a known default or shorter than min_len.
weak() {
	case "$(lower "$1")" in
	ps | ps_app | postgres | password | secret | changeme | change-me | admin | \
		promptshield | guardspec | test | dev | change-me-in-production | dev-only-*)
		return 0 ;;
	esac
	[ "${#1}" -lt "$min_len" ]
}

if [ -z "${PS_APP_PASSWORD:-}" ]; then
	echo "PS_APP_PASSWORD is not set; set PS_APP_PASSWORD to a unique password of at least $min_len characters (see .env.example)" >&2
	exit 1
fi

if [ "$(lower "${GUARD_ENV:-}")" != "dev" ]; then
	failed=0
	if weak "${PGPASSWORD:-}"; then
		echo "POSTGRES_PASSWORD is a known default or shorter than $min_len characters; set POSTGRES_PASSWORD to a unique password (see .env.example), or GUARD_ENV=dev for local development" >&2
		failed=1
	fi
	if weak "$PS_APP_PASSWORD"; then
		echo "PS_APP_PASSWORD is a known default or shorter than $min_len characters; set PS_APP_PASSWORD to a unique password (see .env.example), or GUARD_ENV=dev for local development" >&2
		failed=1
	fi
	[ "$failed" -eq 0 ] || exit 1
fi

# The password goes in as a psql variable, quoted by psql, never spliced into SQL.
psql -v ON_ERROR_STOP=1 -q -v app_password="$PS_APP_PASSWORD" <<'SQL'
ALTER ROLE ps_app WITH PASSWORD :'app_password';
SQL
echo "ps_app password set"
