#!/bin/bash
set -eo pipefail

echo "🛠️ Point realm SMTP at Mailpit (email-binding OTP)"

./kcadm.sh update realms/zeta-guard -s 'smtpServer."host"=mailpit' -s 'smtpServer."port"=1025' -s 'smtpServer."from"=zeta-guard@zeta-it.invalid'
