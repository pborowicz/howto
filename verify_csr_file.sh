#by Paul Borowicz

if [ "$1" = "" -o "$1" = "-h" ]; then
  echo "Usage: $0 <csr_file>"
  exit
fi

openssl req -verify -text -noout -in $1 | more
