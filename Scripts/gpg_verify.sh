#!/bin/bash

echo "Verifying signature files in the current directory..."

for sig_file in *.sig; do
  if [[ -f "$sig_file" ]]; then
    original_file="${sig_file%.sig}"
    echo ""
    echo "Verifying signature for \"$original_file\" using \"$sig_file\"..."
    gpg --verify "$sig_file" "$original_file"
    if [ $? -ne 0 ]; then
      echo "[ERROR] Signature verification failed for \"$original_file\". The file may have been tampered with or the signature is invalid."
    else
      echo "[OK] Signature verification successful for \"$original_file\"."
    fi
  fi
done

echo ""
echo "Verification process complete."
