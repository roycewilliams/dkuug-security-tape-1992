#!/bin/sh
# This script prepares a wordlist for use with goodpass().
# It converts everything to lowercase, truncates to 8 chars,
# deletes words shorter than 5 chars, sorts, and deletes duplicates.
cat $* | cut -c1-8 | tr A-Z a-z | uniq | sort -u | awk 'length>5'
