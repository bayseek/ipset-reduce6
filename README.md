# ipset-reduce6
IPv6 (and IPv4) CIDR prefix reducer for ipset hash:net

Replicates the --ipset-reduce / --ipset-reduce-entries logic of
FireHOL's `iprange` (which is IPv4-only) and extends it to IPv6.

Algorithm (faithful port of iprange's ipset_reduce.c):

  1.  Read all prefixes from files/stdin.
  2.  Aggregate them (merge overlapping/adjacent) via `aggregate6`.
  3.  Count how many CIDR entries each prefix-length produces.
  4.  Compute an acceptable ceiling:
        acceptable = max(total * (1 + reduce_pct/100), reduce_entries)
  5.  Iteratively find the prefix-length whose elimination causes the
      smallest entry increase, merge it into the next longer enabled
      prefix, and repeat until the ceiling would be exceeded.
  6.  Re-split every range using only the surviving prefix-lengths and
      print the result.

Dependencies:
  - Python >=3.4   (ipaddress module)
  - aggregate6     (system command, used for initial aggregation)

Usage:
  ipset-reduce6 [OPTIONS] [FILE ...]

  Reads CIDR prefixes (one per line, IPv4 or IPv6) from FILEs or stdin,
  reduces the number of distinct prefix-lengths, and prints the result.

Options:
  --ipset-reduce PERCENT        acceptable % increase in entries  (default 20)
  --ipset-reduce-entries ENTRIES minimum acceptable entries        (default 16384)
  --only-v6 / -6                process only IPv6 prefixes
  --only-v4 / -4                process only IPv4 prefixes
  --print-stats / -v            print reduction statistics to stderr
  --help / -h                   show this help and exit
"""
