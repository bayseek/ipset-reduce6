#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipset-reduce6 — IPv6 (and IPv4) CIDR prefix reducer for ipset hash:net

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
  - aggregate6     (system command, used for initial aggregation; 
                    https://github.com/job/aggregate6)

Usage:
  ipset-reduce6 [OPTIONS] [FILE ...]

  Reads CIDR prefixes (one per line, IPv4 or IPv6) from FILEs or stdin,
  reduces the number of distinct prefix-lengths, and prints the result.

Options:
  --ipset-reduce PERCENT        acceptable % increase in entries  (default 20)
  --ipset-reduce-entries ENTRIES minimum acceptable entries        (default 16384)
  --only-v6 / -6                process only IPv6 prefixes
  --only-v4 / -4                process only IPv4 prefixes
  --print-prefix STRING         print STRING before each output entry
                                (sets both --print-prefix-ips and -nets)
  --print-prefix-ips STRING     print STRING before single-host entries only
  --print-prefix-nets STRING    print STRING before subnet entries only
  --print-suffix STRING         print STRING after each output entry
                                (sets both --print-suffix-ips and -nets)
  --print-suffix-ips STRING     print STRING after single-host entries only
  --print-suffix-nets STRING    print STRING after subnet entries only
  --print-stats / -v            print reduction statistics to stderr
  --help / -h                   show this help and exit
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
from collections import defaultdict
from typing import List, Tuple, Union

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# ---------------------------------------------------------------------------
# Aggregation via aggregate6
# ---------------------------------------------------------------------------

def aggregate_prefixes(lines: List[str], family: str | None = None) -> List[IPNetwork]:
    """Call aggregate6 to merge overlapping/adjacent prefixes."""
    cmd = ["aggregate6"]
    if family == "6":
        cmd.append("-6")
    elif family == "4":
        cmd.append("-4")

    proc = subprocess.run(
        cmd,
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"aggregate6 error: {proc.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    result: List[IPNetwork] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        result.append(ipaddress.ip_network(line, strict=False))
    return result


# ---------------------------------------------------------------------------
# Splitting a CIDR network into sub-CIDRs using only enabled prefix lengths
# ---------------------------------------------------------------------------

def split_net_enabled(net: IPNetwork, enabled: set[int]) -> List[IPNetwork]:
    """
    Given a single CIDR *net*, decompose it into the smallest set of
    sub-CIDRs whose prefix lengths are all in *enabled*.

    If the net's own prefix is enabled, returns [net] unchanged.
    Otherwise the net is split into its two halves (prefix+1) and
    each half is processed recursively.
    """
    if net.prefixlen in enabled:
        return [net]

    max_pfx = net.max_prefixlen  # 32 for v4, 128 for v6

    if net.prefixlen >= max_pfx:
        # Cannot split further; should not happen if max_pfx is enabled
        return [net]

    # split into two halves
    subnets = list(net.subnets(prefixlen_diff=1))
    result: List[IPNetwork] = []
    for sub in subnets:
        result.extend(split_net_enabled(sub, enabled))
    return result


def count_entries_for_net(net: IPNetwork, enabled: set[int]) -> dict[int, int]:
    """Count how many entries each prefix-length produces for a single net."""
    counters: dict[int, int] = defaultdict(int)
    for sub in split_net_enabled(net, enabled):
        counters[sub.prefixlen] += 1
    return dict(counters)


# ---------------------------------------------------------------------------
# Count prefixes produced by current enabled set
# ---------------------------------------------------------------------------

def count_prefixes(networks: List[IPNetwork],
                   enabled: set[int]) -> dict[int, int]:
    """Return {prefix_length: count} for the full network list."""
    counters: dict[int, int] = defaultdict(int)
    for net in networks:
        for sub in split_net_enabled(net, enabled):
            counters[sub.prefixlen] += 1
    return dict(counters)


# ---------------------------------------------------------------------------
# The reduction algorithm  (port of ipset_reduce() from ipset_reduce.c)
# ---------------------------------------------------------------------------

def ipset_reduce(networks: List[IPNetwork], reduce_pct: int,
                 reduce_entries: int, max_prefix: int,
                 verbose: bool = False) -> set[int]:
    """
    Compute the set of enabled prefix lengths after reduction.

    Returns a set of enabled prefix-length ints.
    """
    enabled: set[int] = set(range(max_prefix + 1))

    # --- initial count (each aggregated CIDR is exactly 1 entry) ---
    counters: dict[int, int] = defaultdict(int)
    for net in networks:
        counters[net.prefixlen] += 1

    # disable prefixes that have zero entries
    present_prefixes = set(counters.keys())
    enabled = present_prefixes.copy()

    total = sum(counters.values())
    initial_prefixes = len(present_prefixes)

    if verbose:
        print(f"\nInitial: {total} entries across {initial_prefixes} prefixes",
              file=sys.stderr)
        for p in sorted(counters):
            if counters[p]:
                print(f"  /{p}: {counters[p]} entries", file=sys.stderr)

    # --- acceptable ceiling ---
    acceptable = int(total * (100 + reduce_pct) / 100)
    if acceptable < reduce_entries:
        acceptable = reduce_entries

    if verbose:
        print(f"Acceptable ceiling: {acceptable} entries", file=sys.stderr)

    # --- iterative reduction ---
    eliminated = 0

    while total < acceptable:
        best_src: int | None = None
        best_dst: int | None = None
        best_increase = acceptable * 10  # sentinel

        # sorted enabled prefixes (shorter first = fewer bits = broader nets)
        sorted_enabled = sorted(enabled)

        for idx, i in enumerate(sorted_enabled):
            if counters.get(i, 0) == 0:
                continue

            # find the nearest longer (numerically next) enabled prefix
            for j in sorted_enabled[idx + 1:]:
                if counters.get(j, 0) == 0:
                    continue

                # eliminating prefix i means each /i entry becomes
                # 2^(j-i) entries of /j
                multiplier = 1 << (j - i)
                increase = counters[i] * (multiplier - 1)

                if increase < best_increase:
                    best_increase = increase
                    best_src = i
                    best_dst = j
                break  # only consider nearest non-empty dest

        if best_src is None or best_dst is None:
            if verbose:
                print("  Nothing more to reduce", file=sys.stderr)
            break

        # recompute exact multiplier
        multiplier = 1 << (best_dst - best_src)
        increase = counters[best_src] * multiplier - counters[best_src]

        if total + increase > acceptable:
            if verbose:
                print(f"  Cannot merge /{best_src} -> /{best_dst}: "
                      f"increase {increase} would exceed ceiling "
                      f"({total}+{increase} > {acceptable})", file=sys.stderr)
            break

        if verbose:
            print(f"  Merge /{best_src} ({counters[best_src]} entries) "
                  f"-> /{best_dst}: +{increase} entries", file=sys.stderr)

        total += increase
        counters[best_dst] = counters.get(best_dst, 0) + increase + counters[best_src]
        counters[best_src] = 0
        enabled.discard(best_src)
        eliminated += 1

    if verbose:
        remaining = initial_prefixes - eliminated
        print(f"\nEliminated {eliminated}/{initial_prefixes} prefixes "
              f"({remaining} remain), total entries now {total}\n",
              file=sys.stderr)

    return enabled


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ipset-reduce6",
        description=(
            "Reduce the number of distinct CIDR prefix-lengths in an IP set, "
            "trading a bounded increase in entry count for fewer unique masks. "
            "Works with both IPv4 and IPv6. "
            "Requires 'aggregate6' for initial prefix merging."
        ),
    )
    parser.add_argument(
        "--ipset-reduce",
        type=int,
        default=20,
        metavar="PERCENT",
        dest="reduce_pct",
        help="acceptable %% increase in entries (default: 20)",
    )
    parser.add_argument(
        "--ipset-reduce-entries",
        type=int,
        default=16384,
        metavar="ENTRIES",
        dest="reduce_entries",
        help="minimum acceptable entries (default: 16384)",
    )

    fam = parser.add_mutually_exclusive_group()
    fam.add_argument("-6", "--only-v6", action="store_true",
                     help="process only IPv6 prefixes")
    fam.add_argument("-4", "--only-v4", action="store_true",
                     help="process only IPv4 prefixes")

    parser.add_argument("-v", "--print-stats", action="store_true",
                        help="print reduction statistics to stderr")

    # -- print-prefix / print-suffix (iprange feature parity) --
    parser.add_argument("--print-prefix", default=None, metavar="STRING",
                        help="print STRING before each IP or CIDR "
                             "(sets both --print-prefix-ips and --print-prefix-nets)")
    parser.add_argument("--print-prefix-ips", default="", metavar="STRING",
                        help="print STRING before single-host entries (/32 or /128)")
    parser.add_argument("--print-prefix-nets", default="", metavar="STRING",
                        help="print STRING before subnet entries")
    parser.add_argument("--print-suffix", default=None, metavar="STRING",
                        help="print STRING after each IP or CIDR "
                             "(sets both --print-suffix-ips and --print-suffix-nets)")
    parser.add_argument("--print-suffix-ips", default="", metavar="STRING",
                        help="print STRING after single-host entries (/32 or /128)")
    parser.add_argument("--print-suffix-nets", default="", metavar="STRING",
                        help="print STRING after subnet entries")

    parser.add_argument("files", nargs="*", metavar="FILE",
                        help="input files (default: stdin)")

    args = parser.parse_args()
    verbose: bool = args.print_stats

    # resolve shorthand --print-prefix / --print-suffix
    if args.print_prefix is not None:
        args.print_prefix_ips = args.print_prefix
        args.print_prefix_nets = args.print_prefix
    if args.print_suffix is not None:
        args.print_suffix_ips = args.print_suffix
        args.print_suffix_nets = args.print_suffix

    # ---- read input ----
    raw_lines: List[str] = []
    if args.files:
        for path in args.files:
            if path == "-":
                raw_lines.extend(sys.stdin.read().splitlines())
            else:
                with open(path) as f:
                    raw_lines.extend(f.read().splitlines())
    else:
        raw_lines = sys.stdin.read().splitlines()

    # strip comments and blanks
    clean: List[str] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # handle lines that may come from ipset save format:
        # "add setname 1.2.3.0/24" -> extract the CIDR
        parts = line.split()
        if parts[0] in ("add", "create"):
            if len(parts) >= 3:
                line = parts[2]
            else:
                continue
        else:
            line = parts[0]
        clean.append(line)

    if not clean:
        sys.exit(0)

    # ---- determine family filter ----
    family_filter: str | None = None
    if args.only_v6:
        family_filter = "6"
    elif args.only_v4:
        family_filter = "4"

    # ---- separate v4 / v6 ----
    v4_lines: List[str] = []
    v6_lines: List[str] = []
    for cidr in clean:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                v4_lines.append(str(net))
            else:
                v6_lines.append(str(net))
        except ValueError:
            print(f"WARNING: skipping invalid entry: {cidr}", file=sys.stderr)

    results: List[str] = []

    # ---- process IPv4 if applicable ----
    if v4_lines and family_filter in (None, "4"):
        if verbose:
            print(f"=== IPv4: {len(v4_lines)} raw prefixes ===", file=sys.stderr)
        nets4 = aggregate_prefixes(v4_lines, "4")
        if verbose:
            print(f"After aggregation: {len(nets4)} prefixes", file=sys.stderr)
        enabled4 = ipset_reduce(nets4, args.reduce_pct, args.reduce_entries,
                                max_prefix=32, verbose=verbose)
        for net in nets4:
            for sub in split_net_enabled(net, enabled4):
                results.append(str(sub))

    # ---- process IPv6 if applicable ----
    if v6_lines and family_filter in (None, "6"):
        if verbose:
            print(f"=== IPv6: {len(v6_lines)} raw prefixes ===", file=sys.stderr)
        nets6 = aggregate_prefixes(v6_lines, "6")
        if verbose:
            print(f"After aggregation: {len(nets6)} prefixes", file=sys.stderr)
        enabled6 = ipset_reduce(nets6, args.reduce_pct, args.reduce_entries,
                                max_prefix=128, verbose=verbose)
        for net in nets6:
            for sub in split_net_enabled(net, enabled6):
                results.append(str(sub))

    # ---- output (with prefix/suffix decoration) ----
    pfx_ips  = args.print_prefix_ips
    pfx_nets = args.print_prefix_nets
    sfx_ips  = args.print_suffix_ips
    sfx_nets = args.print_suffix_nets

    for r in results:
        net = ipaddress.ip_network(r, strict=False)
        is_host = (net.prefixlen == net.max_prefixlen)  # /32 or /128
        if is_host:
            print(f"{pfx_ips}{r}{sfx_ips}")
        else:
            print(f"{pfx_nets}{r}{sfx_nets}")


if __name__ == "__main__":
    main()
