#!/bin/ksh
#
# health-check-v8.sh
# AIX6 health check - adjust network section so the ":" are aligned with other sections
# Keep running as root for best results.
#
# Usage: ./health-check-v8.sh
#

timestamp=$(date '+%Y%m%d%H%M')
outfile="healthcheck-${timestamp}.txt"
tmpdir="/tmp/hc_${timestamp}"
mkdir -p "$tmpdir"

sep_line() { printf '%s\n' "------------------------------------------------------------"; }

# Basic info
host=$(hostname 2>/dev/null || uname -n)
date_now=$(date '+%Y-%m-%d %H:%M:%S')
oslevel_full=$(oslevel -s 2>/dev/null || oslevel 2>/dev/null || uname -a)

# Model and system serial (best-effort)
model=""
serial_sys=""
if command -v prtdiag >/dev/null 2>&1; then
  model=$(prtdiag -v 2>/dev/null | awk -F: 'BEGIN{IGNORECASE=1} /machine type and model|system model/ { $1=""; gsub(/^[ \t]+|[ \t]+$/,"",$0); print $0; exit }')
  serial_sys=$(prtdiag -v 2>/dev/null | awk -F: 'BEGIN{IGNORECASE=1} /machine serial number|serial number/ { $1=""; gsub(/^[ \t]+|[ \t]+$/,"",$0); print $0; exit }')
fi
[ -z "$model" ] && model=$(uname -M 2>/dev/null || uname -m 2>/dev/null || echo "Unknown")
if [ -z "$serial_sys" ]; then
  serial_sys=$(lsattr -El sys0 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /systemid|system_id|system id/ {print $2; exit}')
  [ -z "$serial_sys" ] && serial_sys="Unknown"
fi

# Network info (per-interface)
net_ifaces_file="$tmpdir/net_ifaces.txt"
if command -v ifconfig >/dev/null 2>&1; then
  ifconfig -a 2>/dev/null | awk '
    /^[^ \t]/ { iface=$1; sub(/:/,"",iface); next }
    /inet / {
      ip=""; for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { ip=$i; break }
      if(ip != "" && ip !~ /^127\./) print iface " " ip
    }
  ' > "$net_ifaces_file"
else
  echo "(ifconfig not available)" > "$net_ifaces_file"
fi

# HMC IP heuristics (best-effort)
hmc_ips=""
if command -v lshmc >/dev/null 2>&1; then
  hmc_ips=$(lshmc 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /ip|address|host/ { for(i=1;i<=NF;i++) if($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i }' | sort -u | tr '\n' ' ' | sed 's/ $//')
fi
if [ -z "$hmc_ips" ]; then
  if [ -f /etc/hosts ]; then
    hmc_ips=$(awk 'BEGIN{IGNORECASE=1} /hmc/ {for(i=1;i<=NF;i++) if($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i}' /etc/hosts | sort -u | tr '\n' ' ' | sed 's/ $//')
  fi
fi
if [ -z "$hmc_ips" ]; then
  tmp=$(lsattr -El sys0 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /hmc|hmcaddr|hmc_ip/ {print $2}')
  [ -n "$tmp" ] && hmc_ips="$tmp"
fi
[ -z "$hmc_ips" ] && hmc_ips="(HMC IP not found by heuristics)"

# Detect LPAR vs Physical (best-effort)
machine_type="Physical"
if command -v lparstat >/dev/null 2>&1; then
  machine_type="LPAR (virtual)"
else
  if lsattr -El sys0 2>/dev/null | grep -qi 'partition'; then
    machine_type="LPAR (virtual)"
  fi
fi

# errpt
err_count=$(errpt 2>/dev/null | sed -n '4,999p' | sed '/^$/d' | wc -l 2>/dev/null)
err_detail="$(errpt -a 2>/dev/null | sed -n '1,200p')"
[ -z "$err_detail" ] && err_detail="(errpt output not available or no recent records)"

# Disk listing and sizes
disk_lines=$(lsdev -Cc disk 2>/dev/null | sed '/^$/d')
blocks_to_gb() {
  b="$1"
  echo "$b" | grep -qE '^[0-9]+$' 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "-"
    return
  fi
  awk "BEGIN{printf \"%.2f\", ($b * 512) / 1073741824}"
}
> "$tmpdir/disks.txt"
echo "$disk_lines" | while IFS= read -r line; do
  device=$(echo "$line" | awk '{print $1}')
  state=$(echo "$line" | awk '{print $2}')
  desc=$(echo "$line" | cut -d' ' -f3-)
  size_display="-"
  if echo "$device" | grep -qE '^hdisk[0-9]+'; then
    blocks=$(bootinfo -s "$device" 2>/dev/null)
    if [ -n "$blocks" ] && echo "$blocks" | grep -qE '^[0-9]+$' 2>/dev/null; then
      gb=$(blocks_to_gb "$blocks")
      [ "$gb" != "-" ] && size_display="${gb} GB"
    fi
  fi
  printf "%-10s %-12s %-12s %s\n" "$device" "$state" "$size_display" "$desc" >> "$tmpdir/disks.txt"
done
disk_count=0; disk_table=""
if [ -s "$tmpdir/disks.txt" ]; then
  disk_count=$(wc -l < "$tmpdir/disks.txt" | tr -d ' ')
  disk_table=$(cat "$tmpdir/disks.txt")
fi

# PV / VG
pv_summary=$(lspv 2>/dev/null | sed -n '1,200p')
vg_list=$(lsvg 2>/dev/null | sed -n '1,200p')

# Memory total
realmem_kb=$(lsattr -El sys0 2>/dev/null | awk '/realmem/ {print $2; exit}')
if [ -n "$realmem_kb" ]; then
  total_mem_mb=$(( realmem_kb / 1024 ))
else
  total_mem_mb=0
fi

# Parse lscfg -vp for hardware blocks
lscfg_out=$(lscfg -vp 2>/dev/null)
hw_raw_file="$tmpdir/hw_raw.txt"
> "$hw_raw_file"
if [ -n "$lscfg_out" ]; then
  printf "%s\n" "$lscfg_out" | awk '
    BEGIN{ RS=""; ORS=""; IGNORECASE=1 }
    {
      device_line=""; part=""; serial=""; size="";
      n=split($0, a, "\n");
      for(i=1;i<=n;i++){ gsub(/^[ \t]+|[ \t]+$/,"",a[i]); if(a[i]!=""){ device_line=a[i]; break } }
      for(i=1;i<=n;i++){
        line=a[i]; low=tolower(line);
        if(low ~ /part[[:space:]]*number|part[[:space:]]*no|p\/n|part#/){
          sub(/^[^:]*:[[:space:]]*/,"",line); if(part=="") part=line;
        }
        if(low ~ /serial[[:space:]]*number|ser[[:space:]]*no|serial#/){
          sub(/^[^:]*:[[:space:]]*/,"",line); if(serial=="") serial=line;
        }
        if(low ~ /size[[:space:]]*[:=]|[0-9]+[ ]*(kb|mb|gb)/){
          if(size==""){ sub(/^[^:]*:[[:space:]]*/,"",line); size=line; }
        }
      }
      lowblk=tolower($0);
      if(part!="" || serial!="" || lowblk ~ /memory|dimm|processor|disk|hba/){
        gsub(/\n/,"\\n",$0);
        printf("%s|%s|%s|%s\n", device_line, (part==""?"-":part), (serial==""?"-":serial), (size==""?"-":size));
      }
    }
  ' > "$hw_raw_file"
fi

# Determine memory modules
mem_mods_file="$tmpdir/mem_mods.txt"
> "$mem_mods_file"
mem_slots_count=0
if [ -s "$hw_raw_file" ]; then
  awk 'BEGIN{IGNORECASE=1; FS="|"} { if(tolower($0) ~ /memory|dimm/ || tolower($1) ~ /dimm|memory/) print }' "$hw_raw_file" > "$tmpdir/hw_mem_candidates.txt"
  if [ ! -s "$tmpdir/hw_mem_candidates.txt" ]; then
    awk 'BEGIN{FS="|"} { if($4 ~ /[0-9]+[ ]*(kb|mb|gb)/) print }' "$hw_raw_file" > "$tmpdir/hw_mem_candidates.txt"
  fi
  if [ -s "$tmpdir/hw_mem_candidates.txt" ]; then
    mem_slots_count=$(wc -l < "$tmpdir/hw_mem_candidates.txt" | tr -d ' ')
    awk -F"|" '{ dev=$1; part=$2; ser=$3; size=$4; gsub(/^[ \t]+|[ \t]+$/,"",dev); gsub(/^[ \t]+|[ \t]+$/,"",part); gsub(/^[ \t]+|[ \t]+$/,"",ser); gsub(/^[ \t]+|[ \t]+$/,"",size); print dev "|" part "|" ser "|" size }' "$tmpdir/hw_mem_candidates.txt" > "$mem_mods_file"
  fi
fi

# normalize_to_mb helper
normalize_to_mb() {
  val="$1"
  if [ -z "$val" ] || [ "$val" = "-" ]; then
    echo ""
    return
  fi
  v=$(echo "$val" | tr -d ',' )
  num=$(echo "$v" | sed 's/[^0-9.]*//g')
  unit=$(echo "$v" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z]/ /g' | awk '{for(i=1;i<=NF;i++) if($i ~ /kb|mb|gb/) {print $i; exit}}')
  if [ -z "$num" ]; then echo ""; return; fi
  case "$unit" in
    kb) awk "BEGIN{printf \"%d\", ($num/1024)}";;
    mb) awk "BEGIN{printf \"%d\", ($num)}";;
    gb) awk "BEGIN{printf \"%d\", ($num*1024)}";;
    *) awk "BEGIN{printf \"%d\", ($num)}";;
  esac
}

# Build mem module printable lines: only include size if normalized MB > 0
mem_module_lines=""
if [ -s "$mem_mods_file" ]; then
  while IFS="|" read dev part ser size_raw; do
    normalized_mb=$(normalize_to_mb "$size_raw")
    if [ -n "$normalized_mb" ] && [ "$normalized_mb" -gt 0 ]; then
      gb=$(awk "BEGIN{printf \"%.2f\", $normalized_mb/1024}")
      size_display="${gb} GB"
    else
      size_display="-"   # will be printed blank later
    fi
    printf "%-40s|%-25s|%-25s|%s\n" "$dev" "$part" "$ser" "$size_display" >> "$tmpdir/mem_out.txt"
  done < "$mem_mods_file"
  [ -f "$tmpdir/mem_out.txt" ] && mem_module_lines=$(cat "$tmpdir/mem_out.txt")
fi

# CPU info
logical_cpus=$(lsdev -Cc processor 2>/dev/null | sed '/^$/d' | wc -l)
sockets_num=0; cores_num=0
if [ -n "$lscfg_out" ]; then
  sockets_num=$(printf "%s\n" "$lscfg_out" | awk 'BEGIN{RS=""; IGNORECASE=1} /processor|proc /{count++} END{ if(count=="") print 0; else print count}')
  cores_num=$(printf "%s\n" "$lscfg_out" | awk 'BEGIN{RS=""; IGNORECASE=1}
    {
      n=split($0,a,"\n");
      for(i=1;i<=n;i++){
        low=tolower(a[i]);
        if(low ~ /number of cores|core count|cores per cpu|core per package/){
          gsub(/[^0-9]/,"",a[i]);
          if(a[i]+0>0) cores += a[i]+0;
        }
      }
    }
    END{ if(cores==0) print 0; else print cores }')
fi
sockets_display="Unknown"; cores_display="Unknown"
if echo "$sockets_num" | grep -qE '^[0-9]+$' 2>/dev/null && [ "$sockets_num" -gt 0 ]; then sockets_display="$sockets_num"; fi
if echo "$cores_num" | grep -qE '^[0-9]+$' 2>/dev/null && [ "$cores_num" -gt 0 ]; then cores_display="$cores_num"; fi

# Filesystem sizes
fs_output=""
if df -m / >/dev/null 2>&1; then
  fs_output=$(df -m | awk 'NR==1{print $0} NR>1{printf "%-30s %-10s %-10s %-10s %-6s\n",$1,$2"M",$3"M",$4"M",$5}')
else
  fs_output="(df not available)"
fi

# Build PN/SN hardware table neatly aligned
hw_pnsn_table=""
if [ -s "$hw_raw_file" ]; then
  printf "%-40s %-25s %-25s\n" "Device" "Part Number" "Serial Number" > "$tmpdir/hw_pnsn.txt"
  printf "%s\n" "----------------------------------------------------------------------------------------" >> "$tmpdir/hw_pnsn.txt"
  awk -F"|" '{ printf "%-40s %-25s %-25s\n", $1, $2, $3 }' "$hw_raw_file" >> "$tmpdir/hw_pnsn.txt"
  hw_pnsn_table=$(cat "$tmpdir/hw_pnsn.txt")
fi

# --- Serial console & baudrate detection (best-effort) ---
serial_info_file="$tmpdir/serial_info.txt"
> "$serial_info_file"

if [ -f /etc/inittab ]; then
  awk -F: 'BEGIN{IGNORECASE=1}
    /getty|ttymon|console|ctty/ {
      proc=$4;
      dev=""; baud="";
      if(match(proc, /\/dev\/[a-zA-Z0-9\/._-]*/)) {
        dev=substr(proc, RSTART, RLENGTH)
      } else if(match(proc, /tty[a-zA-Z0-9]*/)) {
        dev="/dev/" substr(proc, RSTART, RLENGTH)
      }
      if(match(proc, /([0-9]{3,6})/, m)) { baud=m[1] }
      if(dev!="") print dev "|" baud
    }' /etc/inittab | sort -u >> "$serial_info_file"
fi

for dev_candidate in /dev/console /dev/tty0 /dev/tty /dev/ttya /dev/ttyb /dev/tty00 /dev/tty01 /dev/tty02; do
  [ -e "$dev_candidate" ] || continue
  grep -q "^${dev_candidate}|" "$serial_info_file" 2>/dev/null || echo "${dev_candidate}|" >> "$serial_info_file"
done

get_baud() {
  device="$1"
  stty_out=$(stty -a < "$device" 2>/dev/null || true)
  if [ -z "$stty_out" ]; then
    stty_out=$(stty -F "$device" -a 2>/dev/null || true)
  fi
  if [ -n "$stty_out" ]; then
    baud=$(printf "%s\n" "$stty_out" | awk '
      { if(match($0, /speed[ =]*([0-9]+)/, m)) { print m[1]; exit } 
        if(match($0, /([0-9]{3,6})[ ]*baud/, m)) { print m[1]; exit } 
        if(match($0, /ispeed[ =]*([0-9]+)/, m)) { print m[1]; exit } }')
    if [ -n "$baud" ]; then
      printf "%s\n" "$baud"
      return
    fi
  fi
  printf "\n"
}

if [ -s "$serial_info_file" ]; then
  while IFS="|" read dev inittab_baud; do
    [ -z "$dev" ] && continue
    dev=$(echo "$dev" | sed 's/\/dev\/dev\//\/dev\//g')
    if [ ! -e "$dev" ]; then
      detected=""
    else
      detected=$(get_baud "$dev")
    fi
    [ -z "$inittab_baud" ] && inittab_baud="-"
    [ -z "$detected" ] && detected="-"
    printf "%-20s %-12s %-12s\n" "$dev" "$inittab_baud" "$detected" >> "${serial_info_file}.out"
  done < "$serial_info_file"
fi
# --- end serial detection ---

# Print final report
{
  printf "AIX Healthcheck - %s\n" "$date_now"
  sep_line
  printf "%-25s : %s\n" "Host" "$host"
  printf "%-25s : %s\n" "OS Level" "$oslevel_full"
  printf "%-25s : %s\n" "Model (PN)" "$model"
  printf "%-25s : %s\n" "Serial Number (system)" "$serial_sys"
  printf "%-25s : %s\n" "Machine Type" "$machine_type"
  sep_line

  # Network immediately after device info (labels width set to 25 so ":" aligns)
  printf "Network\n"
  sep_line
  if [ -s "$net_ifaces_file" ]; then
    printf "%-25s : %s\n" "Interface" "IP Address"
    printf "%s\n" "------------------------------------------------------------"
    awk '{ printf "%-25s : %s\n", $1, $2 }' "$net_ifaces_file"
  else
    printf "%-25s : %s\n" "Interface" "(no network interface / IP info available)"
  fi
  printf "%-25s : %s\n" "HMC IP(s) (heuristic)" "$hmc_ips"
  sep_line

  printf "Serial Console (device | inittab_baud | detected_baud)\n"
  sep_line
  if [ -f "${serial_info_file}.out" ]; then
    printf "%-20s %-12s %-12s\n" "Device" "Inittab" "Detected"
    printf "%s\n" "--------------------------------------------------"
    cat "${serial_info_file}.out"
  else
    echo "  (no serial console entries detected)"
  fi
  sep_line

  printf "Hardware PN / SN list\n"
  sep_line
  if [ -n "$hw_pnsn_table" ]; then
    printf "%s\n" "$hw_pnsn_table"
  else
    echo "  (no PN/SN information parsed from lscfg -vp)"
  fi
  sep_line

  printf "Hardware Errors (errpt) - total entries: %s\n" "${err_count:-0}"
  sep_line
  printf "%s\n" "$err_detail"
  sep_line

  printf "Disk Summary\n"
  sep_line
  printf "%-10s : %s\n" "Total disks" "$disk_count"
  printf "%-10s %-12s %-12s %s\n" "Device" "State" "Size" "Description"
  printf "%s\n" "------------------------------------------------------------"
  if [ -n "$disk_table" ]; then
    printf "%s\n" "$disk_table"
  else
    echo "  (no disk information available)"
  fi
  sep_line

  printf "Physical Volumes (lspv)\n"
  sep_line
  printf "%s\n" "$pv_summary"
  sep_line

  printf "Volume Groups (lsvg)\n"
  sep_line
  printf "%s\n" "$vg_list"
  sep_line

  printf "CPU Summary\n"
  sep_line
  printf "%-25s : %s\n" "Logical CPUs" "$logical_cpus"
  printf "%-25s : %s\n" "CPU sockets (proc blocks)" "$sockets_display"
  printf "%-25s : %s\n" "Total cores (if parseable)" "$cores_display"
  sep_line

  printf "Memory Summary\n"
  sep_line
  if [ "$total_mem_mb" -gt 0 ]; then
    printf "%-25s : %s MB (%.2f GB)\n" "Total real memory" "$total_mem_mb" "$(awk "BEGIN{printf \"%.2f\", $total_mem_mb/1024}")"
  else
    printf "%-25s : %s\n" "Total real memory" "(unknown)"
  fi
  printf "%-25s : %s\n" "Memory slots/modules found" "${mem_slots_count}"
  printf "%s\n" "Memory modules (Device | Part Number | Serial Number | Size if available):"
  printf "%s\n" "-----------------------------------------------------------------------------------------------"
  if [ -n "$mem_module_lines" ]; then
    printf "%-40s %-25s %-25s %-15s\n" "Device" "Part Number" "Serial Number" "Size"
    printf "%s\n" "-----------------------------------------------------------------------------------------------"
    printf "%s\n" "$mem_module_lines" | while IFS="|" read dev part ser size; do
      if [ "$size" = "-" ]; then
        size_print=""
      else
        size_print="$size"
      fi
      printf "%-40s %-25s %-25s %-15s\n" "$dev" "$part" "$ser" "$size_print"
    done
  else
    echo "  (no detailed memory module info available from lscfg -vp)"
  fi
  sep_line

  printf "Filesystem Summary\n"
  sep_line
  printf "%s\n" "$fs_output"
  sep_line

  printf "End of healthcheck\n"
} | tee "$outfile"

# cleanup
rm -rf "$tmpdir"

echo ""
echo "Report saved to: $outfile"
