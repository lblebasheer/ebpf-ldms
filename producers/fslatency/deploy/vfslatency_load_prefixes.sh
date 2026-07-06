#!/bin/bash -e

NUM_PREFIX=$(($(echo -n $PREFIXES|wc -w) - 1))
if [[ $NUM_PREFIX -gt 8 ]]; then
    (1>&2 echo "ERROR: Greater than maximum number of prefixes")
    exit 1
fi

MAP_NAMES="CLOSE_STATS FSYNC_STATS WRITE_STATS WRITEV_STATS READ_STATS READV_STATS KREAD_STATS KWRITE_STATS"

for NAME in $MAP_NAMES; do
    MAP_IDS=$(bpftool map show --json|jq '.[]|select(.name == "'$NAME'")|.id')
    NUM_MAPS=$(echo -n $MAP_IDS|wc -w)
    for mapid in $MAP_IDS; do
        key=0
        value_bytes=$(bpftool map show id $mapid --json|jq .bytes_value)
        for prefix in $PREFIXES; do
            prefix_len=$(echo -n $prefix|wc -c)
            # struct bpf_spin_lock
            spin_lock="00 00 00 00"
            len_spin_lock=$(echo $spin_lock|wc -w)
            # length of path in hex
            len_field="$(printf %02x $prefix_len) 00 00 00"
            len_field_len=$(echo $len_field|wc -w)
            # -1 because seq is inclusive in the range
            bpftool map update id $mapid key hex 0${key} 00 00 00 value hex $spin_lock $len_field $(echo -n $prefix|hexdump -e '/1 "%02x "') $(for k in $(seq 0 $((${value_bytes} - ${prefix_len} - ${len_field_len} - ${len_spin_lock} - 1)));do echo -n "00 ";done)
            key=$((key+1))
        done
    done
done
