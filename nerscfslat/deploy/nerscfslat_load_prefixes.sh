#!/bin/bash -ex

MAP_IDS=$(bpftool map show --json|jq '.[]|select(.name == "WRITESTATS")|.id')
NUM_MAPS=$(echo -n $MAP_IDS|wc -w)
NUM_PREFIX=$(($(echo -n $PREFIXES|wc -w) - 1))
if [[ $NUM_PREFIX -gt 8 ]]; then
    (1>&2 echo "ERROR: Greater than maximum number of prefixes")
    exit 1
fi

for mapid in $MAP_IDS; do
    key=0
    for prefix in $PREFIXES; do
        prefix_len=$(echo -n $prefix|wc -c)
        # length of path in hex
        len_field="$(printf %02x $prefix_len) 00 00 00"
        bpftool map update id $mapid key hex 0${key} 00 00 00 value hex $len_field $(echo -n $prefix|hexdump -e '/1 "%02x "') $(for k in $(seq 0 $((76-prefix_len-1)));do echo -n "00 ";done)
        key=$((key+1))
    done
done
