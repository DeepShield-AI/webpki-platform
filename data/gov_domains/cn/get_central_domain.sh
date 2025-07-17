find ./centralData20241106 -type f -name '*.csv' -exec awk -F',' 'NR>1 { 
  gsub(/(^"|"$)/, "", $4);   # 去除双引号 
  url=$4; 
  sub(/^https?:\/\//, "", url); 
  sub(/\/.*$/, "", url); 
  print url 
}' {} + | sort -u > domains.txt

(
  head -n 1 "$(find ./centralData20241106 -type f -name '*.csv' | head -n 1)"
  find ./centralData20241106 -type f -name '*.csv' -exec tail -n +2 {} \;
) > cn_gov_20241106_map_central.csv
