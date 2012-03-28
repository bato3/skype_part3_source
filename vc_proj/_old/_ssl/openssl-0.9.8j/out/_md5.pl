

$l="xoteg_iam";
$p="329047";
$str=$l."\x0a"."skyper"."\x0a".$p;

open WR, ">_a_md5n.txt";
binmode WR;
print WR $str;
close WR;
