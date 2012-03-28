#!perl
# create sha1 hash
# for msg

$sha1_block="";
$sha1_block.="\x66\xCE\x3F\xDB\xAA\x55\xB4\xF7\x00";

open WR, ">_myin_sha1_2.txt";
binmode (WR);
print WR $sha1_block;
close WR;
