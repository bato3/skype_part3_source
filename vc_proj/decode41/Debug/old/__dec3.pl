#!perl

$a="";
$a.="\x68\x6F\x68\x6F\x68\x6F";

open WR, ">__tmp.txt";
binmode WR;
print WR $a;
close WR;

