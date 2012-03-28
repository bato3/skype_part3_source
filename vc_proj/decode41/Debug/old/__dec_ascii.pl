#!perl



$a ="23786F7465675F69616D2F24786F745F69616D3B346665663762303135636232";
$a.="3061643000";

$l=length($a);

$all="";
for($i=0;$i<$l;$i=$i+2){
	$h=substr($a,$i,2);
	$g=chr(hex($h));
	$all=$all.$g;
};

open WR, ">__out.txt";
binmode WR;
print WR $all;
close WR;

