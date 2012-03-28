#!perl

open RD, "_getnodes.txt";
open WR, ">_boot_addr.txt";
while(<RD>){ chomp();
	if ($_=~ /^\d+/){
		print WR $_."\n";
	};
};
close(RD);
close(WR);

