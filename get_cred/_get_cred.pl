#!perl


if ( @ARGV != 1) {
	print "usage log-file\n";
	exit();
};

$file=@ARGV[0];
open RD, "$file";

$cred=0;
$data_cred="";
$pubkey=0;
$pubkey_start=0;
$data_pubkey="";
$seckey=0;
$data_seckey="";
$skypename="failed";
while(<RD>){ chomp;

        if ($_=~ /ActivateProfile\: activating (.+) /) {
		$skypename=$1;
	};

	if ($_=~ /After cipher/){
	  	$seckey=1;
		$i=0;
		$tmp=<RD>;
		$tmp=<RD>;
		$tmp=<RD>;
                next;
	};

	if ($seckey){
	    $i++; 
	    if ($i<=8){
		 $data_seckey.=substr($_,9);
	    }else{
	      	 $seckey=0;
		 $cred=1;
                 $i=0;
	    };
	};

	if ($cred){
	    $i++; 
	    if ($i<=17){
		 $data_cred.=substr($_,9);
	    }else{
	      	 $cred=0;
		 $pubkey=1;
                 $i=0;
	    };
	};

        if ($pubkey) {
            if ($_=~ / 80 01 /) {
                $pubkey_start=1;
            };
        };

	if ($pubkey_start){
	    $i++; 
	    if ($i<=9){
		if ($i==1){
                      ($tmp_a,$tmp_b)=split(" 80 01 ",$_);
                      $data_pubkey.=$tmp_b;
 		}else{
                      $data_pubkey.=substr($_,9);
		};
	    }else{
                 $pubkey=0;
                 $i=0;                  
                 last;
	    };
	};


};
close RD;


$data_pubkey=substr($data_pubkey,0,0x80*3);

$data_pubkey=~ s/ //g;
$data_seckey=~ s/ //g;
$data_cred=~ s/ //g;

if (1) {
	print "Name: $skypename\n";
	print "seckey:\n";
	print $data_seckey."\n";
	print "cred:\n";
	print $data_cred."\n";
	print "pubkey:\n";
	print $data_pubkey."\n";
};

$line="$skypename:skypepass:FirstName LastName:my\@email.com:4.1.0.179:";
$line.="$data_cred:$data_pubkey:$data_seckey:2\n";

open WR,">>_accounts.txt";
print WR $line;
close WR;

