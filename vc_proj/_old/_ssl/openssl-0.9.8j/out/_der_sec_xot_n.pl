#!perl
# create der rsa secret key 
# xot_iam NEW

$der_start="\x30\x82\x02\x5D\x02\x01\x00\x02\x81\x81\x00";
$der_end="\x02\x03\x01\x00\x01";

$der_start2="\x02\x81\x80";


$xot_pub="";
$xot_pub.="\x9D\xAB\x16\x66\x1B\x5F\x4C\xD8\x27\x1C\x9D";
$xot_pub.="\xBF\xF8\x06\x75\xCC\x85\x75\xB9\x67\x2F\xA3\x7E\x93\x08\xF3\xB2";
$xot_pub.="\x0F\x02\x31\xCD\xD2\x46\x35\x4B\x80\x9F\x7F\xFE\x10\xE1\x7C\x7C";
$xot_pub.="\x38\x2A\x71\xBF\xB6\x02\x8C\xA9\x43\xF6\x9B\x90\x59\xA0\x62\x84";
$xot_pub.="\x8B\xCD\xBC\x70\xD4\xC7\x85\x63\xCB\xE1\xD2\x18\x5F\x88\x73\xCC";
$xot_pub.="\x8E\x53\x88\xF8\x8B\x10\x43\x42\x20\xE9\x8A\xEF\x0C\x7D\xCD\x9C";
$xot_pub.="\xF7\xAA\xB2\x95\x65\x51\x10\xA5\x54\x40\x1F\x21\x10\x67\x5F\x42";
$xot_pub.="\x53\xE7\xEF\xF6\x1A\xD7\x58\x1F\x53\xC5\x68\xDE\xDE\xDE\xAA\xBD";
$xot_pub.="\xFC\x38\xEF\xA1\x25";



$xot_sec="";
$xot_sec.="\x37\xDB\x8E\xF9\xE9\xA4\x9F\xA2\xCC\x68\x74\xF2\xB7\xBA\x02\x2D";
$xot_sec.="\xCC\xF2\x62\x16\xCE\x67\xCB\xC5\xE7\x9B\xFE\x6F\x16\xC5\xF2\x37";
$xot_sec.="\x16\xAC\x76\xED\x40\x94\xA5\xBB\xF1\x46\x9A\xF3\x83\x05\xFD\x77";
$xot_sec.="\x4B\xFB\xED\x53\xA8\xA0\x80\x49\x60\x6A\xC6\xAE\x88\xDA\xC3\xD5";
$xot_sec.="\xEF\xD5\x25\x37\x6E\x35\xFA\x20\x1D\x69\x0E\xC6\xA0\xB5\xE2\x30";
$xot_sec.="\x81\xCC\x37\xC2\x3C\xCD\x34\x74\x95\x44\x09\x83\xC2\xB1\xB8\x88";
$xot_sec.="\xF0\x4E\x47\x30\x8F\x27\x07\xF9\xBE\x51\xC2\x10\x92\x4B\xCE\x53";
$xot_sec.="\x60\xA2\xAE\x25\xEC\x52\x30\xF5\x8E\xBA\xFD\x78\x83\xCA\xF3\x99";


$der_rest="";
$der_rest.="\x02\x41\x00\xE1\x76\xF6\x30\x5C\xF5\xE1\xA8\x2E\x05";
$der_rest.="\xE1\x4D\x95\xE8\x7A\x75\x8B\x2E\x93\x84\xCE\xE2\x19\xBD\x55\x16";
$der_rest.="\x67\xA5\x5A\x8F\x80\xDE\xC1\xA7\x8F\xD6\x6E\x25\x72\x38\xFA\x17";
$der_rest.="\x8E\x51\x83\xA6\x68\x00\xDE\x15\xF7\x13\x15\x36\x97\xF7\x10\x47";
$der_rest.="\xD9\x25\xB6\x3F\x3E\xC1\x02\x41\x00\xC9\x8A\xB3\x14\x27\x59\x16";
$der_rest.="\x2B\x91\x96\x51\x6B\xAD\x86\xAC\xDB\xC4\x1E\x99\x8B\x54\xB5\xF4";
$der_rest.="\x5C\xC9\x7E\x83\xB5\xF7\x3B\x46\x03\x3A\xF3\x70\xFC\x04\xCC\xDB";
$der_rest.="\xCB\x68\xA6\x6D\x58\x96\x7B\x39\x31\x4C\xC0\xDA\xDB\x8C\x3B\x95";
$der_rest.="\x4C\xFB\x55\x93\x55\x1C\xB9\xBC\xA5\x02\x41\x00\xCD\x5C\xFC\x15";
$der_rest.="\x45\x37\x39\x59\x64\xC2\x3A\x5B\xDF\x05\xA8\x35\x54\x97\x12\x0B";
$der_rest.="\x50\x1D\xA5\xF0\x4C\x86\x61\xD5\xBD\x4D\x24\xC6\xC1\x81\x8C\x84";
$der_rest.="\x76\x43\x69\x6C\xF8\x6F\x68\x54\x5B\x23\xC1\x6B\xB8\xDE\x2C\xF4";
$der_rest.="\x96\xC7\xE9\x57\x42\xDF\x0E\xAD\x48\xF9\x06\x81\x02\x40\x45\x45";
$der_rest.="\x0B\xA9\xC8\xA0\x60\xF3\x56\x95\xA0\xA4\x6E\xBE\xD4\x18\xB0\xBE";
$der_rest.="\x87\xAD\x90\xCE\xFD\x0F\x0B\x1E\x15\xAC\xEC\x2D\x8E\x31\xBC\x08";
$der_rest.="\x41\xF4\x0C\xBE\x50\x69\x08\x2D\xF3\x75\x38\x3B\x5F\xFB\xE6\xD2";
$der_rest.="\x7E\x26\x69\x7B\x6D\x24\x49\x5A\x2F\x4A\x58\x96\x2A\x15\x02\x41";
$der_rest.="\x00\xE0\x10\x37\xA5\x94\xF9\xBC\x94\x77\x48\xA2\x16\x8B\xE6\x78";
$der_rest.="\xA8\xDC\xC8\xFA\x3A\xCA\x36\xCD\x37\x60\x12\xB7\x2E\xEB\xA3\xD3";
$der_rest.="\x3C\x31\xE4\xEA\x3B\xF1\xE0\xFC\xE3\xB5\x84\x55\x85\x05\x37\x20";
$der_rest.="\x1B\xB6\xCA\x6F\xF2\x1A\xD6\xA5\xD0\x1D\x82\xBF\x02\xF9\xD4\x63";
$der_rest.="\x98";


open WR, ">_xot_sec_new.der";
binmode (WR);

print WR $der_start;
print WR $xot_pub;
print WR $der_end;

print WR $der_start2;
print WR $xot_sec;

print WR $der_rest;

close WR;
