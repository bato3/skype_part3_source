/*
    Boneh-Lynn-Shacham short signature scheme - key generation phase
    cl /O2 /GX bls_gen.cpp ecn3.cpp ecn.cpp zzn3.cpp zzn.cpp big.cpp ms32.lib

    I believe this method is patented - so check first before use in a commercial application
*/

#include <iostream>
#include <fstream>
#include <string.h>
#include "ecn3.h"
#include "ecn.h"
#include <ctime>

using namespace std;

// cofactor - number of points on curve=CF.q

#define CF 2  
#define CNR -2

int main()
{
    ifstream common("mnt.ecs");      // MNT elliptic curve parameters
    ofstream public_key("bls_public.key");
    ofstream private_key("bls_private.key");
    miracl* mip=mirsys(40,16);
    ECn3 P,R;
    ECn Q;
    ZZn3 x,y,z;
    ZZn a,b,c;
    Big w,s,p,q,B,cf,sru;
    int i,bits,A;
    time_t seed;

    common >> bits;
    mip->IOBASE=16;
    common >> p;
    common >> A;
    common >> B >> q >> cf >> sru;

    time(&seed);
    irand((long)seed);

    ecurve(A,B,p,MR_PROJECTIVE);
    set_zzn3(CNR,sru);

    mip->TWIST=TRUE;   // map to point on twisted curve E(Fp3)

// find a random point on the curve

    cout << "generating keys - keys in bls_private.key and bls_public.key" << endl;

    forever
    {
        w=rand(p);
        x.set((ZZn)0,(ZZn)w,(ZZn)0);
        if (P.set(x)) break;
    }

    s=rand(q);

// generate public values.

    R=P; R*=s;

    P.get(x,y);

    x.get(a,b,c);

    public_key << a << endl;
    public_key << b << endl;
    public_key << c << endl;

    y.get(a,b,c);

    public_key << a << endl;
    public_key << b << endl;
    public_key << c << endl;

    R.get(x,y);

    x.get(a,b,c);

    public_key << a << endl;
    public_key << b << endl;
    public_key << c << endl;

    y.get(a,b,c);

    public_key << a << endl;
    public_key << b << endl;
    public_key << c << endl;

    private_key << s << endl;
 
    return 0;
}

