gcc root.c base64.c groth.c issuer.c sha1.c common.c -o root -lpbc -lgmp
./root ISSUE user2 A5,A6 < ../../software/pbc-0.5.14/param/a.param
