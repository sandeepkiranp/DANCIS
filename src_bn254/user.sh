gcc user.c base64.c groth.c issuer.c sha1.c common.c -o user -lpbc -lgmp -g
./user user2 LOAD < ../../software/pbc-0.5.14/param/a.param
./user user1 DELEGATE user2 all < ../../software/pbc-0.5.14/param/a.param
