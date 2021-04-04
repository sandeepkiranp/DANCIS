echo "gcc service.c common.c base64.c parser.c token.c sha1.c -o service -lgmp -lmclbn384_256 -lmcl -lpthread"
gcc service.c common.c base64.c parser.c token.c sha1.c -o service -lgmp -lmclbn384_256 -lmcl -lpthread
echo "gcc controller.c common.c base64.c parser.c token.c sha1.c issuer.c groth.c -o controller -lgmp -lmclbn384_256 -lmcl -lpthread"
gcc controller.c common.c base64.c parser.c token.c sha1.c issuer.c groth.c -o controller -lgmp -lmclbn384_256 -lmcl -lpthread
echo "gcc root.c base64.c groth.c issuer.c sha1.c common.c -o root -lgmp -lmclbn384_256 -lmcl -lpthread"
gcc root.c base64.c groth.c issuer.c sha1.c common.c -o root -lgmp -lmclbn384_256 -lmcl -lpthread
echo "gcc user.c base64.c groth.c issuer.c sha1.c common.c -o user -lgmp -lmclbn384_256 -lmcl"
gcc user.c base64.c groth.c issuer.c sha1.c common.c -o user -lgmp -lmclbn384_256 -lmcl
