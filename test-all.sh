echo > err

pwd=`pwd`

echo "======================================================"
echo "[ Reference implementation ]" 
echo "======================================================"
echo "[ Reference implementation ]" >>err 
./test.sh 2>err

echo
echo "======================================================"
echo "[ Side channel attack resistance implementation ]" 
echo "======================================================"
cd side-channel-attack-resistance
echo "[ Side channel attack resistance implementation ]" >> ../err 
./test.sh 2>>../err

echo
echo "======================================================"
echo "[ Optimized (merged) implementation ]" 
echo "======================================================"
cd ../optimized/merged
echo "[ Optimized (merged) implementation ]" >> ../../err 
./test.sh 2>>../../err

echo
echo "======================================================"
echo "[ Optimized for min_rounds = 8, max_rounds = 32 ]" 
echo "======================================================"
cd ../8-32
echo "[ Optimized for min_rounds = 8, max_rounds = 32 ]" >> ../../err 
./test.sh 2>>../../err

cd $pwd

echo
echo 
echo "================= WARNINGS/ERRORS ===================="
cat err
echo
echo "======================================================"
