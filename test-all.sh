echo "======================================================"
echo "[ Reference implementation ]" 
echo "======================================================"
./test.sh 2>err

echo
echo "======================================================"
echo "[ Side channel attack resistance implementation ]" 
echo "======================================================"
cd side-channel-attack-resistance
./test.sh 2>>err

echo
echo "======================================================"
echo "[ Optimized (merged) implementation ]" 
echo "======================================================"
cd ../optimized/merged
./test.sh 2>>err

echo
echo "======================================================"
echo "[ Optimized for min_rounds = 8, max_rounds = 32 ]" 
echo "======================================================"
cd ../8-32
./test.sh 2>>err

echo
echo 
echo "================= WARNINGS/ERRORS ===================="
cat err
echo
echo "======================================================"
