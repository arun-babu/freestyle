echo "======================================================"
echo "[ Reference implementation ]" 
echo "======================================================"
./test.sh

echo
echo "======================================================"
echo "[ Side channel attack resistance implementation ]" 
echo "======================================================"
cd side=channel=attack=resistance
./test.sh

echo
echo "======================================================"
echo "[ Optimized (merged) implementation ]" 
echo "======================================================"
cd ../optimized/merged
./test.sh

echo
