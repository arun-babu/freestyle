echo "=== Reference implementation ========================="
./test.sh

echo
echo "=== Side channel attack resistance implementation ===="
cd side-channel-attack-resistance
./test.sh

echo
echo "=== Optimized (merged) implementation ================"
cd ../optimized/merged
./test.sh
