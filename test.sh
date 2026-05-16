rm -f target_cmd_pipe cli_pipe cli_out.txt
mkfifo target_cmd_pipe cli_pipe
./build/DummyTarget < target_cmd_pipe > /dev/null 2>&1 &
TARGET_PID=$!
exec 3>target_cmd_pipe
sleep 1

./build/HexScanCLI $TARGET_PID interactive < cli_pipe > cli_out.txt 2>&1 &
CLI_PID=$!
exec 4>cli_pipe

echo "scan i32 0 10" >&4
sleep 2
echo "nextscan i32 0 4" >&4
sleep 2
echo "quit" >&4
wait $CLI_PID
cat cli_out.txt
