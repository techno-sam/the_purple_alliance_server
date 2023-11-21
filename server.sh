# shellcheck disable=SC2076
if ! [[ "$PATH" =~ "/home/tpa/.local/bin:" ]]
then
    PATH="/home/tpa/.local/bin:$PATH"
fi
echo "PATH"
echo "$PATH"
uwsgi server.ini