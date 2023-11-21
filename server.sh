if ! [[ "$PATH" =~ ":/usr/local/bin" ]]
then
    PATH="$PATH:/usr/local/bin"
fi
uwsgi server.ini