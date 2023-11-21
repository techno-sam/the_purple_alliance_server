# Installation
This guide assumes some basic knowledge of linux.
## Requirements
- Some sort of linux server
- Python 3.6+
- Git

## Important note
While you need superuser priveleges to install uWSGI and the server, it is *extremely* inadvisable to run the server
with superuser privileges.

Instead, create a new user and run the server as that user. This is because if the server is compromised, the attacker
will have root access to your server. If the server is run as a non-root user, the attacker will only have access to
the files owned by that user.
## Process
1. Install uWSGI (https://uwsgi-docs.readthedocs.io/en/latest/Install.html)<br>
If using an Oracle Linux server, these commands might work:
```shell
sudo yum groupinstall "Development Tools"
sudo yum install python36 python36-devel
sudo yum install openssl-devel.aarch64
UWSGI_PROFILE_OVERRIDE=ssl=true sudo python3 -m pip install uwsgi
```
2. Clone this repository
```shell
git clone https://github.com/techno-sam/the_purple_alliance_server.git
cd the_purple_alliance_server
```
3. Install the required python packages
```shell
python3 -m pip install -r requirements.txt
```
4. Copy the example config file and edit it to your liking (make sure you set up Blue Alliance API keys)
5. Copy the testing scheme file and edit it to your liking
6. Copy the example server.ini
7. Edit `server.ini` to point to its containing directory and to use the proper `uid` and `gid`
<br>(eg. `/home/username/the_purple_alliance_server`)
8. Run the server
```shell
./server.sh
```