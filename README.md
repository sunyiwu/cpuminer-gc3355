cpuminer-gc3355
==============

CPUMiner with GridSeed GC3355 support

How to compile from git (Debian-based):

```
apt-get update
apt-get install -y build-essential libtool libcurl4-openssl-dev libjansson-dev libudev-dev libncurses5-dev autoconf automake
git clone https://github.com/siklon/cpuminer-gc3355
cd cpuminer-gc3355
./autogen.sh
./configure CFLAGS="-O3"
make
```

Failover pool strategy is supported.
`--url=stratum+tcp://pool1:port --userpass=user1:pass1 --url=stratum+tcp://pool2:port --userpass=user2:pass2 --url=stratum+tcp://pool3:port --userpass=user3:pass3`
Pool 1 is the main pool, if it is down, it will try to connect to the backup pool(s) and query the main pool until it is back up and switch pools automatically.

Special option: `--no-refresh` - only send new work to the GC3355 when a new block is detected (default: always send new work GC3355)

GC3355-specific options:

```
--gc3355=DEV0,DEV1,...,DEVn      				enable GC3355 chip mining mode (default: no)
--gc3355-detect					      			automatically detect GC3355 miners (not for Windows) (default: no)
--freq=FREQUENCY  								set GC3355 core frequency in NONE dual mode (default: 600)
--gc3355-freq=DEV0:F0,DEV1:F1,...,DEVn:Fn		individual frequency setting
--gc3355-freq=DEV0:F0:CHIP0,...,DEVn:Fn:CHIPn	individual per chip frequency setting
--gc3355-autotune  								auto overclocking each GC3355 chip (default: no)
--gc3355-timeout=N  							max. time in seconds after no share is submitted before restarting GC3355 (default: never)
```

If you cannot find any /dev/ttyUSB or /dev/ttyACM, it related to running cgminer, this can easily be fixed by rebooting the system.
You do not need the set the # of chips for USB Miner or G-Blade, it is detected automatically
Example with per chip tuned frequency setting, USB miner (ttyACM0) and G-Blade (ttyACM1, ttyACM2):

```
./minerd --gc3355-detect --freq=850 --gc3355-freq=/dev/ttyACM0:900,/dev/ttyACM0:875:1,/dev/ttyACM0:875:2,/dev/ttyACM1:825,/dev/ttyACM1:1025:32,/dev/ttyACM2:825,/dev/ttyACM2:850:10
```

The syntax is:
```
--gc3355-freq=DEV0:F0:CHIP0,...,DEVn:Fn:CHIPn
where n = 0,1,...,chip_count-1
USB miner -> chip_count = 5
G-Blade -> chip_count = 40
```

Example script with backup pools for *nix:

```
./minerd --gc3355-detect --gc3355-freq=/dev/ttyACM0:800 --gc3355-autotune --freq=850 --url=stratum+tcp://pool1:port --userpass=user1:pass1 --url=stratum+tcp://pool2:port --userpass=user2:pass2
```

Example script with backup pools for Windows:

```
minerd.exe --gc3355=\\.\COM1,\\.\COM2,\\.\COM3 --gc3355-freq=\\.\COM1:800 --gc3355-autotune --freq=850 --url=stratum+tcp://pool1:port --userpass=user1:pass1 --url=stratum+tcp://pool2:port --userpass=user2:pass2
pause
```

API
==============
The API is accessible on port 4028 (by default), to change the port pass --api-port=PORT
One GET command is currently supported:
```
{"get":"stats"}\n
```
This will output a JSON encoded array with mining stats for each GC3355 chip.
One SET command is currently supported:
```
{"set":"frequency", "devices":{"ttyACM0":{"chips":[825,850,875,900,850]}}}\n
```
This will set the frequency on the fly of the GC3355 chips to 825MHz (chip0), 850MHz (chip1), 875MHz (chip2), 900MHz (chip3), 850MHz (chip4)
You can specify multiple devices, but the length of the chips array must be equal to the number of chips on the GC3355 miners, Blades have 40 chips but you can only address chip0-7 (clusters of 5 chips), so the max is 8.
To translate the JSON keys, please refer to cpu-miner.c:66
Do not forget the newline (\n), it is used to tell the API to stop reading and execute the command!
Windows is not supported.

Binaries
==============

Windows: https://www.dropbox.com/s/ttqa9p851siz8oi/minerd-gc3355.zip

Raspberry PI: https://www.dropbox.com/s/xc3lvysi8vtrt00/minerd-gc3355

Support
==============

`BTC: 1AMsjqzXQpRunxUmtn3xzQ5cMdhV7fmet2`


`LTC: Lc75scqhMCkpMhC3aYGPVB4BEAzHvvz2rm`


`DOGE: DFZ3rxAUgFspMfpZbqMzgRFFQKiT695HCo`