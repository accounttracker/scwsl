# try

<pre></code>
apt update -y && apt-get update -y && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt install -y bzip2 gzip coreutils screen curl unzip wget && wget https://raw.githubusercontent.com/anzclan/scwsl/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh
</code></pre>
