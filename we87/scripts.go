package we87

const autoFdiskScript = `#/bin/bash
#fdisk ,formating and create the file system on /dev/xvdb or /dev/vdb
DISK_ATTACH_POINT="/dev/xvdb"
fdisk_fun()
{
fdisk -S 56 \$DISK_ATTACH_POINT << EOF
n
p
1


wq
EOF

sleep 5
mkfs.ext4 \${DISK_ATTACH_POINT}1
}

#config /etc/fstab and mount device
main()
{
  if [ -b "/dev/vdb" ]; then
    DISK_ATTACH_POINT="/dev/vdb"
  elif [ ! -b "/dev/xvdb" ]; then
    echo "No extra disk found"
    exit 0
  fi

  if grep -qs "\$DISK_ATTACH_POINT" /proc/mounts; then
    echo "Disk \$DISK_ATTACH_POINT is already mounted, skip"
    exit 0
  fi

  fdisk_fun

  mkdir -p /data
  echo "\${DISK_ATTACH_POINT}1    /data     ext4    defaults        0 0" >>/etc/fstab
  mount -a

  mkdir -p /data/docker
  echo "/data/docker    /var/lib/docker     none    bind        0 0" >>/etc/fstab
  flag=0
  if [ -d "/var/lib/docker" ]; then
    flag=1
    service docker stop
    rsync -aXS /var/lib/docker/.  /data/docker/
    rm -rf /var/lib/docker
  else
    mkdir -p /var/lib/docker
  fi
  mount -a

  if [ \$flag==1 ]; then
    service docker start
  fi
}

main
df -h

`

const disableSSHPassword = `#/bin/bash
grep -q "ChallengeResponseAuthentication" /etc/ssh/sshd_config && sed -i "/^[^#]*ChallengeResponseAuthentication[[:space:]]yes.*/c\ChallengeResponseAuthentication no" /etc/ssh/sshd_config || echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
grep -q "^[^#]*PasswordAuthentication" /etc/ssh/sshd_config && sed -i "/^[^#]*PasswordAuthentication[[:space:]]yes/c\PasswordAuthentication no" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
service ssh restart

`

const ossfuseHelper = `#/bin/bash
grep -q "oss" /etc/updatedb.conf || sed -i.bak "s/PRUNEFS=\"/PRUNEFS=\"fuse.ossfs /" /etc/updatedb.conf
grep -q "oss" /etc/updatedb.conf || sed -i.bak "s/PRUNEPATHS=\"/PRUNEPATHS=\"\/oss /" /etc/updatedb.conf
rm -rf /etc/updatedb.conf.bak

# egg in egg
echo "SHELL=/bin/sh" >/etc/cron.d/ossfusehelper
echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >>/etc/cron.d/ossfusehelper
echo "@reboot root  mkdir -p /oss && mount --bind /oss /oss && mount --make-rshared /oss" >>/etc/cron.d/ossfusehelper

# mount inplace
mkdir -p /oss
mount | grep  -q "/oss" || mount --bind /oss /oss && mount --make-rshared /oss

`
