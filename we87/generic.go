package we87

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/denverdino/aliyungo/common"
	"github.com/denverdino/aliyungo/ecs"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

// Driver for we87
type Driver struct {
	*drivers.BaseDriver
	EnginePort int
	SSHKey     string
	SSHPasswd  string
	PublicKey  []byte

	// ecs
	UpgradeKernel bool
	AutoFmtDisk   bool
	AccessKey     string
	SecretKey     string
	Region        common.Region
	client        *ecs.Client
}

const (
	defaultTimeout = 1 * time.Second
	defaultRegion  = "cn-shanghai"
	timeout        = 300
)

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.IntFlag{
			Name:   "we87-engine-port",
			Usage:  "Docker engine port",
			Value:  engine.DefaultPort,
			EnvVar: "WE87_ENGINE_PORT",
		},
		mcnflag.StringFlag{
			Name:   "we87-ip-address",
			Usage:  "IP Address of machine",
			EnvVar: "WE87_IP_ADDRESS",
		},
		mcnflag.StringFlag{
			Name:   "we87-ssh-user",
			Usage:  "SSH user",
			Value:  drivers.DefaultSSHUser,
			EnvVar: "WE87_SSH_USER",
		},
		mcnflag.StringFlag{
			Name:   "we87-ssh-key",
			Usage:  "SSH private key path (if not provided, default SSH key will be used)",
			Value:  "",
			EnvVar: "WE87_SSH_KEY",
		},
		mcnflag.StringFlag{
			Name:   "we87-ssh-password",
			Usage:  "SSH password, if provided, it will be used to upload the key to host",
			Value:  "",
			EnvVar: "WE87_SSH_PASSWORD",
		},
		mcnflag.IntFlag{
			Name:   "we87-ssh-port",
			Usage:  "SSH port",
			Value:  drivers.DefaultSSHPort,
			EnvVar: "WE87_SSH_PORT",
		},
		mcnflag.StringFlag{
			Name:   "we87-access-key-id",
			Usage:  "WE87 Access Key ID",
			Value:  "",
			EnvVar: "WE87_ACCESS_KEY_ID",
		},
		mcnflag.StringFlag{
			Name:   "we87-access-key-secret",
			Usage:  "WE87 Access Key Secret",
			Value:  "",
			EnvVar: "WE87_ACCESS_KEY_SECRET",
		},
		mcnflag.BoolFlag{
			Name:   "we87-upgrade-kernel",
			Usage:  "Upgrade kernel for instance (Ubuntu 14.04 only)",
			EnvVar: "WE87_UPGRADE_KERNEL",
		},
		mcnflag.BoolFlag{
			Name:   "we87-auto-format-disk",
			Usage:  "Auto format external disk and mount to /var/lib/docker",
			EnvVar: "WE87_UPGRADE_KERNEL",
		},
		mcnflag.StringFlag{
			Name:   "we87-region",
			Usage:  "WE87 region, default " + defaultRegion,
			Value:  defaultRegion,
			EnvVar: "WE87_REGION",
		},
	}
}

// NewDriver creates and returns a new instance of the driver
func NewDriver(hostName, storePath string) drivers.Driver {
	return &Driver{
		EnginePort: engine.DefaultPort,
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "we87"
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

func (d *Driver) GetSSHKeyPath() string {
	return d.SSHKeyPath
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {

	d.EnginePort = flags.Int("we87-engine-port")
	d.IPAddress = flags.String("we87-ip-address")
	d.SSHUser = flags.String("we87-ssh-user")
	d.SSHKey = flags.String("we87-ssh-key")
	d.SSHPort = flags.Int("we87-ssh-port")
	d.SSHPasswd = flags.String("we87-ssh-password")

	d.AccessKey = flags.String("we87-access-key-id")
	d.SecretKey = flags.String("we87-access-key-secret")
	region, err := validateECSRegion(flags.String("we87-region"))
	if err != nil {
		return err
	}
	d.Region = region
	d.UpgradeKernel = flags.Bool("we87-upgrade-kernel")
	d.AutoFmtDisk = flags.Bool("we87-auto-format-disk")

	if d.IPAddress == "" {
		return errors.New("generic driver requires the --we87-ip-address option")
	}

	return nil
}

func (d *Driver) PreCreateCheck() error {
	if d.SSHKey != "" {
		if _, err := os.Stat(d.SSHKey); os.IsNotExist(err) {
			return fmt.Errorf("SSH key does not exist: %q", d.SSHKey)
		}

		// TODO: validate the key is a valid key
	}

	return nil
}

func (d *Driver) Create() error {
	ssh.SetDefaultClient(ssh.Native)

	if err := d.prepareSSHAccess(); err != nil {
		return err
	}

	if err := d.provision(); err != nil {
		return err
	}

	log.Debugf("IP: %s", d.IPAddress)

	return nil
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, strconv.Itoa(d.EnginePort))), nil
}

func (d *Driver) GetState() (state.State, error) {
	inst, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}
	switch ecs.InstanceStatus(inst.Status) {
	case ecs.Starting:
		return state.Starting, nil
	case ecs.Running:
		return state.Running, nil
	case ecs.Stopping:
		return state.Stopping, nil
	case ecs.Stopped:
		return state.Stopped, nil
	default:
		return state.Error, nil
	}
}

func (d *Driver) Start() error {
	inst, err := d.getInstance()
	if err != nil {
		return err
	}
	if err := d.getClient().StartInstance(inst.InstanceId); err != nil {
		log.Errorf("Failed to start instance %s: %v", inst.InstanceId, err)
		return err
	}

	// Wait for running
	err = d.getClient().WaitForInstance(inst.InstanceId, ecs.Running, timeout)
	if err != nil {
		log.Errorf("Failed to wait instance %s running: %v", inst.InstanceId, err)
		return err
	}

	return nil
}

func (d *Driver) Stop() error {
	inst, err := d.getInstance()
	if err != nil {
		return err
	}
	if err := d.getClient().StopInstance(inst.InstanceId, false); err != nil {
		log.Errorf("Failed to stop instance %s: %v", inst.InstanceId, err)
		return err
	}

	// Wait for stopped
	err = d.getClient().WaitForInstance(inst.InstanceId, ecs.Stopped, timeout)
	if err != nil {
		log.Errorf("Failed to wait instance %s stopped: %v", inst.InstanceId, err)
		return err
	}

	return nil
}

func (d *Driver) Restart() error {
	inst, err := d.getInstance()
	if err != nil {
		return err
	}
	if err := d.getClient().RebootInstance(inst.InstanceId, false); err != nil {
		return fmt.Errorf("Unable to restart instance %s: %s", inst.InstanceId, err)
	}
	return nil
}

func (d *Driver) Kill() error {
	inst, err := d.getInstance()
	if err != nil {
		return err
	}

	log.Debug("Killing instance ...")
	if err := d.getClient().StopInstance(inst.InstanceId, true); err != nil {
		return fmt.Errorf("Unable to kill instance %s: %s", inst.InstanceId, err)
	}
	return nil
}

func (d *Driver) Remove() error {
	return nil
}

func (d *Driver) getClient() *ecs.Client {
	if d.client == nil {
		client := ecs.NewClient(d.AccessKey, d.SecretKey)
		client.SetDebug(false)
		d.client = client
	}
	return d.client
}

func (d *Driver) getInstance() (*ecs.InstanceAttributesType, error) {
	instances, _, err := d.getClient().DescribeInstances(&ecs.DescribeInstancesArgs{
		RegionId:            d.Region,
		InstanceNetworkType: "Vpc",
		PrivateIpAddresses:  `["` + d.IPAddress + `"]`,
	})
	if err != nil {
		return nil, err
	}
	if len(instances) != 1 {
		return nil, errors.New("cannot determine the instance")
	}
	return &instances[0], err
}

func (d *Driver) createKeyPair() error {
	log.Debugf("SSH key path: %s", d.GetSSHKeyPath())
	d.SSHKeyPath = d.ResolveStorePath("id_rsa")
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	d.PublicKey = publicKey
	return nil
}

func (d *Driver) prepareSSHAccess() error {
	if d.SSHKey == "" {
		if d.SSHPasswd == "" {
			log.Infof("No SSH password. Connecting to this machine now and in the" +
				" futur will require the ssh agent to contain the appropriate key.")
			return nil
		}
		log.Info("No SSH key specified. Creating key pair for instance ...")
		if err := d.createKeyPair(); err != nil {
			return fmt.Errorf("Failed to create key pair: %v", err)
		}
		ipAddr := d.IPAddress
		port, _ := d.GetSSHPort()
		tcpAddr := fmt.Sprintf("%s:%d", ipAddr, port)
		log.Infof("Waiting SSH service %s is ready to connect ...", tcpAddr)
		auth := ssh.Auth{
			Passwords: []string{d.SSHPasswd},
		}
		sshClient, err := ssh.NewClient(d.GetSSHUsername(), ipAddr, port, &auth)
		if err != nil {
			return err
		}
		if err := d.uploadKeypair(sshClient); err != nil {
			return err
		}
	} else {
		log.Info("Importing SSH key...")
		d.SSHKeyPath = d.ResolveStorePath(path.Base(d.SSHKey))
		if err := copySSHKey(d.SSHKey, d.SSHKeyPath); err != nil {
			return err
		}
		if err := copySSHKey(d.SSHKey+".pub", d.SSHKeyPath+".pub"); err != nil {
			log.Infof("Couldn't copy SSH public key : %s", err)
		}
	}
	return nil
}

func (d *Driver) provision() error {
	sshClient, err := drivers.GetSSHClientFromDriver(d)
	if err != nil {
		return err
	}

	d.fixRoutingRules(sshClient)

	d.installCurl(sshClient)

	if d.AutoFmtDisk {
		d.autoFdisk(sshClient)
	}

	if d.UpgradeKernel {
		d.upgradeKernel(sshClient)
	}

	d.enableNFS(sshClient)

	d.disableSSHPasswordLogin(sshClient)

	d.enableOssFuseHelper(sshClient)

	return nil
}

func (d *Driver) uploadKeypair(sshClient ssh.Client) error {
	log.Info("Uploading SSH keypair ...")

	command := fmt.Sprintf("mkdir -p ~/.ssh; echo '%s' > ~/.ssh/authorized_keys", string(d.PublicKey))
	log.Debugf("Upload the public key with command: %s", command)
	output, err := sshClient.Output(command)
	log.Debugf("Upload command err: %v, output: %s", err, output)
	if err != nil {
		return err
	}

	return nil
}

// Fix the routing rules
func (d *Driver) fixRoutingRules(sshClient ssh.Client) {
	output, err := sshClient.Output("route del -net 172.16.0.0/12")
	log.Debugf("Delete route command err: %v, output: %s", err, output)

	output, err = sshClient.Output("if [ -e /etc/network/interfaces ]; then sed -i '/^up route add -net 172.16.0.0 netmask 255.240.0.0 gw/d' /etc/network/interfaces; fi")
	log.Debugf("Fix route in /etc/network/interfaces command err: %v, output: %s", err, output)

	output, err = sshClient.Output("if [ -e /etc/sysconfig/network-scripts/route-eth0 ]; then sed -i '/^172.16.0.0\\/12 via /d' /etc/sysconfig/network-scripts/route-eth0; fi")
	log.Debugf("Fix route in /etc/sysconfig/network-scripts/route-eth0 command err: %v, output: %s", err, output)
}

// Mount the addtional disk
func (d *Driver) autoFdisk(sshClient ssh.Client) {
	script := fmt.Sprintf("cat > ~/machine_autofdisk.sh <<MACHINE_EOF\n%s\nMACHINE_EOF\n", autoFdiskScript)
	output, err := sshClient.Output(script)
	output, err = sshClient.Output("bash ~/machine_autofdisk.sh")
	log.Debugf("Auto Fdisk command err: %v, output: %s", err, output)
}

// Disable ssh password access
func (d *Driver) disableSSHPasswordLogin(sshClient ssh.Client) {
	script := fmt.Sprintf("cat > ~/machine_secssh.sh <<MACHINE_EOF\n%s\nMACHINE_EOF\n", disableSSHPassword)
	output, err := sshClient.Output(script)
	output, err = sshClient.Output("bash ~/machine_secssh.sh")
	log.Debugf("Secure ssh command err: %v, output: %s", err, output)
}

// Install oss fuse helper, if want to deploy ossfs container
func (d *Driver) enableOssFuseHelper(sshClient ssh.Client) {
	script := fmt.Sprintf("cat > ~/ossfuse_helper.sh <<MACHINE_EOF\n%s\nMACHINE_EOF\n", ossfuseHelper)
	output, err := sshClient.Output(script)
	output, err = sshClient.Output("bash ~/ossfuse_helper.sh")
	log.Debugf("OSS fuse helper command err: %v, output: %s", err, output)
}

// Install Kernel 4.4
func (d *Driver) upgradeKernel(sshClient ssh.Client) {
	log.Debug("Upgrade kernel version ...")
	output, err := sshClient.Output("for i in 1 2 3 4 5; do apt-get update -y && break || sleep 5; done")
	log.Infof("apt-get update err: %v, output: %s", err, output)
	output, err = sshClient.Output("for i in 1 2 3 4 5; do apt-get install -y linux-generic-lts-xenial && break || sleep 5; done")
	log.Infof("Upgrade kernel err: %v, output: %s", err, output)
	time.Sleep(5 * time.Second)
	log.Info("Restart VM instance for kernel update ...")
	d.Restart()
	time.Sleep(30 * time.Second)
}

// Install curl
func (d *Driver) installCurl(sshClient ssh.Client) {
	log.Debug("install curl ...")
	output, err := sshClient.Output("for i in 1 2 3 4 5; do apt-get install -y curl && break || sleep 5; done")
	log.Infof("apt-get install curl err: %v, output: %s", err, output)
}

// Enable NFS
func (d *Driver) enableNFS(sshClient ssh.Client) {
	log.Debug("enabling nfs ...")
	output, err := sshClient.Output("modprobe nfs && lsmod | grep nfs")
	log.Infof("modprobe nfs err: %v, output: %s", err, output)
	output, err = sshClient.Output(`echo nfs >>/etc/modules && cat /etc/modules`)
	log.Infof("echo nfs >>/etc/modules err: %v, output: %s", err, output)
}

func copySSHKey(src, dst string) error {
	if err := mcnutils.CopyFile(src, dst); err != nil {
		return fmt.Errorf("unable to copy ssh key: %s", err)
	}

	if err := os.Chmod(dst, 0600); err != nil {
		return fmt.Errorf("unable to set permissions on the ssh key: %s", err)
	}

	return nil
}

func validateECSRegion(region string) (common.Region, error) {
	for _, v := range common.ValidRegions {
		if v == common.Region(region) {
			return v, nil
		}
	}

	return "", errors.New("invalid region specified")
}
