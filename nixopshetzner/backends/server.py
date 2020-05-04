# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import socket
import struct
import subprocess
from typing import Optional

from hetzner.robot import Robot

from nixops import known_hosts
from nixops.util import wait_for_tcp_port, ping_tcp_port
from nixops.util import attr_property, create_key_pair
from nixops.ssh_util import SSHCommandFailed
from nixops.backends import MachineDefinition, MachineState
from nixops.nix_expr import nix2py

# This is set to True by tests/hetzner-backend.nix. If it's in effect, no
# attempt is made to connect to the real Robot API and the API calls only
# return dummy objects.
TEST_MODE = False


class TestModeServer(object):
    """
    Server object from the Hetzner API but mocked up to return only dummy
    values.
    """

    def reboot(self, method):
        return None

    def set_name(self, method):
        return None

    class admin(object):
        create = classmethod(lambda cls: ("test_user", "test_pass"))
        delete = classmethod(lambda cls: None)

    class rescue(object):
        activate = classmethod(lambda cls: None)
        password = "abcd1234"


class HetznerDefinition(MachineDefinition):
    """
    Definition of a Hetzner machine.
    """

    @classmethod
    def get_type(cls):
        return "hetzner"

    def __init__(self, xml, config):
        super().__init__(name,config)
        self.main_ipv4 = config["mainIPv4"]
        self.create_sub_account = config["createSubAccount"]
        self.robot_user = config["robotUser"]
        self.robot_pass = config["robotPass"]
        self.partitions = config["partitions"]


class HetznerState(MachineState):
    """
    State of a Hetzner machine.
    """

    @classmethod
    def get_type(cls):
        return "hetzner"

    state = attr_property("state", MachineState.UNKNOWN, int)

    main_ipv4 = attr_property("hetzner.mainIPv4", None)
    robot_admin_user = attr_property("hetzner.robotUser", None)
    robot_admin_pass = attr_property("hetzner.robotPass", None)
    partitions = attr_property("hetzner.partitions", None)

    just_installed = attr_property("hetzner.justInstalled", False, bool)
    rescue_passwd = attr_property("hetzner.rescuePasswd", None)
    fs_info = attr_property("hetzner.fsInfo", None)
    net_info = attr_property("hetzner.networkInfo", None, "json")
    hw_info = attr_property("hetzner.hardwareInfo", None)

    main_ssh_private_key = attr_property("hetzner.sshPrivateKey", None)
    main_ssh_public_key = attr_property("hetzner.sshPublicKey", None)

    def __init__(self, depl, name, id):
        MachineState.__init__(self, depl, name, id)
        self._robot = None

    @property
    def resource_id(self) -> Optional[str]:
        return self.vm_id

    @property
    def public_ipv4(self) -> Optional[str]:
        return self.main_ipv4

    def connect(self) -> Robot:
        """
        Connect to the Hetzner robot by using the admin credetials in
        'self.robot_admin_user' and 'self.robot_admin_pass'.
        """
        if self._robot is not None:
            return self._robot

        self._robot = Robot(self.robot_admin_user, self.robot_admin_pass)
        return self._robot

    def _get_robot_user_and_pass(
        self,
        defn: Optional[HetznerDefinition] = None,
        default_user=None,
        default_pass=None,
    ):
        """
        Fetch the server instance using the main robot user and passwords
        from the MachineDefinition passed by 'defn'. If the definition does not
        contain these credentials or is None, it is tried to fetch it from
        environment variables.
        """
        if defn is not None and len(defn.robot_user) > 0:
            robot_user = defn.robot_user
        else:
            robot_user = os.environ.get("HETZNER_ROBOT_USER", default_user)

        if defn is not None and len(defn.robot_pass) > 0:
            robot_pass = defn.robot_pass
        else:
            robot_pass = os.environ.get("HETZNER_ROBOT_PASS", default_pass)

        if robot_user is None:
            raise Exception(
                "please either set ‘deployment.hetzner.robotUser’"
                " or $HETZNER_ROBOT_USER for machine"
                f" ‘{self.name}’"
            )
        elif robot_pass is None:
            raise Exception(
                "please either set ‘deployment.hetzner.robotPass’"
                " or $HETZNER_ROBOT_PASS for machine"
                f" ‘{self.name}’"
            )

        return (robot_user, robot_pass)

    def _get_server_from_main_robot(self, ip, defn=None):
        (robot_user, robot_pass) = self._get_robot_user_and_pass(defn=defn)

        if TEST_MODE:
            return TestModeServer()

        robot = Robot(robot_user, robot_pass)
        return robot.servers.get(ip)

    def _get_server_by_ip(self, ip):
        """
        Queries the robot for the given ip address and returns the Server
        instance if it was found.
        """
        if TEST_MODE:
            return TestModeServer()

        robot = self.connect()
        return robot.servers.get(ip)

    def get_ssh_private_key_file(self):
        if self._ssh_private_key_file:
            return self._ssh_private_key_file
        else:
            return self.write_ssh_private_key(self.main_ssh_private_key)

    def get_ssh_flags(self, *args, **kwargs):
        return super(HetznerState, self).get_ssh_flags(*args, **kwargs) + (
            [
                "-o",
                "LogLevel=quiet",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ]
            if self.state == self.RESCUE
            else
            # XXX: Disabling strict host key checking will only impact the
            # behaviour on *new* keys, so it should be "reasonably" safe to do
            # this until we have a better way of managing host keys in
            # ssh_util. So far this at least avoids to accept every damn host
            # key on a large deployment.
            [
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-i",
                self.get_ssh_private_key_file(),
            ]
        )

    def _wait_for_rescue(self, ip):
        if not TEST_MODE:
            # In test mode, the target machine really doesn't go down at all,
            # so only wait for the reboot to finish when deploying real
            # systems.
            self.log_start("waiting for rescue system...")

            def dotlog():
                self.log_continue(".")

            wait_for_tcp_port(ip, 22, open=False, callback=dotlog)
            self.log_continue("[down]")
            wait_for_tcp_port(ip, 22, callback=dotlog)
            self.log_end("[up]")
        self.state = self.RESCUE

    def _bootstrap_rescue_for_existing_system(self):
        """
        Make sure that an existing system is easy to work on and set everything
        up properly to enter a chrooted shell on the target system.
        """
        self.log_start("mounting /mnt/run... ")
        self.run_command("mkdir -m 0755 -p /mnt/run")
        self.run_command("mount -t tmpfs -o mode=0755 none /mnt/run")
        self.log_end("done.")

        self.log_start("symlinking /mnt/run/current-system... ")
        self.run_command(
            "ln -s /nix/var/nix/profiles/system " "/mnt/run/current-system"
        )
        self.log_end("done.")

        self.log_start("adding note on ‘nixos-enter’ to motd... ")
        cmd = "nixos-enter"
        msg = f"Use {cmd} to enter a shell on the target system"
        msglen = len(msg)
        csimsg = msg.format(f"\033[1;32m{cmd}\033[37m")
        hborder = "-" * (msglen + 2)
        fullmsg = "\033[1;30m{}\033[m\n\n".format(
            "\n".join(
                [f"+{hborder}+", f"| \033[37;1m{csimsg}\033[30m |", f"+{hborder}+",]
            )
        )
        self.run_command("cat >> /etc/motd", stdin_string=fullmsg)
        self.log_end("done.")

    def _bootstrap_rescue(self, install: bool, partitions):
        """
        Bootstrap everything needed in order to get Nix and the partitioner
        usable in the rescue system. The keyword arguments are only for
        partitioning, see reboot_rescue() for description, if not given we will
        only mount based on information provided in self.partitions.
        """
        self.log_start("building Nix bootstrap installer... ")
        expr = os.path.realpath(
            os.path.dirname(__file__)
            + "../../../../../../share/nix/nixops-hetzner/hetzner-bootstrap.nix"
        )
        bootstrap_out = subprocess.check_output(
            ["nix-build", expr, "--no-out-link"]
        ).rstrip()
        bootstrap = os.path.join(bootstrap_out, "bin/hetzner-bootstrap")
        self.log_end(f"done. ({bootstrap})")

        self.log_start("creating nixbld group in rescue system... ")
        self.run_command(
            "getent group nixbld > /dev/null || " "groupadd -g 30000 nixbld"
        )
        self.log_end("done.")

        self.log_start("checking if tmpfs in rescue system is large enough... ")
        dfstat = self.run_command("stat -f -c '%a:%S' /", capture_stdout=True)
        df, bs = dfstat.split(":")
        free_mb = (int(df) * int(bs)) // 1024 // 1024
        if free_mb > 300:
            self.log_end(f"yes: {free_mb} MB")
            tarcmd = "tar x -C /"
        else:
            self.log_end(f"no: {free_mb} MB")
            tarexcludes = [
                "*/include",
                "*/man",
                "*/info",
                "*/locale",
                "*/locales",
                "*/share/doc",
                "*/share/aclocal",
                "*/example",
                "*/terminfo",
                "*/pkgconfig",
                "*/nix-support",
                "*/etc",
                "*/bash-completion",
                "*.a",
                "*.la",
                "*.pc",
                "*.lisp",
                "*.pod",
                "*.html",
                "*.pyc",
                "*.pyo",
                "*-kbd-*/share",
                "*-gcc-*/bin",
                "*-gcc-*/libexec",
                "*-systemd-*/bin",
                "*-boehm-gc-*/share",
            ]
            tarcmd = "tar x -C / " + " ".join(
                [f"--exclude='{glob}'" for glob in tarexcludes]
            )

        # The command to retrieve our split TAR archive on the other side.
        recv = f'read -d: tarsize; head -c "$tarsize" | {tarcmd}; {tarcmd}'

        self.log_start("copying bootstrap files to rescue system... ")
        tarstream = subprocess.Popen([bootstrap], stdout=subprocess.PIPE)
        if not self.has_fast_connection:
            stream = subprocess.Popen(
                ["gzip", "-c"], stdin=tarstream.stdout, stdout=subprocess.PIPE
            )
            self.run_command(f"gzip -d | ({recv})", stdin=stream.stdout)
            stream.wait()
        else:
            self.run_command(recv, stdin=tarstream.stdout)
        tarstream.wait()
        self.log_end("done.")

        if install:
            self.log_start("partitioning disks... ")
            try:
                out = self.run_command(
                    "nixpart -p -", capture_stdout=True, stdin_string=partitions
                )
            except SSHCommandFailed as failed_command:
                # Exit code 100 is when the partitioner requires a reboot.
                if failed_command.exitcode == 100:
                    self.log(failed_command.message)
                    self.reboot_rescue(install, partitions)
                    return
                else:
                    raise

            # This is the *only* place to set self.partitions unless we have
            # implemented a way to repartition the system!
            self.partitions = partitions
            self.fs_info = out
        else:
            self.log_start("mounting filesystems... ")
            self.run_command("nixpart -m -", stdin_string=self.partitions)
        self.log_end("done.")

        if not install:
            self.log_start("checking if system in /mnt is NixOS... ")
            res = self.run_command("test -e /mnt/etc/NIXOS", check=False)
            if res == 0:
                self.log_end("yes.")
                self._bootstrap_rescue_for_existing_system()
            else:
                self.log_end("NO! Not mounting special filesystems.")
                return

        self.log_start("bind-mounting special filesystems... ")
        for mountpoint in ("/proc", "/dev", "/dev/shm", "/sys"):
            self.log_continue(f"{mountpoint}...")
            cmd = f"mkdir -m 0755 -p /mnt{mountpoint} && "
            cmd += f"mount --bind {mountpoint} /mnt{mountpoint}"
            self.run_command(cmd)
        self.log_end("done.")

    def reboot(self, hard: bool = False):
        if hard:
            self.log_start("sending hard reset to robot... ")
            server = self._get_server_by_ip(self.main_ipv4)
            server.reboot("hard")
            self.log_end("done.")
            self.state = self.STARTING
            self.ssh.reset()
        else:
            MachineState.reboot(self, hard=hard)

    def reboot_rescue(
        self, install=False, partitions=None, bootstrap: bool = True, hard: bool = False
    ) -> None:
        """
        Use the Robot to activate the rescue system and reboot the system. By
        default, only mount partitions and do not partition or wipe anything.

        On installation, both 'installed' has to be set to True and partitions
        should contain a Kickstart configuration, otherwise it's read from
        self.partitions if available (which it shouldn't if you're not doing
        something nasty).
        """
        self.log(
            f"rebooting machine ‘{self.name}’ ({self.main_ipv4}) into rescue system"
        )
        server = self._get_server_by_ip(self.main_ipv4)
        server.rescue.activate()
        rescue_passwd = server.rescue.password
        if hard or (install and self.state not in (self.UP, self.RESCUE)):
            self.log_start("sending hard reset to robot... ")
            server.reboot("hard")
        else:
            self.log_start("sending reboot command... ")
            if self.state == self.RESCUE:
                self.run_command("(sleep 2; reboot) &", check=False)
            else:
                self.run_command("systemctl reboot", check=False)
        self.log_end("done.")
        self._wait_for_rescue(self.main_ipv4)
        self.rescue_passwd = rescue_passwd
        self.state = self.RESCUE
        self.ssh.reset()
        if bootstrap:
            self._bootstrap_rescue(install, partitions)

    def _install_base_system(self):
        self.log_start("creating missing directories... ")
        cmds = ["mkdir -m 1777 -p /mnt/tmp /mnt/nix/store"]
        mntdirs = [
            "var",
            "etc",
            "bin",
            "nix/var/nix/gcroots",
            "nix/var/nix/temproots",
            "nix/var/nix/manifests",
            "nix/var/nix/userpool",
            "nix/var/nix/profiles",
            "nix/var/nix/db",
            "nix/var/log/nix/drvs",
        ]
        to_create = " ".join(map(lambda d: os.path.join("/mnt", d), mntdirs))
        cmds.append(f"mkdir -m 0755 -p {to_create}")
        self.run_command(" && ".join(cmds))
        self.log_end("done.")

        self.log_start("bind-mounting files in /etc... ")
        for etcfile in ("resolv.conf", "passwd", "group"):
            self.log_continue(f"{etcfile}...")
            cmd = (
                f"if ! test -e /mnt/etc/{etcfile}; then"
                f" touch /mnt/etc/{etcfile} && mount --bind /etc/{etcfile} /mnt/etc/{etcfile};"
                " fi"
            )
            self.run_command(cmd)
        self.log_end("done.")

        self.run_command("touch /mnt/etc/NIXOS")
        self.run_command("activate-remote")

        self.main_ssh_private_key, self.main_ssh_public_key = create_key_pair(
            key_name=f"NixOps client key of {self.name}"
        )
        self._gen_network_spec()

    def _detect_hardware(self):
        self.log_start("detecting hardware... ")
        cmd = "nixos-generate-config --no-filesystems --show-hardware-config"
        hardware = self.run_command(cmd, capture_stdout=True)
        self.hw_info = "\n".join(
            [
                line
                for line in hardware.splitlines()
                if not line.lstrip().startswith("#")
            ]
        )
        self.log_end("done.")

    def switch_to_configuration(self, method, sync, command=None):
        if self.state == self.RESCUE:
            # We cannot use the mountpoint command here, because it's unable to
            # detect bind mounts on files, so we just go ahead and try to
            # unmount.
            umount = 'if umount "{0}" 2> /dev/null; then rm -f "{0}"; fi'
            cmd = "; ".join(
                [
                    umount.format(os.path.join("/mnt/etc", mnt))
                    for mnt in ("resolv.conf", "passwd", "group")
                ]
            )
            self.run_command(cmd)

            command = "chroot /mnt /nix/var/nix/profiles/system/bin/"
            command += "switch-to-configuration"

        res = MachineState.switch_to_configuration(self, method, sync, command)
        if res not in (0, 100):
            return res
        if self.state == self.RESCUE and self.just_installed:
            self.reboot_sync()
            self.just_installed = False
        return res

    def _get_ethernet_interfaces(self):
        """
        Return a list of all the ethernet interfaces active on the machine.
        """
        # We don't use \(\) here to ensure this works even without GNU sed.
        cmd = "ip addr show | sed -n -e 's/^[0-9]*: *//p' | cut -d: -f1"
        return self.run_command(cmd, capture_stdout=True).splitlines()

    def _get_udev_rule_for(self, interface):
        """
        Get lines suitable for services.udev.extraRules for 'interface',
        and thus essentially map the device name to a hardware address.
        """
        cmd = f"ip addr show \"{interface}\" | sed -n -e 's|^.*link/ether  *||p'"
        cmd += " | cut -d' ' -f1"
        mac_addr = self.run_command(cmd, capture_stdout=True).strip()

        rule = f'ACTION=="add", SUBSYSTEM=="net", ATTR{{address}}=="{mac_addr}", '
        rule += f'NAME="{interface}"'
        return rule

    def _get_ipv4_addr_and_prefix_for(self, interface):
        """
        Return a tuple of (ipv4_address, prefix_length) for the specified
        interface.
        """
        cmd = f"ip addr show \"{interface}\" | sed -n -e 's/^.*inet  *//p'"
        cmd += " | cut -d' ' -f1"
        ipv4_addr_prefix = self.run_command(cmd, capture_stdout=True).strip()
        if "/" not in ipv4_addr_prefix:
            # No IP address set for this interface.
            return None
        else:
            return ipv4_addr_prefix.split("/", 1)

    def _get_default_gw(self):
        """
        Return the default gateway of the currently running machine.
        """
        default_gw_cmd = "ip route list | sed -n -e 's/^default  *via  *//p'"
        default_gw_output = self.run_command(
            default_gw_cmd, capture_stdout=True
        ).strip()
        default_gw_output_split = default_gw_output.split(" ")
        gw_ip = default_gw_output_split[0]
        gw_dev = default_gw_output_split[2]
        return (gw_ip, gw_dev)

    def _get_nameservers(self):
        """
        Return a list of all nameservers defined on the currently running
        machine.
        """
        cmd = "cat /etc/resolv.conf | sed -n -e 's/^nameserver  *//p'"
        return self.run_command(cmd, capture_stdout=True).splitlines()

    def _indent(self, lines, level=1):
        """
        Indent list of lines by the specified level (one level = two spaces).
        """
        return map(lambda line: "  " + line, lines)

    def _calculate_ipv4_subnet(self, ipv4, prefix_len):
        """
        Returns the address of the subnet for the given 'ipv4' and
        'prefix_len'.
        """
        bits = struct.unpack("!L", socket.inet_aton(ipv4))[0]
        mask = 0xFFFFFFFF >> (32 - prefix_len) << (32 - prefix_len)
        return socket.inet_ntoa(struct.pack("!L", bits & mask))

    def _gen_network_spec(self):
        """
        Generate Nix expressions related to networking configuration based on
        the currently running machine (most likely in RESCUE state) and set the
        resulting string to self.net_info.
        """
        udev_rules = []
        iface_attrs = {}

        server = self._get_server_by_ip(self.main_ipv4)

        # Global networking options
        defgw_ip, defgw_dev = self._get_default_gw()
        v6defgw = None

        # Interface-specific networking options
        for iface in self._get_ethernet_interfaces():
            if iface == "lo":
                continue

            result = self._get_ipv4_addr_and_prefix_for(iface)
            if result is None:
                continue

            udev_rules.append(self._get_udev_rule_for(iface))

            ipv4addr, prefix = result
            iface_attrs[iface] = {
                "ipv4": {
                    "addresses": [{"address": ipv4addr, "prefixLength": int(prefix)},],
                },
            }

            # We can't handle Hetzner-specific networking info in test mode.
            if TEST_MODE:
                continue

            # Extra route for accessing own subnet for this interface
            # (see https://wiki.hetzner.de/index.php/Netzkonfiguration_Debian/en#IPv4),
            # but only if it's not the interface for the default gateway,
            # because that one will already get such a route generated
            # by NixOS's `network-setup.service`. See also:
            #   https://github.com/NixOS/nixops/pull/1032#issuecomment-433741624
            if iface != defgw_dev:
                net = self._calculate_ipv4_subnet(ipv4addr, int(prefix))
                iface_attrs[iface]["ipv4"] = {
                    "routes": [
                        {"address": net, "prefixLength": int(prefix), "via": defgw_ip,}
                    ],
                }

            # IPv6 subnets only for eth0
            v6subnets = []
            for subnet in server.subnets:
                if "." in subnet.net_ip:
                    # skip IPv4 addresses
                    continue
                v6subnets.append(
                    {"address": subnet.net_ip, "prefixLength": int(subnet.mask)}
                )
                assert v6defgw is None or v6defgw.get("address") == subnet.gateway
                v6defgw = {
                    "address": subnet.gateway,
                    "interface": defgw_dev,
                }
            iface_attrs[iface]["ipv6"] = {"addresses": v6subnets}

        self.net_info = {
            "services": {"udev": {"extraRules": "\n".join(udev_rules) + "\n"},},
            "networking": {
                "interfaces": iface_attrs,
                "defaultGateway": {"address": defgw_ip, "interface": defgw_dev,},
                "defaultGateway6": v6defgw,
                "nameservers": self._get_nameservers(),
            },
        }

    def get_physical_spec(self):
        if all([self.net_info, self.fs_info, self.hw_info, self.main_ssh_public_key]):
            return {
                "config": dict(
                    self.net_info.items()
                    + {
                        (
                            "users",
                            "extraUsers",
                            "root",
                            "openssh",
                            "authorizedKeys",
                            "keys",
                        ): [self.main_ssh_public_key]
                    }.items()
                ),
                "imports": [nix2py(self.fs_info), nix2py(self.hw_info)],
            }
        else:
            return {}

    def create(
        self,
        defn: HetznerDefinition,
        check: bool,
        allow_reboot: bool,
        allow_recreate: bool,
    ):
        assert isinstance(defn, HetznerDefinition)

        if self.state not in (self.RESCUE, self.UP) or check:
            self.check()

        self.set_common_state(defn)
        self.main_ipv4 = defn.main_ipv4

        if defn.create_sub_account:
            if not self.robot_admin_user or not self.robot_admin_pass:
                self.log_start(
                    "creating an exclusive robot admin sub-account "
                    f"for ‘{self.name}’... "
                )
                server = self._get_server_from_main_robot(self.main_ipv4, defn)
                with self.depl._db:
                    (
                        self.robot_admin_user,
                        self.robot_admin_pass,
                    ) = server.admin.create()
                self.log_end(f"done. ({self.robot_admin_user})")
        else:
            # If available, assign user and password even if they are already
            # in the DB, so that changes to them are immediately reflected.
            # If not available, we use the ones from the DB.
            (robot_user, robot_pass) = self._get_robot_user_and_pass(
                defn=defn,
                default_user=self.robot_admin_user,
                default_pass=self.robot_admin_pass,
            )
            if (
                robot_user != self.robot_admin_user
                or robot_pass != self.robot_admin_pass
            ):
                with self.depl._db:
                    (self.robot_admin_user, self.robot_admin_pass) = (
                        robot_user,
                        robot_pass,
                    )

        if not self.vm_id:
            self.log("installing machine...")
            self.reboot_rescue(install=True, partitions=defn.partitions)
            self._install_base_system()
            self._detect_hardware()
            server = self._get_server_by_ip(self.main_ipv4)
            vm_id = f"nixops-{self.depl.uuid}-{self.name}"
            server.set_name(vm_id[:100])
            self.vm_id = vm_id
            known_hosts.remove(self.main_ipv4, None)
            self.just_installed = True
            self.state_version = defn.config["nixosRelease"]

    def start(self):
        """
        Start the server into the normal system (a reboot is done if the rescue
        system is active).
        """
        if self.state == self.UP:
            return
        elif self.state == self.RESCUE:
            self.reboot()
        elif self.state in (self.STOPPED, self.UNREACHABLE):
            self.log_start("server was shut down, sending hard reset... ")
            server = self._get_server_by_ip(self.main_ipv4)
            server.reboot("hard")
            self.log_end("done.")
            self.state = self.STARTING
        self.wait_for_ssh(check=True)
        self.send_keys()

    def _wait_stop(self):
        """
        Wait for the system to shutdown and set state STOPPED afterwards.
        """
        self.log_start("waiting for system to shutdown... ")

        def dotlog():
            self.log_continue(".")  # NOQA

        wait_for_tcp_port(self.main_ipv4, 22, open=False, callback=dotlog)
        self.log_continue("[down]")

        self.state = self.STOPPED

    def stop(self):
        """
        Stops the server by shutting it down without powering it off.
        """
        if self.state not in (self.RESCUE, self.UP):
            return
        self.log_start("shutting down system... ")
        self.run_command("systemctl halt", check=False)
        self.log_end("done.")

        self.state = self.STOPPING
        self._wait_stop()

    def get_ssh_name(self):
        assert self.main_ipv4
        return self.main_ipv4

    def get_ssh_password(self):
        if self.state == self.RESCUE:
            return self.rescue_passwd
        else:
            return None

    def _check(self, res):
        if not self.vm_id:
            res.exists = False
            return

        if self.state in (self.STOPPED, self.STOPPING):
            res.is_up = ping_tcp_port(self.main_ipv4, 22)
            if not res.is_up:
                self.state = self.STOPPED
                res.is_reachable = False
                return

        res.exists = True
        avg = self.get_load_avg()
        if avg is None:
            if self.state in (self.UP, self.RESCUE):
                self.state = self.UNREACHABLE
            res.is_reachable = False
            res.is_up = False
        elif self.run_command("test -f /etc/NIXOS", check=False) != 0:
            self.state = self.RESCUE
            self.ssh_pinged = True
            self._ssh_pinged_this_time = True
            res.is_reachable = True
            res.is_up = False
        else:
            res.is_up = True
            MachineState._check(self, res)

    def _destroy(self, server, wipe):
        if self.state != self.RESCUE:
            self.reboot_rescue(bootstrap=False, hard=True)
        if wipe:
            self.log_start("erasing all data on disk... ")
            # Let it run in the background because it will take a long time.
            cmd = "nohup shred /dev/[sh]d? &> /dev/null < /dev/null &"
            self.run_command(cmd)
            self.log_end("done. (backgrounded)")
        self.log_start("unsetting server name... ")
        server.set_name("")
        self.log_end("done.")
        self.log_start("removing admin account... ")
        server.admin.delete()
        self.log_start("done.")
        self.log(f"machine left in rescue, password: " "{self.rescue_paswd}")
        return True

    def destroy(self, wipe=False):
        if not self.vm_id:
            return True

        # Create the instance as early as possible so if we don't have the
        # needed credentials, we can avoid to ask for confirmation.
        server = self._get_server_from_main_robot(self.main_ipv4)

        question_target = f"Hetzner machine ‘{self.name}’"
        if wipe:
            question = f"are you sure you want to completely erase {question_target}?"
        else:
            question = f"are you sure you want to destroy {question_target}?"
        if not self.depl.logger.confirm(question):
            return False

        return self._destroy(server, wipe)
