# Packaging for RPM (CentOS, RockyLinux, RHEL, Fedora, etc.)

## Generating a package file

We use CPack to generate `.rpm`s for Flexisip.

You need a [CMake build environment] with the additional requirement that `rpm` is installed.
The [`bc-dev-rocky9` docker image] meets those criteria.

You should refer to the [`.job-linux-rpm` CI job] for up-to-date instructions, but as of 2024-08-20, here is the gist:

```sh
mkdir build.rocky9.rpm && cd build.rocky9.rpm

cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DSYSCONF_INSTALL_DIR=/etc -DFLEXISIP_SYSTEMD_INSTALL_DIR=/usr/lib/systemd/system -DCPACK_GENERATOR=RPM ..

cmake --build . --target package
```

[CMake build environment]: ../../README.md#building-flexisip-with-cmake
[`bc-dev-rocky9` docker image]: ../../docker/bc-dev-rocky9
[`.job-linux-rpm` CI job]: ../../.gitlab-ci-files/job-linux.yml

## Testing the package

### Setting up a VM

Depending on what you want to test, a docker image *might* be enough.

However if you want to test the correct setup of SELinux policies, **docker simply won't do**.

> 🛈 As of 2024-08-20, and to the extent of my testing, it is simply impossible to have SELinux enabled inside a container (even with a SELinux-enabled host).

#### Virtual Machine Manager (virt-man)

[`virt-man`] is a graphical front-end to `libvirt`.
You should refer to your distro's documentation on how to install it (and `libvirt`). ([NixOS](https://nixos.wiki/wiki/Virt-manager))

We are going to create a Rocky 9 (Blue Onyx) minimal VM and run it on QEMU/KVM.

```sh
sudo mkdir --parent /var/lib/libvirt/boot

wget https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2

sudo virt-install \
      --name rocky9-flexisip-install-test \
      --connect qemu:///system \
      --memory 4096 \
      --vcpus 8 \
      --osinfo rocky9 \
      --import \
      --disk Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 \
      --cloud-init disable=on \
      --cloud-init root-ssh-key=$HOME/.ssh/id_ed25519.pub
```

> 🛈 The `mkdir` command might not be required on your system, but does not hurt.

> 🛈 `virt-install` is provided by the `virt-manager` package on my system.

You should be seeing the boot output of the VM in your terminal, which will end with a login prompt.
Do not attempt to login, all users are disabled.
Instead, scroll back to find the IP address of the VM in the local virtual network (look for `eth0`), we will be connecting to it via SSH.
(Your public key has been injected into the machine in the last step)


> 💡 You can also find the IP address of the VM from the Virtual Machine Manager GUI, in the NIC section.

Optionally, before `ssh`ing, you may copy the package you generated [earlier](#generating-a-package-file) into the VM.

```sh
scp bc-flexisip-2.*.rpm root@192.168.122.xxx:
```

The last step is to ssh into the VM and enable the [EPEL] repo so that our Flexisip package can find its required dependencies.
(As documented in [our installation wiki page]. Note that only step 1 is required, as we'll be installing Flexisip packages locally.)


```sh
ssh root@192.168.122.xxx
yum --assumeyes install epel-release
```

You are now ready to test that the package installs correctly

[`virt-man`]: https://virt-manager.org/
[EPEL]: https://docs.fedoraproject.org/en-US/epel/
[our installation wiki page]: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/1.%20Installation/#HCentos2FRockyLinux

### Checking installation

#### Cleaning up dependencies

Some (not so obvious) dependencies of our package might already be present on your test env.
To verify that the package properly declares them as dependencies, you must uninstall them first.
(As happened in [FLEXISIP-366](https://linphone.atlassian.net/browse/FLEXISIP-366))

```sh
sudo yum remove --assumeyes $(rpm --query --file \
      $(which semanage) \
      $(which restorecon) \
)
```

#### Installing the package

```sh
sudo yum --assumeyes --nogpgcheck localinstall ./bc-flexisip-2.*.rpm
```

#### Verifying SELinux policies

```sh
ls -l --all --context /var/opt/belledonne-communications/log/flexisip
```

The output should contain the following line

```
drwxr-xr-x. 2 root root unconfined_u:object_r:var_log_t:s0  6 Aug 21 13:27 .
#                  This is the important part ^^^^^^^^^
```

> 🛈 The default is `var_t`, but `var_log_t` is required for `logrotate` to do its job (cf. [FLEXISIP-367](https://linphone.atlassian.net/browse/FLEXISIP-367))
