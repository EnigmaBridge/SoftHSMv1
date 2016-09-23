# Building a new RPM

Using the spec file we can build a new RPMs from the SoftHSMv1 sources.
(source RPM and spec file was is taken from the original SoftHSM repository)

In order to modify the code / patch it / build a new RPM follow the steps below.

## rpmbuild installation & environment setup

* Do not build with `rpmbuild` under root, its believed to be dangerous [rpmbuild-install].

```bash
sudo yum install rpm-build
sudo yum install redhat-rpm-config 
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
```

## Unpacking SRPM

More information on rebuilding RPMs [rebuild-rpm]: 

```bash
rpmbuild --rebuild ~/softhsm-eb-1.3.7-2.el7.src.rpm
rpm -i ~/softhsm-eb-1.3.7-2.el7.src.rpm
```

## Modifications

* `~/rpmbuild/SOURCES/softhsm-eb-1.3.7.tar.gz`
* `~/rpmbuild/SPECS/softhsm.spec`
* Tar name has to equal to `%{name}-%{version}.tar.gz` (expand vars from the spec)

One way to change sources is simply patching - described also in [rebuild-rpm], [rebuild-rpm2]. 

The other, much simpler way is to change the tar file:

* unpack the tar file
* do the changes to the sources
* if changing the version - rename the directory
* make tar again

```bash
cd ~/rpmbuild/SOURCES
tar -xzvf softhsm-eb-1.3.7.tar.gz
cd softhsm-eb-1.3.7

# some changes here
cd .. 

# optional version change
mv softhsm-eb-1.3.8
tar -czvf softhsm-eb-1.3.8.tar.gz softhsm-eb-1.3.8/
```

Note: if you are changing the version, do the changes also in spec file.
Do not forget also to change $Release var. 

## Rebuilding

For the rebuilding from sources you may need to install some dependencies. 
Mainly sqlite-devel and botan-devel. Botan can be found in the EPEL repository.

```bash
sudo yum install make gcc g++ automake autoconf sqlite-devel botan-devel

cd ~/rpmbuild/SPECS
rpmbuild -ba softhsm.spec
```

The results are:

```
~/rpmbuild/RPMS/x86_64/softhsm-eb-1.3.7-2.el7.x86_64.rpm
~/rpmbuild/RPMS/x86_64/softhsm-eb-devel-1.3.7-2.el7.x86_64.rpm
~/rpmbuild/RPMS/x86_64/softhsm-eb-debuginfo-1.3.7-2.el7.x86_64.rpm
~/rpmbuild/SRPMS/softhsm-eb-1.3.7-2.el7.src.rpm
```


[rpmbuild-install]: https://wiki.centos.org/HowTos/SetupRpmBuildEnvironment
[rebuild-rpm]: https://wiki.centos.org/HowTos/RebuildSRPM
[rebuild-rpm2]: http://bradthemad.org/tech/notes/patching_rpms.php
