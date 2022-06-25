# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852324");
  script_version("2019-04-05T06:55:01+0000");
  script_cve_id("CVE-2019-6454");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-04-05 06:55:01 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-28 04:08:24 +0100 (Thu, 28 Feb 2019)");
  script_name("SuSE Update for systemd openSUSE-SU-2019:0255-1 (systemd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:0255_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  - CVE-2019-6454: Overlong DBUS messages could be used to crash systemd
  (bsc#1125352)

  - units: make sure initrd-cleanup.service terminates before switching to
  rootfs (bsc#1123333)

  - logind: fix bad error propagation

  - login: log session state 'closing' (as well as New/Removed)

  - logind: fix borked r check

  - login: don't remove all devices from PID1 when only one was removed

  - login: we only allow opening character devices

  - login: correct comment in session_device_free()

  - login: remember that fds received from PID1 need to be removed eventually

  - login: fix FDNAME in call to sd_pid_notify_with_fds()

  - logind: fd 0 is a valid fd

  - logind: rework sd_eviocrevoke()

  - logind: check file is device node before using .st_rdev

  - logind: use the new FDSTOREREMOVE=1 sd_notify() message (bsc#1124153)

  - core: add a new sd_notify() message for removing fds from the FD store
  again

  - logind: make sure we don't trip up on half-initialized session devices
  (bsc#1123727)

  - fd-util: accept that kcmp might fail with EPERM/EACCES

  - core: Fix use after free case in load_from_path() (bsc#1121563)

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external tools (#6607)
  (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started after exiting from
  rescue or emergency mode

  - core: free lines after reading them (bsc#1123892)

  - sd-bus: if we receive an invalid dbus message, ignore and proceed

  - automount: don't pass non-blocking pipe to kernel.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-255=1");

  script_tag(name:"affected", value:"systemd on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini", rpm:"libsystemd0-mini~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo", rpm:"libsystemd0-mini-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini-devel", rpm:"libudev-mini-devel~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1", rpm:"libudev-mini1~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-debuginfo", rpm:"libudev-mini1-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo", rpm:"nss-myhostname-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-debuginfo", rpm:"nss-mymachines-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-systemd", rpm:"nss-systemd~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-systemd-debuginfo", rpm:"nss-systemd-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-logger", rpm:"systemd-logger~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini", rpm:"systemd-mini~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-container-mini", rpm:"systemd-mini-container-mini~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-container-mini-debuginfo", rpm:"systemd-mini-container-mini-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-coredump-mini", rpm:"systemd-mini-coredump-mini~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-coredump-mini-debuginfo", rpm:"systemd-mini-coredump-mini-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debuginfo", rpm:"systemd-mini-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debugsource", rpm:"systemd-mini-debugsource~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-devel", rpm:"systemd-mini-devel~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-sysvinit", rpm:"systemd-mini-sysvinit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev", rpm:"udev~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini", rpm:"udev-mini~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-debuginfo", rpm:"udev-mini-debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-bash-completion", rpm:"systemd-mini-bash-completion~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~debuginfo~234~lp150.20.15.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
