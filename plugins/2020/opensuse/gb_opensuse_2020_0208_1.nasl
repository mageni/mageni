# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853031");
  script_version("2020-02-14T06:25:11+0000");
  script_cve_id("CVE-2019-20386", "CVE-2020-1712");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-02-14 06:25:11 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 04:01:05 +0000 (Wed, 12 Feb 2020)");
  script_name("openSUSE: Security Advisory for systemd (openSUSE-SU-2020:0208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2020:0208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  - CVE-2020-1712 (bsc#bsc#1162108) Fix a heap use-after-free vulnerability,
  when asynchronous Polkit queries were performed while handling Dbus
  messages. A local unprivileged attacker could have abused this flaw to
  crash systemd services or potentially execute code and elevate their
  privileges, by sending specially crafted Dbus messages.

  - Use suse.pool.ntp.org server pool on SLE distros (jsc#SLE-7683)

  - libblkid: open device in nonblock mode. (bsc#1084671)

  - udev/cdrom_id: Do not open CD-rom in exclusive mode. (bsc#1154256)

  - bus_open leak sd_event_source when udevadm trigger (bsc#1161436
  CVE-2019-20386)

  - fileio: introduce read_full_virtual_file() for reading virtual files in
  sysfs, procfs (bsc#1133495 bsc#1159814)

  - fileio: initialize errno to zero before we do fread()

  - fileio: try to read one byte too much in read_full_stream()

  - logind: consider 'greeter' sessions suitable as 'display' sessions of a
  user (bsc#1158485)

  - logind: never elect a session that is stopping as display

  - journal: include kmsg lines from the systemd process which exec()d us
  (#8078)

  - udevd: don't use monitor after manager_exit()

  - udevd: capitalize log messages in on_sigchld()

  - udevd: merge conditions to decrease indentation

  - Revert 'udevd: fix crash when workers time out after exit is signal
  caught'

  - core: fragments of masked units ought not be considered for
  NeedDaemonReload (#7060) (bsc#1156482)

  - udevd: fix crash when workers time out after exit is signal caught

  - udevd: wait for workers to finish when exiting (bsc#1106383)

  - Improve bash completion support (bsc#1155207)

  * shell-completion: systemctl: do not list template units in {re, }start

  * shell-completion: systemctl: pass current word to all list_unit*

  * bash-completion: systemctl: pass current partial unit to list-unit*
  (bsc#1155207)

  * bash-completion: systemctl: use systemctl --no-pager

  * bash-completion: also suggest template unit files

  * bash-completion: systemctl: add missing options and verbs

  * bash-completion: use the first argument instead of the global variable
  (#6457)

  - networkd: VXLan Make group and remote variable separate (bsc#1156213)

  - networkd: vxlan require Remote= to be a non multicast address (#8117)
  (bsc#1156213)

  - fs-util: let's avoid unnecessary strerror()

  - fs-util: introduce inotify_add_watch_and_warn() helper

  - ask-password: improve log message when inotify limit is reached
  (bsc#1155574)

  - shared/install: failing with -ELOOP can be due to the use of an alias in
  insta ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini", rpm:"libsystemd0-mini~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo", rpm:"libsystemd0-mini-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini-devel", rpm:"libudev-mini-devel~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1", rpm:"libudev-mini1~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-debuginfo", rpm:"libudev-mini1-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo", rpm:"nss-myhostname-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-debuginfo", rpm:"nss-mymachines-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-systemd", rpm:"nss-systemd~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-systemd-debuginfo", rpm:"nss-systemd-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-logger", rpm:"systemd-logger~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini", rpm:"systemd-mini~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-container-mini", rpm:"systemd-mini-container-mini~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-container-mini-debuginfo", rpm:"systemd-mini-container-mini-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-coredump-mini", rpm:"systemd-mini-coredump-mini~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-coredump-mini-debuginfo", rpm:"systemd-mini-coredump-mini-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debuginfo", rpm:"systemd-mini-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debugsource", rpm:"systemd-mini-debugsource~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-devel", rpm:"systemd-mini-devel~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-sysvinit", rpm:"systemd-mini-sysvinit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini", rpm:"udev-mini~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-debuginfo", rpm:"udev-mini-debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-bash-completion", rpm:"systemd-mini-bash-completion~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~debuginfo~234~lp151.26.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
