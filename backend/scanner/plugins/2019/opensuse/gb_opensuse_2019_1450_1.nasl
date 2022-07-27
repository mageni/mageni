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
  script_oid("1.3.6.1.4.1.25623.1.0.852518");
  script_version("2019-05-31T13:18:49+0000");
  script_cve_id("CVE-2018-6954", "CVE-2019-3842", "CVE-2019-6454");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-31 13:18:49 +0000 (Fri, 31 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-28 02:00:44 +0000 (Tue, 28 May 2019)");
  script_name("openSUSE Update for systemd openSUSE-SU-2019:1450-1 (systemd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00062.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:1450_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  Security issues fixed:

  - CVE-2018-6954: Fixed a vulnerability in the symlink handling of
  systemd-tmpfiles which allowed a local user to obtain ownership of
  arbitrary files (bsc#1080919).

  - CVE-2019-3842: Fixed a vulnerability in pam_systemd which allowed a
  local user to escalate privileges (bsc#1132348).

  - CVE-2019-6454: Fixed a denial of service caused by long dbus messages
  (bsc#1125352).

  Non-security issues fixed:

  - systemd-coredump: generate a stack trace of all core dumps (jsc#SLE-5933)

  - udevd: notify when max number value of children is reached only once per
  batch of events (bsc#1132400)

  - sd-bus: bump message queue size again (bsc#1132721)

  - core: only watch processes when it's really necessary (bsc#955942
  bsc#1128657)

  - rules: load drivers only on 'add' events (bsc#1126056)

  - sysctl: Don't pass null directive argument to '%s' (bsc#1121563)

  - Do not automatically online memory on s390x (bsc#1127557)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1450=1");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-228", rpm:"libsystemd0-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo-228", rpm:"libsystemd0-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini-228", rpm:"libsystemd0-mini-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo-228", rpm:"libsystemd0-mini-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel-228", rpm:"libudev-devel-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini-devel-228", rpm:"libudev-mini-devel-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-228", rpm:"libudev-mini1-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-debuginfo-228", rpm:"libudev-mini1-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-228", rpm:"libudev1-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-228", rpm:"libudev1-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-228", rpm:"nss-myhostname-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo-228", rpm:"nss-myhostname-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-228", rpm:"nss-mymachines-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-debuginfo-228", rpm:"nss-mymachines-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-228", rpm:"systemd-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-228", rpm:"systemd-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource-228", rpm:"systemd-debugsource-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel-228", rpm:"systemd-devel-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-logger-228", rpm:"systemd-logger-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-228", rpm:"systemd-mini-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debuginfo-228", rpm:"systemd-mini-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debugsource-228", rpm:"systemd-mini-debugsource-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-devel-228", rpm:"systemd-mini-devel-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-sysvinit-228", rpm:"systemd-mini-sysvinit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit-228", rpm:"systemd-sysvinit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-228", rpm:"udev-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo-228", rpm:"udev-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-228", rpm:"udev-mini-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-debuginfo-228", rpm:"udev-mini-debuginfo-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion-228", rpm:"systemd-bash-completion-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-bash-completion-228", rpm:"systemd-mini-bash-completion-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-228", rpm:"libsystemd0-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo-32bit-228", rpm:"libsystemd0-debuginfo-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-228", rpm:"libudev1-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-32bit-228", rpm:"libudev1-debuginfo-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-32bit-228", rpm:"nss-myhostname-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo-32bit-228", rpm:"nss-myhostname-debuginfo-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-228", rpm:"systemd-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-32bit-228", rpm:"systemd-debuginfo-32bit-228~71.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
