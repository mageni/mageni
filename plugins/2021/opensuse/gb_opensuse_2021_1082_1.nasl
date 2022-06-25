# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.854020");
  script_version("2021-08-03T06:52:21+0000");
  script_cve_id("CVE-2021-33910");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-03 10:35:54 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-24 03:01:25 +0000 (Sat, 24 Jul 2021)");
  script_name("openSUSE: Security Advisory for systemd (openSUSE-SU-2021:1082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1082-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AAGPKC3S3ZQN25VD5T76IP4JJFCIWE4R");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2021:1082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  - CVE-2021-33910: Fixed a denial of service in systemd via
       unit_name_path_escape() (bsc#1188063)

  - Skip udev rules if &#x27 elevator=&#x27  is used (bsc#1184994)

     This update was imported from the SUSE:SLE-15:Update update project.


  Special Instructions and Notes:

     Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-234", rpm:"libsystemd0-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo-234", rpm:"libsystemd0-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini-234", rpm:"libsystemd0-mini-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo-234", rpm:"libsystemd0-mini-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel-234", rpm:"libudev-devel-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini-devel-234", rpm:"libudev-mini-devel-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-234", rpm:"libudev-mini1-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-debuginfo-234", rpm:"libudev-mini1-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-234", rpm:"libudev1-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-234", rpm:"libudev1-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-234", rpm:"nss-myhostname-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo-234", rpm:"nss-myhostname-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-234", rpm:"nss-mymachines-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-debuginfo-234", rpm:"nss-mymachines-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-systemd-234", rpm:"nss-systemd-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-systemd-debuginfo-234", rpm:"nss-systemd-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-234", rpm:"systemd-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-234", rpm:"systemd-container-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo-234", rpm:"systemd-container-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-234", rpm:"systemd-coredump-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-debuginfo-234", rpm:"systemd-coredump-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-234", rpm:"systemd-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource-234", rpm:"systemd-debugsource-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel-234", rpm:"systemd-devel-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote-234", rpm:"systemd-journal-remote-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote-debuginfo-234", rpm:"systemd-journal-remote-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-logger-234", rpm:"systemd-logger-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-234", rpm:"systemd-mini-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-container-mini-234", rpm:"systemd-mini-container-mini-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-container-mini-debuginfo-234", rpm:"systemd-mini-container-mini-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-coredump-mini-234", rpm:"systemd-mini-coredump-mini-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-coredump-mini-debuginfo-234", rpm:"systemd-mini-coredump-mini-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debuginfo-234", rpm:"systemd-mini-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debugsource-234", rpm:"systemd-mini-debugsource-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-devel-234", rpm:"systemd-mini-devel-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-sysvinit-234", rpm:"systemd-mini-sysvinit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-network-234", rpm:"systemd-network-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-network-debuginfo-234", rpm:"systemd-network-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit-234", rpm:"systemd-sysvinit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-234", rpm:"udev-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo-234", rpm:"udev-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-234", rpm:"udev-mini-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-debuginfo-234", rpm:"udev-mini-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion-234", rpm:"systemd-bash-completion-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-bash-completion-234", rpm:"systemd-mini-bash-completion-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-234", rpm:"libsystemd0-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-debuginfo-234", rpm:"libsystemd0-32bit-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel-32bit-234", rpm:"libudev-devel-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-234", rpm:"libudev1-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-debuginfo-234", rpm:"libudev1-32bit-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-32bit-234", rpm:"nss-myhostname-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-32bit-debuginfo-234", rpm:"nss-myhostname-32bit-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-32bit-234", rpm:"nss-mymachines-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-mymachines-32bit-debuginfo-234", rpm:"nss-mymachines-32bit-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-234", rpm:"systemd-32bit-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-debuginfo-234", rpm:"systemd-32bit-debuginfo-234~lp152.31.31.1", rls:"openSUSELeap15.2"))) {
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
