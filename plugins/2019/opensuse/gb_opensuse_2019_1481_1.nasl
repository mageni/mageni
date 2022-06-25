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
  script_oid("1.3.6.1.4.1.25623.1.0.852527");
  script_version("2019-06-04T07:02:10+0000");
  script_cve_id("CVE-2015-1331", "CVE-2015-1334", "CVE-2015-1335", "CVE-2017-5985", "CVE-2018-6556", "CVE-2019-5736");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-04 07:02:10 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-02 02:01:05 +0000 (Sun, 02 Jun 2019)");
  script_name("openSUSE Update for lxc, openSUSE-SU-2019:1481-1 (lxc, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc, '
  package(s) announced via the openSUSE-SU-2019:1481_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lxc, lxcfs to version 3.1.0 fixes the following issues:

  Security issues fixed:

  - CVE-2019-5736: Fixed a container breakout vulnerability (boo#1122185).

  - CVE-2018-6556: Enable setuid bit on lxc-user-nic (boo#988348).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1481=1");

  script_tag(name:"affected", value:"'lxc, ' package(s) on openSUSE Leap 42.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"lxcfs", rpm:"lxcfs~3.0.3~2.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxcfs-debuginfo", rpm:"lxcfs-debuginfo~3.0.3~2.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxcfs-debugsource", rpm:"lxcfs-debugsource~3.0.3~2.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1-debuginfo", rpm:"liblxc1-debuginfo~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-debuginfo", rpm:"lxc-debuginfo~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-debugsource", rpm:"lxc-debugsource~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_cgfs", rpm:"pam_cgfs~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_cgfs-debuginfo", rpm:"pam_cgfs-debuginfo~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-bash-completion", rpm:"lxc-bash-completion~3.1.0~24.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxcfs-hooks-lxc", rpm:"lxcfs-hooks-lxc~3.0.3~2.1", rls:"openSUSELeap42.3"))) {
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
