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
  script_oid("1.3.6.1.4.1.25623.1.0.852429");
  script_version("2019-04-22T07:09:02+0000");
  script_cve_id("CVE-2019-3816", "CVE-2019-3833");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-22 07:09:02 +0000 (Mon, 22 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-17 02:01:19 +0000 (Wed, 17 Apr 2019)");
  script_name("openSUSE Update for openwsman openSUSE-SU-2019:1217-1 (openwsman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openwsman'
  package(s) announced via the openSUSE-SU-2019:1217_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openwsman fixes the following issues:

  Security issues fixed:

  - CVE-2019-3816: Fixed a vulnerability in openwsmand daemon which could
  lead to arbitrary file disclosure (bsc#1122623).

  - CVE-2019-3833: Fixed a vulnerability in process_connection() which could
  allow an attacker to trigger an infinite loop which leads to Denial of
  Service (bsc#1122623).

  Other issues addressed:

  - Directory listing without authentication fixed (bsc#1092206).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1217=1");

  script_tag(name:"affected", value:"'openwsman' package(s) on openSUSE Leap 42.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwsman-devel", rpm:"libwsman-devel~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman3", rpm:"libwsman3~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman3-debuginfo", rpm:"libwsman3-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman_clientpp-devel", rpm:"libwsman_clientpp-devel~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman_clientpp1", rpm:"libwsman_clientpp1~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman_clientpp1-debuginfo", rpm:"libwsman_clientpp1-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-debugsource", rpm:"openwsman-debugsource~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-java", rpm:"openwsman-java~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-perl", rpm:"openwsman-perl~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-perl-debuginfo", rpm:"openwsman-perl-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-python", rpm:"openwsman-python~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-python-debuginfo", rpm:"openwsman-python-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-ruby", rpm:"openwsman-ruby~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-ruby-debuginfo", rpm:"openwsman-ruby-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-ruby-docs", rpm:"openwsman-ruby-docs~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-server", rpm:"openwsman-server~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-server-debuginfo", rpm:"openwsman-server-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-server-plugin-ruby", rpm:"openwsman-server-plugin-ruby~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-server-plugin-ruby-debuginfo", rpm:"openwsman-server-plugin-ruby-debuginfo~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winrs", rpm:"winrs~2.6.7~4.3.1", rls:"openSUSELeap42.3"))) {
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
