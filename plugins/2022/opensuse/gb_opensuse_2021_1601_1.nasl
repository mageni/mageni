# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854392");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:34:33 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for log4j (openSUSE-SU-2021:1601-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1601-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YLSFAYMV5DOWQ3EO5252SX7QTCHNCWGK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'log4j'
  package(s) announced via the openSUSE-SU-2021:1601-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for log4j fixes the following issue:

  - Previously published fixes for log4jshell turned out to be incomplete.
       Upstream has followed up on the original patch for CVE-2021-44228 with
       several additional changes (LOG4J2-3198, LOG4J2-3201, LOG4J2-3208, and
       LOG4J2-3211) that are included in this update. Since the totality of
       those patches is pretty much equivalent to an update to the latest
       version of log4j, we did update the package's tarball from version
       2.13.0 to 2.16.0 instead of trying to apply those patches to the old
       version. This change brings in a new dependency on 'jakarta-servlet' and
       a version update of 'disruptor'. [bsc#1193743, CVE-2021-45046]
  This update was imported from SUSE:SLE-15-SP2:Update.");

  script_tag(name:"affected", value:"'log4j' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"disruptor", rpm:"disruptor~3.4.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"disruptor-javadoc", rpm:"disruptor-javadoc~3.4.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jakarta-servlet", rpm:"jakarta-servlet~5.0.0~lp152.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jakarta-servlet-javadoc", rpm:"jakarta-servlet-javadoc~5.0.0~lp152.2.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j", rpm:"log4j~2.16.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-javadoc", rpm:"log4j-javadoc~2.16.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-jcl", rpm:"log4j-jcl~2.16.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-slf4j", rpm:"log4j-slf4j~2.16.0~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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