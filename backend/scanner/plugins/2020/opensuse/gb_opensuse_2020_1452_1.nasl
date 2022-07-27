# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853431");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19873", "CVE-2020-17507");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-19 03:00:45 +0000 (Sat, 19 Sep 2020)");
  script_name("openSUSE: Security Advisory for libqt4 (openSUSE-SU-2020:1452-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1452-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00057.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt4'
  package(s) announced via the openSUSE-SU-2020:1452-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt4 fixes the following issues:

  * Fix buffer over-read in read_xbm_body (boo#1176315, CVE-2020-17507)

  * Fix 'double free or corruption' in QXmlStreamReader (boo#1118595,
  CVE-2018-15518)

  * Fix QBmpHandler segfault on malformed BMP file boo#1118596,
  CVE-2018-19873)

  * Fix crash when parsing malformed url reference (boo#1118599,
  CVE-2018-19869)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1452=1");

  script_tag(name:"affected", value:"'libqt4' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debuginfo", rpm:"libqt4-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-debugsource", rpm:"libqt4-debugsource~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-debuginfo", rpm:"libqt4-devel-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-linguist", rpm:"libqt4-linguist~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-linguist-debuginfo", rpm:"libqt4-linguist-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-private-headers-devel", rpm:"libqt4-private-headers-devel~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-debuginfo", rpm:"libqt4-qt3support-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-debuginfo", rpm:"libqt4-sql-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-debuginfo", rpm:"libqt4-sql-sqlite-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-debuginfo", rpm:"libqt4-x11-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit-debuginfo", rpm:"libqt4-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-32bit", rpm:"libqt4-devel-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-32bit-debuginfo", rpm:"libqt4-devel-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc", rpm:"libqt4-devel-doc~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debuginfo", rpm:"libqt4-devel-doc-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-debugsource", rpm:"libqt4-devel-doc-debugsource~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit-debuginfo", rpm:"libqt4-qt3support-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit-debuginfo", rpm:"libqt4-sql-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-plugins-debugsource", rpm:"libqt4-sql-plugins-debugsource~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-postgresql", rpm:"libqt4-sql-postgresql~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-postgresql-debuginfo", rpm:"libqt4-sql-postgresql-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-32bit", rpm:"libqt4-sql-sqlite-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite-32bit-debuginfo", rpm:"libqt4-sql-sqlite-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-unixODBC", rpm:"libqt4-sql-unixODBC~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-unixODBC-debuginfo", rpm:"libqt4-sql-unixODBC-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit-debuginfo", rpm:"libqt4-x11-32bit-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools", rpm:"qt4-x11-tools~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools-debuginfo", rpm:"qt4-x11-tools-debuginfo~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel-doc-data", rpm:"libqt4-devel-doc-data~4.8.7~lp151.9.3.1", rls:"openSUSELeap15.1"))) {
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