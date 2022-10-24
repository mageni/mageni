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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0377");
  script_cve_id("CVE-2022-2879", "CVE-2022-2889", "CVE-2022-41715");
  script_tag(name:"creation_date", value:"2022-10-19 04:46:32 +0000 (Wed, 19 Oct 2022)");
  script_version("2022-10-19T04:46:32+0000");
  script_tag(name:"last_modification", value:"2022-10-19 04:46:32 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 18:45:00 +0000 (Fri, 19 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0377)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0377");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0377.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30964");
  script_xref(name:"URL", value:"https://groups.google.com/g/golang-announce/c/xtuG5faxtaU");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SWGSHGPO6S5363G5FSISXYXICE3YJRKU/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/THKJHFMX4DAZXJ5MFPN3BNHZDN7BW5RI/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2022-0377 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"regexp/syntax: limit memory used by parsing regexps (CVE-2022-41715)
archive/tar: unbounded memory consumption when reading headers
(CVE-2022-2879)
net/http/httputil: ReverseProxy should not forward unparseable query
parameters (CVE-2022-2880)");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-race", rpm:"golang-race~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.18.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.18.7~1.mga8", rls:"MAGEIA8"))) {
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
