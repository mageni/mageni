# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0145");
  script_cve_id("CVE-2023-24534", "CVE-2023-24536", "CVE-2023-24537", "CVE-2023-24538");
  script_tag(name:"creation_date", value:"2023-04-17 04:13:02 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-17 16:54:00 +0000 (Mon, 17 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0145");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0145.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31769");
  script_xref(name:"URL", value:"https://groups.google.com/g/golang-announce/c/Xdv6JL9ENs8");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-April/014420.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-April/014421.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-April/014423.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-April/014387.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2023-0145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DOS due to incorrect HTTP and MIME header parsing (CVE-2023-24534)
DOS due to incorrect Multipart form parsing (CVE-2023-24536)
Calling any of the Parse functions on Go source code which contains //line
directives with very large line numbers can cause an infinite loop due to
integer overflow. (CVE-2023-24537)
Arbitrary Javascript code execution due to failure to escape back ticks
(CVE-2023-24538)");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-race", rpm:"golang-race~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.19.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.19.8~1.mga8", rls:"MAGEIA8"))) {
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
