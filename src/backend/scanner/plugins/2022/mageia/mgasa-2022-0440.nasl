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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0440");
  script_cve_id("CVE-2021-32613", "CVE-2021-3673", "CVE-2021-4021", "CVE-2021-44974", "CVE-2021-44975", "CVE-2022-0173", "CVE-2022-0419", "CVE-2022-0476", "CVE-2022-0518", "CVE-2022-0519", "CVE-2022-0520", "CVE-2022-0521", "CVE-2022-0522", "CVE-2022-0523", "CVE-2022-0559", "CVE-2022-0676", "CVE-2022-0695", "CVE-2022-0712", "CVE-2022-0713");
  script_tag(name:"creation_date", value:"2022-11-28 04:13:48 +0000 (Mon, 28 Nov 2022)");
  script_version("2022-11-28T04:13:48+0000");
  script_tag(name:"last_modification", value:"2022-11-28 04:13:48 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-19 04:22:00 +0000 (Sat, 19 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0440)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0440");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0440.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29163");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/V2UL4V4XKSFJVNNUMFV443UJXGDBYGS4/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JIARALLVVY2362AYFSFULTZKIW6QO5R5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IQIRJ72UALGMSWH6MYPVJQQLXFGZ23RS/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/E6YBRQ3UCFWJVSOYIKPVUDASZ544TFND/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/05/25/1");
  script_xref(name:"URL", value:"https://census-labs.com/news/2022/05/24/multiple-vulnerabilities-in-radare2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2, radare2-cutter, rizin' package(s) announced via the MGASA-2022-0440 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In radare2 through 5.3.0 there is a double free vulnerability in the pyc
parse via a crafted file which can lead to DoS. (CVE-2021-32613)

A vulnerability was found in Radare2 in version 5.3.1. Improper input
validation when reading a crafted LE binary can lead to resource
exhaustion and DoS. (CVE-2021-3673)

A vulnerability was found in Radare2 in versions prior to 5.6.2, 5.6.0,
5.5.4 and 5.5.2. Mapping a huge section filled with zeros of an ELF64
binary for MIPS architecture can lead to uncontrolled resource consumption
and DoS. (CVE-2021-4021)

radareorg radare2 version 5.5.2 is vulnerable to NULL Pointer Dereference
via libr/bin/p/bin_symbols.c binary symbol parser. (CVE-2021-44974)

radareorg radare2 5.5.2 is vulnerable to Buffer Overflow via
/libr/core/anal_objc.c mach-o parser. (CVE-2021-44975)

radare2 is vulnerable to Out-of-bounds Read. (CVE-2022-0173)

NULL Pointer Dereference in GitHub repository radareorg/radare2 prior to
5.6.0. (CVE-2022-0419)

Denial of Service in GitHub repository radareorg/radare2 prior to 5.6.4.
(CVE-2022-0476)

Heap-based Buffer Overflow in GitHub repository radareorg/radare2 prior to
5.6.2. (CVE-2022-0518)

Buffer Access with Incorrect Length Value in GitHub repository
radareorg/radare2 prior to 5.6.2. (CVE-2022-0519)

Use After Free in NPM radare2.js prior to 5.6.2. (CVE-2022-0520)

Access of Memory Location After End of Buffer in GitHub repository
radareorg/radare2 prior to 5.6.2. (CVE-2022-0521)

Access of Memory Location Before Start of Buffer in NPM radare2.js prior
to 5.6.2. (CVE-2022-0522)

Expired Pointer Dereference in GitHub repository radareorg/radare2 prior
to 5.6.2. (CVE-2022-0523)

Use After Free in GitHub repository radareorg/radare2 prior to 5.6.2.
(CVE-2022-0559)

Heap-based Buffer Overflow in GitHub repository radareorg/radare2 prior to
5.6.4. (CVE-2022-0676)

Denial of Service in GitHub repository radareorg/radare2 prior to 5.6.4.
(CVE-2022-0695)

NULL Pointer Dereference in GitHub repository radareorg/radare2 prior to
5.6.4. (CVE-2022-0712)

Heap-based Buffer Overflow in GitHub repository radareorg/radare2 prior to
5.6.4. (CVE-2022-0713)");

  script_tag(name:"affected", value:"'radare2, radare2-cutter, rizin' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2-devel", rpm:"lib64radare2-devel~5.6.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2_5.6.4", rpm:"lib64radare2_5.6.4~5.6.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rizin-devel", rpm:"lib64rizin-devel~0.3.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rizin0", rpm:"lib64rizin0~0.3.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2-devel", rpm:"libradare2-devel~5.6.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2_5.6.4", rpm:"libradare2_5.6.4~5.6.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librizin-devel", rpm:"librizin-devel~0.3.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librizin0", rpm:"librizin0~0.3.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.6.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-cutter", rpm:"radare2-cutter~2.0.4~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-cutter-devel", rpm:"radare2-cutter-devel~2.0.4~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin", rpm:"rizin~0.3.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-common", rpm:"rizin-common~0.3.1~1.mga8", rls:"MAGEIA8"))) {
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
