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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0454");
  script_cve_id("CVE-2017-6004", "CVE-2017-7186", "CVE-2017-7244", "CVE-2017-7245", "CVE-2017-7246");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-17 10:29:00 +0000 (Fri, 17 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0454");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0454.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20355");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/03/24/1");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/03/24/2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ESZV6GLV63XBXTZQOAJPOWLRIG35TEV7/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/XEYMUTVQAMYFGYH7ZE6RJD34GJMBZRMS/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre, pcre' package(s) announced via the MGASA-2017-0454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The compile_bracket_matchingpath function in pcre_jit_compile.c in PCRE
through 8.x before revision 1680 (e.g., the PHP 7.1.1 bundled version)
allows remote attackers to cause a denial of service (out-of-bounds read
and application crash) via a crafted regular expression (CVE-2017-6004).

A vulnerability was found in pcre caused by trying to find a Unicode
property for a code value greater than 0x10ffff, the Unicode maximum,
when running in non-UTF mode (where character values can be up to
0xffffffff) (CVE-2017-7186).

The _pcre32_xclass function in pcre_xclass.c in libpcre1 in PCRE 8.40
allows remote attackers to cause a denial of service (invalid memory
read) via a crafted file (CVE-2017-7244).

Stack-based buffer overflow in the pcre32_copy_substring function in
pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a
denial of service (WRITE of size 4) or possibly have unspecified other
impact via a crafted file (CVE-2017-7245).

Stack-based buffer overflow in the pcre32_copy_substring function in
pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a
denial of service (WRITE of size 268) or possibly have unspecified other
impact via a crafted file (CVE-2017-7246).");

  script_tag(name:"affected", value:"'pcre, pcre' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-devel", rpm:"lib64pcre-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre1", rpm:"lib64pcre1~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre16_0", rpm:"lib64pcre16_0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre32_0", rpm:"lib64pcre32_0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp-devel", rpm:"lib64pcrecpp-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp0", rpm:"lib64pcrecpp0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix-devel", rpm:"lib64pcreposix-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix0", rpm:"lib64pcreposix0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix1", rpm:"lib64pcreposix1~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-devel", rpm:"libpcre-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16_0", rpm:"libpcre16_0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre32_0", rpm:"libpcre32_0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp-devel", rpm:"libpcrecpp-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix-devel", rpm:"libpcreposix-devel~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix1", rpm:"libpcreposix1~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.41~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-devel", rpm:"lib64pcre-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-static-devel", rpm:"lib64pcre-static-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre1", rpm:"lib64pcre1~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre16_0", rpm:"lib64pcre16_0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre32_0", rpm:"lib64pcre32_0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp-devel", rpm:"lib64pcrecpp-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp0", rpm:"lib64pcrecpp0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix-devel", rpm:"lib64pcreposix-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix0", rpm:"lib64pcreposix0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix1", rpm:"lib64pcreposix1~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-devel", rpm:"libpcre-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-static-devel", rpm:"libpcre-static-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16_0", rpm:"libpcre16_0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre32_0", rpm:"libpcre32_0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp-devel", rpm:"libpcrecpp-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix-devel", rpm:"libpcreposix-devel~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix1", rpm:"libpcreposix1~8.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.41~1.mga6", rls:"MAGEIA6"))) {
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
