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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0029");
  script_cve_id("CVE-2019-13224", "CVE-2019-13225", "CVE-2019-16163", "CVE-2019-19012", "CVE-2019-19203", "CVE-2019-19204", "CVE-2019-19246");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 18:15:00 +0000 (Wed, 17 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0029");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0029.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25843");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SNL26OZSQRVLEO6JRNUVIMZTICXBNEQW/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/NWOWZZNFSAWM3BUTQNAE3PD44A6JU4KE/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2020");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2019-19203");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/NO267PLHGYZSWX3XTRPKYBKD4J3YOU5V/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oniguruma' package(s) announced via the MGASA-2020-0029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated oniguruma packages fix security vulnerabilities:

A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2
allows attackers to potentially cause information disclosure, denial
of service, or possibly code execution by providing a crafted regular
expression. The attacker provides a pair of a regex pattern and a string,
with a multi-byte encoding that gets handled by onig_new_deluxe()
(CVE-2019-13224).

A NULL Pointer Dereference in match_at() in regexec.c in Oniguruma 6.9.2
allows attackers to potentially cause denial of service by providing a
crafted regular expression (CVE-2019-13225).

Oniguruma before 6.9.3 allows Stack Exhaustion in regcomp.c because of
recursion in regparse.c (CVE-2019-16163).

An integer overflow in the search_in_range function in regexec.c leads to
an out-of-bounds read, in which the offset of this read is under the
control of an attacker. (This only affects the 32-bit compiled version).
Remote attackers can cause a denial-of-service or information disclosure,
or possibly have unspecified other impact, via a crafted regular expression
(CVE-2019-19012).

An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function
gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is dereferenced
without checking if it passed the end of the matched string. This leads to
a heap-based buffer over-read (CVE-2019-19203).

In the function fetch_range_quantifier in regparse.c, PFETCH is called
without checking PEND. This leads to a heap-based buffer over-read and
lead to denial-of-service via a crafted regular expression
(CVE-2019-19204).

Heap-based buffer over-read in str_lower_case_match in regexec.c can lead
to denial-of-service via a crafted regular expression (CVE-2019-19246).");

  script_tag(name:"affected", value:"'oniguruma' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64onig5", rpm:"lib64onig5~6.9.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oniguruma-devel", rpm:"lib64oniguruma-devel~6.9.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libonig5", rpm:"libonig5~6.9.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboniguruma-devel", rpm:"liboniguruma-devel~6.9.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma", rpm:"oniguruma~6.9.4~1.mga7", rls:"MAGEIA7"))) {
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
