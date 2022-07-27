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
  script_oid("1.3.6.1.4.1.25623.1.0.892431");
  script_version("2020-11-05T04:00:12+0000");
  script_cve_id("CVE-2019-13224", "CVE-2019-16163", "CVE-2019-19012", "CVE-2019-19203", "CVE-2019-19204", "CVE-2019-19246", "CVE-2020-26159");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-05 11:06:14 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-05 04:00:12 +0000 (Thu, 05 Nov 2020)");
  script_name("Debian LTS: Security Advisory for libonig (DLA-2431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2431-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/931878");
  script_xref(name:"URL", value:"https://bugs.debian.org/939988");
  script_xref(name:"URL", value:"https://bugs.debian.org/944959");
  script_xref(name:"URL", value:"https://bugs.debian.org/945312");
  script_xref(name:"URL", value:"https://bugs.debian.org/945313");
  script_xref(name:"URL", value:"https://bugs.debian.org/946344");
  script_xref(name:"URL", value:"https://bugs.debian.org/972113");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libonig'
  package(s) announced via the DLA-2431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Oniguruma regular
expressions library, notably used in PHP mbstring.

CVE-2019-13224

A use-after-free in onig_new_deluxe() in regext.c allows
attackers to potentially cause information disclosure, denial of
service, or possibly code execution by providing a crafted regular
expression. The attacker provides a pair of a regex pattern and a
string, with a multi-byte encoding that gets handled by
onig_new_deluxe().

CVE-2019-16163

Oniguruma allows Stack Exhaustion in regcomp.c because of recursion
in regparse.c.

CVE-2019-19012

An integer overflow in the search_in_range function in regexec.c in
Onigurama leads to an out-of-bounds read, in which the offset of
this read is under the control of an attacker. (This only affects
the 32-bit compiled version). Remote attackers can cause a
denial-of-service or information disclosure, or possibly have
unspecified other impact, via a crafted regular expression.

CVE-2019-19203

An issue was discovered in Oniguruma. In the function
gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is
dereferenced without checking if it passed the end of the matched
string. This leads to a heap-based buffer over-read.

CVE-2019-19204

An issue was discovered in Oniguruma. In the function
fetch_interval_quantifier (formerly known as fetch_range_quantifier)
in regparse.c, PFETCH is called without checking PEND. This leads to
a heap-based buffer over-read.

CVE-2019-19246

Oniguruma has a heap-based buffer over-read in str_lower_case_match
in regexec.c.

CVE-2020-26159

In Oniguruma an attacker able to supply a regular expression for
compilation may be able to overflow a buffer by one byte in
concat_opt_exact_str in src/regcomp.c");

  script_tag(name:"affected", value:"'libonig' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
6.1.3-2+deb9u1.

We recommend that you upgrade your libonig packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libonig-dev", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libonig4", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libonig4-dbg", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
