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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3363");
  script_cve_id("CVE-2019-20454", "CVE-2022-1586", "CVE-2022-1587");
  script_tag(name:"creation_date", value:"2023-03-16 04:23:59 +0000 (Thu, 16 Mar 2023)");
  script_version("2023-03-16T10:09:04+0000");
  script_tag(name:"last_modification", value:"2023-03-16 10:09:04 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 03:15:00 +0000 (Thu, 26 May 2022)");

  script_name("Debian: Security Advisory (DLA-3363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3363");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3363");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pcre2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pcre2' package(s) announced via the DLA-3363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple out-of-bounds read vulnerabilities were found in pcre2, a Perl Compatible Regular Expression library, which could result in information disclosure or denial or service.

CVE-2019-20454

Out-of-bounds read when the pattern X is JIT compiled and used to match specially crafted subjects in non-UTF mode.

CVE-2022-1586

Out-of-bounds read involving unicode property matching in JIT-compiled regular expressions. The issue occurs because the character was not fully read in case-less matching within JIT.

CVE-2022-1587

Out-of-bounds read affecting recursions in JIT-compiled regular expressions caused by duplicate data transfers.

This upload also fixes a subject buffer overread in JIT when UTF is disabled and X or R has a greater than 1 fixed quantifier. This issue was found by Yunho Kim.

For Debian 10 buster, these problems have been fixed in version 10.32-5+deb10u1.

We recommend that you upgrade your pcre2 packages.

For the detailed security status of pcre2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pcre2' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-16-0", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-32-0", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-8-0-udeb", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-8-0", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-dbg", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-dev", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre2-posix0", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcre2-utils", ver:"10.32-5+deb10u1", rls:"DEB10"))) {
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
