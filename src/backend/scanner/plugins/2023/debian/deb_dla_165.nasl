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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.165");
  script_cve_id("CVE-2011-5320", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480", "CVE-2012-4412", "CVE-2012-4424", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4357", "CVE-2013-4458", "CVE-2013-4788", "CVE-2013-7423", "CVE-2013-7424", "CVE-2014-4043", "CVE-2015-1472", "CVE-2015-1473");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:31:00 +0000 (Tue, 14 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-165");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DLA-165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in eglibc, Debian's version of the GNU C library.

#553206, CVE-2015-1472, CVE-2015-1473 The scanf family of functions do not properly limit stack allocation, which allows context-dependent attackers to cause a denial of service (crash) or possibly execute arbitrary code. CVE-2012-3405 The printf family of functions do not properly calculate a buffer length, which allows context-dependent attackers to bypass the FORTIFY_SOURCE format-string protection mechanism and cause a denial of service. CVE-2012-3406 The printf family of functions do not properly limit stack allocation, which allows context-dependent attackers to bypass the FORTIFY_SOURCE format-string protection mechanism and cause a denial of service (crash) or possibly execute arbitrary code via a crafted format string. CVE-2012-3480 Multiple integer overflows in the strtod, strtof, strtold, strtod_l, and other related functions allow local users to cause a denial of service (application crash) and possibly execute arbitrary code via a long string, which triggers a stack-based buffer overflow. CVE-2012-4412 Integer overflow in the strcoll and wcscoll functions allows context-dependent attackers to cause a denial of service (crash) or possibly execute arbitrary code via a long string, which triggers a heap-based buffer overflow. CVE-2012-4424 Stack-based buffer overflow in the strcoll and wcscoll functions allows context-dependent attackers to cause a denial of service (crash) or possibly execute arbitrary code via a long string that triggers a malloc failure and use of the alloca function. CVE-2013-0242 Buffer overflow in the extend_buffers function in the regular expression matcher allows context-dependent attackers to cause a denial of service (memory corruption and crash) via crafted multibyte characters. CVE-2013-1914, CVE-2013-4458 Stack-based buffer overflow in the getaddrinfo function allows remote attackers to cause a denial of service (crash) via a hostname or IP address that triggers a large number of domain conversion results. CVE-2013-4237 readdir_r allows context-dependent attackers to cause a denial of service (out-of-bounds write and crash) or possibly execute arbitrary code via a malicious NTFS image or CIFS service. CVE-2013-4332 Multiple integer overflows in malloc/malloc.c allow context-dependent attackers to cause a denial of service (heap corruption) via a large value to the pvalloc, valloc, posix_memalign, memalign, or aligned_alloc functions. CVE-2013-4357 The getaliasbyname, getaliasbyname_r, getaddrinfo, getservbyname, getservbyname_r, getservbyport, getservbyport_r, and glob functions do not properly limit stack allocation, which allows context-dependent attackers to cause a denial of service (crash) or possibly execute arbitrary code. CVE-2013-4788 When the GNU C library is statically linked into an executable, the PTR_MANGLE implementation does ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"eglibc-source", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glibc-doc", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-dev", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i386", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-i686", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-pic", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-prof", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-udeb", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6-xen", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dns-udeb", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-files-udeb", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales-all", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"locales", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.11.3-4+deb6u5", rls:"DEB6"))) {
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
