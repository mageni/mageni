###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 3946-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703946");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2017-11423", "CVE-2017-6419");
  script_name("Debian Security Advisory DSA 3946-1 (libmspack - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-08-18 00:00:00 +0200 (Fri, 18 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3946.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"libmspack on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 0.5-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 0.5-1+deb9u1.

We recommend that you upgrade your libmspack packages.");
  script_tag(name:"summary", value:"It was discovered that libsmpack, a library used to handle Microsoft
compression formats, did not properly validate its input. A remote
attacker could craft malicious CAB or CHM files and use this flaw to
cause a denial of service via application crash, or potentially
execute arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmspack-dbg", ver:"0.5-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack-dev", ver:"0.5-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack-doc", ver:"0.5-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack0", ver:"0.5-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack-dbg", ver:"0.5-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack-dev", ver:"0.5-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack-doc", ver:"0.5-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmspack0", ver:"0.5-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}