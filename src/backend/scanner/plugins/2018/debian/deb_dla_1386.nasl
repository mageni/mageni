###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1386.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1386-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891386");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-7866", "CVE-2018-7873", "CVE-2018-7876", "CVE-2018-9009", "CVE-2018-9132");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1386-1] ming security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-05-28 00:00:00 +0200 (Mon, 28 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"ming on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1:0.4.4-1.1+deb7u9.

We recommend that you upgrade your ming packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Ming:

CVE-2018-7866

NULL pointer dereference in the newVar3 function (util/decompile.c).
Remote attackers might leverage this vulnerability to cause a denial
of service via a crafted swf file.

CVE-2018-7873

Heap-based buffer overflow vulnerability in the getString function
(util/decompile.c). Remote attackers might leverage this vulnerability
to cause a denial of service via a crafted swf file.

CVE-2018-7876

Integer overflow and resulting memory exhaustion in the
parseSWF_ACTIONRECORD function (util/parser.c). Remote attackers might
leverage this vulnerability to cause a denial of service via a crafted
swf file.

CVE-2018-9009

Various heap-based buffer overflow vulnerabilities in util/decompiler.c.
Remote attackers might leverage this vulnerability to cause a denial of
service via a crafted swf file.

CVE-2018-9132

NULL pointer dereference in the getInt function (util/decompile.c).
Remote attackers might leverage this vulnerability to cause a denial
of service via a crafted swf file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libming-dev", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libming-util", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libming1", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libswf-perl", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ming-fonts-dejavu", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ming-fonts-opensymbol", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php5-ming", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-ming", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}