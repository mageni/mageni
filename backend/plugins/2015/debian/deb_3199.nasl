# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3199-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703199");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2015-0252");
  script_name("Debian Security Advisory DSA 3199-1 (xerces-c - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2015-03-20 00:00:00 +0100 (Fri, 20 Mar 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3199.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"xerces-c on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
this problem has been fixed in version 3.1.1-3+deb7u1.

We recommend that you upgrade your xerces-c packages.");
  script_tag(name:"summary", value:"Anton Rager and Jonathan Brossard from
the Salesforce.com Product Security Team and Ben Laurie of Google discovered a
denial of service vulnerability in xerces-c, a validating XML parser library for
C++. The parser mishandles certain kinds of malformed input documents, resulting
in a segmentation fault during a parse operation. An unauthenticated
attacker could use this flaw to cause an application using the
xerces-c library to crash.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxerces-c-dev", ver:"3.1.1-3+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxerces-c-doc", ver:"3.1.1-3+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxerces-c-samples", ver:"3.1.1-3+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxerces-c3.1:amd64", ver:"3.1.1-3+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxerces-c3.1:i386", ver:"3.1.1-3+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}