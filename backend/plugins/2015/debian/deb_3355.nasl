# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3355-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703355");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2015-5198", "CVE-2015-5199", "CVE-2015-5200");
  script_name("Debian Security Advisory DSA 3355-1 (libvdpau - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2015-09-10 00:00:00 +0200 (Thu, 10 Sep 2015)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3355.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libvdpau on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution
(wheezy), these problems have been fixed in version 0.4.1-7+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 0.8-3+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1.1.1-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.1-1.

We recommend that you upgrade your libvdpau packages.");
  script_tag(name:"summary", value:"Florian Weimer of Red Hat Product
Security discovered that libvdpau, the VDPAU wrapper library, did not properly
validate environment variables, allowing local attackers to gain additional
privileges.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libvdpau-dev:amd64", ver:"0.4.1-7+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvdpau-dev:i386", ver:"0.4.1-7+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvdpau-doc", ver:"0.4.1-7+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvdpau1:amd64", ver:"0.4.1-7+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvdpau1:i386", ver:"0.4.1-7+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}