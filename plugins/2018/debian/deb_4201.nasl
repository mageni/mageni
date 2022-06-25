###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4201.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4201-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704201");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-10471", "CVE-2018-10472", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-8897");
  script_name("Debian Security Advisory DSA 4201-1 (xen - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-05-15 00:00:00 +0200 (Tue, 15 May 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4201.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its
security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2018-8897
Andy Lutomirski and Nick Peterson discovered that incorrect handling
of debug exceptions could result in privilege escalation.

CVE-2018-10471
An error was discovered in the mitigations against Meltdown which
could result in denial of service.

CVE-2018-10472
Anthony Perard discovered that incorrect parsing of CDROM images
can result in information disclosure.

CVE-2018-10981
Jan Beulich discovered that malformed device models could result
in denial of service.

CVE-2018-10982
Roger Pau Monne discovered that incorrect handling of high precision
event timers could result in denial of service and potentially
privilege escalation.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
# nb: Note that the initial DSA-4201-1 is stating that "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6" is fixing this which is currently wrong.
if((res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}