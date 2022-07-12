# OpenVAS Vulnerability Test
# $Id: deb_2859.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2859-1 using nvtgen 1.0
# Script version: 1.2
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.702859");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_name("Debian Security Advisory DSA 2859-1 (pidgin - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-10 00:00:00 +0100 (Mon, 10 Feb 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2859.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"pidgin on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), no direct backport is provided.
A fixed package will be provided through backports.debian.org shortly.

For the stable distribution (wheezy), these problems have been fixed in
version 2.10.9-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.10.9-1.

We recommend that you upgrade your pidgin packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Pidgin, a multi-protocol
instant messaging client:

CVE-2013-6477
Jaime Breva Ribes discovered that a remote XMPP user can trigger a
crash by sending a message with a timestamp in the distant future.

CVE-2013-6478
Pidgin could be crashed through overly wide tooltip windows.

CVE-2013-6479Jacob Appelbaum discovered that a malicious server or a man in the
middle
could send a malformed HTTP header resulting in denial of
service.

CVE-2013-6481
Daniel Atallah discovered that Pidgin could be crashed through
malformed Yahoo! P2P messages.

CVE-2013-6482
Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
could be crashed through malformed MSN messages.

CVE-2013-6483
Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
could be crashed through malformed XMPP messages.

CVE-2013-6484
It was discovered that incorrect error handling when reading the
response from a STUN server could result in a crash.

CVE-2013-6485
Matt Jones discovered a buffer overflow in the parsing of malformed
HTTP responses.

CVE-2013-6487
Yves Younan and Ryan Pentney discovered a buffer overflow when parsing
Gadu-Gadu messages.

CVE-2013-6489
Yves Younan and Pawel Janic discovered an integer overflow when parsing
MXit emoticons.

CVE-2013-6490
Yves Younan discovered a buffer overflow when parsing SIMPLE headers.

CVE-2014-0020
Daniel Atallah discovered that Pidgin could be crashed via malformed
IRC arguments.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"finch", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"finch-dev", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.10.9-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}