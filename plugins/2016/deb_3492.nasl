# OpenVAS Vulnerability Test
# $Id: deb_3492.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3492-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703492");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-8688");
  script_name("Debian Security Advisory DSA 3492-1 (gajim - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-08 12:37:58 +0530 (Tue, 08 Mar 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3492.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9|7)");
  script_tag(name:"affected", value:"gajim on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), this problem has been fixed
in version 0.15.1-4.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 0.16-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 0.16.5-0.1.

For the unstable distribution (sid), this problem has been fixed in
version 0.16.5-0.1.

We recommend that you upgrade your gajim packages.");
  script_tag(name:"summary", value:"Daniel Gultsch discovered a vulnerability in Gajim, an XMPP/jabber
client. Gajim didn't verify the origin of roster update, allowing an
attacker to spoof them and potentially allowing her to intercept messages.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gajim", ver:"0.16-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gajim", ver:"0.16.5-0.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gajim", ver:"0.15.1-4.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}