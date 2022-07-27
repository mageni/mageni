# OpenVAS Vulnerability Test
# $Id: deb_3253.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3253-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703253");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2009-3555", "CVE-2012-4929", "CVE-2014-3566");
  script_name("Debian Security Advisory DSA 3253-1 (pound - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-07 00:00:00 +0200 (Thu, 07 May 2015)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3253.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"pound on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution
(wheezy), these problems have been fixed in version 2.6-2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 2.6-6+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.6-6.1.

We recommend that you upgrade your pound packages.");
  script_tag(name:"summary", value:"Pound, a HTTP reverse proxy and
load balancer, had several issues related to vulnerabilities in the Secure
Sockets Layer (SSL) protocol.

For Debian 7 (wheezy) this update adds a missing part to make it actually
possible to disable client-initiated renegotiation and disables it by default
(CVE-2009-3555).
TLS compression is disabled (CVE-2012-4929),
although this is normally already disabled by the OpenSSL system library.
Finally it adds the ability to disable the SSLv3 protocol (CVE-2014-3566)
entirely via the new DisableSSLv3
configuration directive, although it
will not disabled by default in this update. Additionally a non-security
sensitive issue in redirect encoding is
addressed.

For Debian 8 (jessie) these issues have been fixed prior to the release,
with the exception of client-initiated renegotiation (CVE-2009-3555
).
This update addresses that issue for jessie.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"pound", ver:"2.6-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}