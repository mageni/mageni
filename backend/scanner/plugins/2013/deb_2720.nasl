# OpenVAS Vulnerability Test
# $Id: deb_2720.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2720-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892720");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-1677", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1685", "CVE-2013-1684", "CVE-2013-1694", "CVE-2013-1678", "CVE-2013-1686", "CVE-2013-1676", "CVE-2013-1690", "CVE-2013-0795", "CVE-2013-0801", "CVE-2013-1681", "CVE-2013-1679", "CVE-2013-1687", "CVE-2013-1697", "CVE-2013-1693", "CVE-2013-1682", "CVE-2013-1692", "CVE-2013-1680", "CVE-2013-1670");
  script_name("Debian Security Advisory DSA 2720-1 (icedove - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-07-06 00:00:00 +0200 (Sat, 06 Jul 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2720.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"icedove on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 17.0.7-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 17.0.7-1.

We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client. Multiple memory safety
errors, use-after-free vulnerabilities, missing permission checks, incorrect
memory handling and other implementation errors may lead to the execution
of arbitrary code, privilege escalation, information disclosure or
cross-site request forgery.

As already announced for Iceweasel: we're changing the approach for
security updates for Icedove in stable-security: instead of
backporting security fixes, we now provide releases based on the
Extended Support Release branch. As such, this update introduces
packages based on Thunderbird 17 and at some point in the future we
will switch to the next ESR branch once ESR 17 has reached it's end
of life.

Some Icedove extensions currently packaged in the Debian archive are
not compatible with the new browser engine.

An updated and compatible version of Enigmail is included with this
update.

The Icedove version in the oldstable distribution (squeeze) is no
longer supported with full security updates. However, it should be
noted that almost all security issues in Icedove stem from the
included browser engine. These security problems only affect Icedove
if scripting and HTML mails are enabled. If there are security issues
specific to Icedove (e.g. a hypothetical buffer overflow in the IMAP
implementation) we'll make an effort to backport such fixes to oldstable.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"calendar-timezones", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceowl-extension", ver:"17.0.7-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}