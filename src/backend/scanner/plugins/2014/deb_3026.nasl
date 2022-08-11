# OpenVAS Vulnerability Test
# $Id: deb_3026.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3026-1 using nvtgen 1.0
# Script version: 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703026");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");
  script_name("Debian Security Advisory DSA 3026-1 (dbus - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-16 00:00:00 +0200 (Tue, 16 Sep 2014)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3026.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"dbus on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 1.6.8-1+deb7u4.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.8-1.

We recommend that you upgrade your dbus packages.");
  script_tag(name:"summary", value:"Alban Crequy and Simon McVittie discovered several vulnerabilities in
the D-Bus message daemon.

CVE-2014-3635
On 64-bit platforms, file descriptor passing could be abused by
local users to cause heap corruption in dbus-daemon,
leading to a crash, or potentially to arbitrary code execution.

CVE-2014-3636
A denial-of-service vulnerability in dbus-daemon allowed local
attackers to prevent new connections to dbus-daemon, or disconnect
existing clients, by exhausting descriptor limits.

CVE-2014-3637
Malicious local users could create D-Bus connections to
dbus-daemon which could not be terminated by killing the
participating processes, resulting in a denial-of-service
vulnerability.

CVE-2014-3638
dbus-daemon suffered from a denial-of-service vulnerability in the
code which tracks which messages expect a reply, allowing local
attackers to reduce the performance of dbus-daemon.

CVE-2014-3639
dbus-daemon did not properly reject malicious connections from
local users, resulting in a denial-of-service vulnerability.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dbus", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-1-dbg", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.6.8-1+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}