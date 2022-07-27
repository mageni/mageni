# OpenVAS Vulnerability Test
# $Id: deb_2971.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2971-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702971");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533");
  script_name("Debian Security Advisory DSA 2971-1 (dbus - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-02 00:00:00 +0200 (Wed, 02 Jul 2014)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2971.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"dbus on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 1.6.8-1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.6-1.

We recommend that you upgrade your dbus packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in dbus, an asynchronous
inter-process communication system. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2014-3477
Alban Crequy at Collabora Ltd. discovered that dbus-daemon sends an
AccessDenied error to the service instead of a client when the
client is prohibited from accessing the service. A local attacker
could use this flaw to cause a bus-activated service that is not
currently running to attempt to start, and fail, denying other users
access to this service.

CVE-2014-3532
Alban Crequy at Collabora Ltd. discovered a bug in dbus-daemon's
support for file descriptor passing. A malicious process could force
system services or user applications to be disconnected from the
D-Bus system by sending them a message containing a file descriptor,
leading to a denial of service.

CVE-2014-3533
Alban Crequy at Collabora Ltd. and Alejandro Martínez Suárez
discovered that a malicious process could force services to be
disconnected from the D-Bus system by causing dbus-daemon to attempt
to forward invalid file descriptors to a victim process, leading to
a denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dbus", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-1-dbg", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.6.8-1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}