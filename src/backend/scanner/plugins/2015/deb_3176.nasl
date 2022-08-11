# OpenVAS Vulnerability Test
# $Id: deb_3176.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3176-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703176");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_name("Debian Security Advisory DSA 3176-1 (request-tracker4 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-26 00:00:00 +0100 (Thu, 26 Feb 2015)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3176.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"request-tracker4 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 4.0.7-5+deb7u3.

For the unstable distribution (sid), these problems have been fixed in
version 4.2.8-3.

We recommend that you upgrade your request-tracker4 packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in Request Tracker, an extensible trouble-ticket tracking system. The
Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-9472
Christian Loos discovered a remote denial of service vulnerability,
exploitable via the email gateway and affecting any installation
which accepts mail from untrusted sources. Depending on RT's
logging configuration, a remote attacker can take advantage of
this flaw to cause CPU and excessive disk usage.

CVE-2015-1165
Christian Loos discovered an information disclosure flaw which may
reveal RSS feeds URLs, and thus ticket data.

CVE-2015-1464
It was discovered that RSS feed URLs can be leveraged to perform
session hijacking, allowing a user with the URL to log in as the
user that created the feed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"request-tracker4", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-clients", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.0.7-5+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}