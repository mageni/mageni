# OpenVAS Vulnerability Test
# $Id: deb_2934.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2934-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702934");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474", "CVE-2014-1418", "CVE-2014-3730");
  script_name("Debian Security Advisory DSA 2934-1 (python-django - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-19 00:00:00 +0200 (Mon, 19 May 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2934.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 1.2.3-3+squeeze10.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.5-1+deb7u7.

For the testing distribution (jessie), these problems have been fixed in
version 1.6.5-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.5-1.

We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Django, a high-level Python
web development framework. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2014-0472
Benjamin Bach discovered that Django incorrectly handled dotted
Python paths when using the reverse() URL resolver function. An
attacker able to request a specially crafted view from a Django
application could use this issue to cause Django to import arbitrary
modules from the Python path, resulting in possible code execution.

CVE-2014-0473
Paul McMillan discovered that Django incorrectly cached certain
pages that contained CSRF cookies. A remote attacker could use this
flaw to acquire the CSRF token of a different user and bypass
intended CSRF protections in a Django application.

CVE-2014-0474
Michael Koziarski discovered that certain Django model field classes
did not properly perform type conversion on their arguments, which
allows remote attackers to obtain unexpected results.

CVE-2014-1418
Michael Nelson, Natalia Bidart and James Westby discovered that
cached data in Django could be served to a different session, or to
a user with no session at all. An attacker may use this to retrieve
private data or poison caches.

CVE-2014-3730
Peter Kuma and Gavin Wahl discovered that Django incorrectly
validated certain malformed URLs from user input. An attacker may
use this to cause unexpected redirects.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze10", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze10", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}