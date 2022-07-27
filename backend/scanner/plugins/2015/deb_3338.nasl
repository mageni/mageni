# OpenVAS Vulnerability Test
# $Id: deb_3338.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3338-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703338");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-5963", "CVE-2015-5964");
  script_name("Debian Security Advisory DSA 3338-1 (python-django - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-18 00:00:00 +0200 (Tue, 18 Aug 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3338.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 1.4.5-1+deb7u13.

For the stable distribution (jessie), these problems have been fixed in
version 1.7.7-1+deb8u2.

For the unstable distribution (sid), these problems will be fixed
shortly.

We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"Lin Hua Cheng discovered that a session could be created when anonymously
accessing the django.contrib.auth.views.logout view. This could allow
remote attackers to saturate the session store or cause other users'
session records to be evicted.

Additionally the contrib.sessions.backends.base.SessionBase.flush() and
cache_db.SessionStore.flush() methods have been modified to avoid
creating a new empty session as well.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django", ver:"1.7.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-django", ver:"1.7.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}