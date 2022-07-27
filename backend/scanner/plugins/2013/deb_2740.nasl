# OpenVAS Vulnerability Test
# $Id: deb_2740.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2740-2 using nvtgen 1.0
# Script version: 2.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892740");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-6044");
  script_name("Debian Security Advisory DSA 2740-2 (python-django - cross-site scripting vulnerability)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-23 00:00:00 +0200 (Fri, 23 Aug 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2740.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze6.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.5-1+deb7u2.

For the testing distribution (jessie) and the unstable distribution
(sid), this problem has been fixed in version 1.5.2-1.

We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"Nick Brunn reported a possible cross-site scripting vulnerability in
python-django, a high-level Python web development framework.

The is_safe_url utility function used to validate that a used URL is on
the current host to avoid potentially dangerous redirects from
maliciously-constructed querystrings, worked as intended for HTTP and
HTTPS URLs, but permitted redirects to other schemes, such as
javascript:.

The is_safe_url function has been modified to properly recognize and
reject URLs which specify a scheme other than HTTP or HTTPS, to prevent
cross-site scripting attacks through redirecting to other schemes.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}