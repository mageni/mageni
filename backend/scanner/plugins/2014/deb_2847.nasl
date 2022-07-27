# OpenVAS Vulnerability Test
# $Id: deb_2847.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2847-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702847");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-1475", "CVE-2014-1476");
  script_name("Debian Security Advisory DSA 2847-1 (drupal7 - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-20 00:00:00 +0100 (Mon, 20 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2847.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"drupal7 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 7.14-2+deb7u2.

For the testing distribution (jessie), these problems have been fixed in
version 7.26-1.

For the unstable distribution (sid), these problems have been fixed in
version 7.26-1.

We recommend that you upgrade your drupal7 packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Drupal, a
fully-featured content management framework. The Common Vulnerabilities
and Exposures project identifies the following issues:

CVE-2014-1475
Christian Mainka and Vladislav Mladenov reported a vulnerability
in the OpenID module that allows a malicious user to log in as
other users on the site, including administrators, and hijack
their accounts.

CVE-2014-1476
Matt Vance and Damien Tournoud reported an access bypass
vulnerability in the taxonomy module. Under certain circumstances,
unpublished content can appear on listing pages provided by the
taxonomy module and will be visible to users who should not have
permission to see it.

These fixes require extra updates to the database which can be done from
the administration pages. Furthermore this update introduces a new
security hardening element for the form API. Please refer to the
upstream advisory at drupal.org/SA-CORE-2014-001
for further
information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}