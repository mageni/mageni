# OpenVAS Vulnerability Test
# $Id: deb_3382.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3382-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703382");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-8958", "CVE-2014-9218", "CVE-2015-2206", "CVE-2015-3902",
                  "CVE-2015-3903", "CVE-2015-6830", "CVE-2015-7873");
  script_name("Debian Security Advisory DSA 3382-1 (phpmyadmin - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-28 00:00:00 +0100 (Wed, 28 Oct 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3382.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"phpmyadmin on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 4:3.4.11.1-2+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 4:4.2.12-2+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.5.1-1.

We recommend that you upgrade your phpmyadmin packages.");
  script_tag(name:"summary", value:"Several issues have been fixed
in phpMyAdmin, the web administration tool for MySQL.

CVE-2014-8958 (Wheezy only)

Multiple cross-site scripting (XSS) vulnerabilities.

CVE-2014-9218 (Wheezy only)

Denial of service (resource consumption) via a long password.

CVE-2015-2206
Risk of BREACH attack due to reflected parameter.

CVE-2015-3902
XSRF/CSRF vulnerability in phpMyAdmin setup.

CVE-2015-3903 (Jessie only)

Vulnerability allowing man-in-the-middle attack on API call to GitHub.

CVE-2015-6830 (Jessie only)

Vulnerability that allows bypassing the reCaptcha test.

CVE-2015-7873 (Jessie only)

Content spoofing vulnerability when redirecting user to an
external site.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.4.11.1-2+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.2.12-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}