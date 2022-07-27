# OpenVAS Vulnerability Test
# $Id: deb_3188.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3188-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703188");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660",
                  "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9666",
                  "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671",
                  "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9675");
  script_name("Debian Security Advisory DSA 3188-1 (freetype - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-15 00:00:00 +0100 (Sun, 15 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3188.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"freetype on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 2.4.9-1.1+deb7u1.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 2.5.2-3.

For the unstable distribution (sid), these problems have been fixed in
version 2.5.2-3.

We recommend that you upgrade your freetype packages.");
  script_tag(name:"summary", value:"Mateusz Jurczyk discovered multiple
vulnerabilities in Freetype. Opening malformed fonts may result in denial of
service or the execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.4.9-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreetype6:amd64", ver:"2.4.9-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreetype6:i386", ver:"2.4.9-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.4.9-1.1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}