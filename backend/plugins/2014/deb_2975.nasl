# OpenVAS Vulnerability Test
# $Id: deb_2975.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2975-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702975");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-4995", "CVE-2013-4996", "CVE-2013-5002", "CVE-2013-5003", "CVE-2014-1879");
  script_name("Debian Security Advisory DSA 2975-1 (phpmyadmin - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-09 00:00:00 +0200 (Wed, 09 Jul 2014)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2975.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"phpmyadmin on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 4:3.4.11.1-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.2.5-1.

We recommend that you upgrade your phpmyadmin packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in phpMyAdmin, a tool to
administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2013-4995
Authenticated users could inject arbitrary web script or HTML
via a crafted SQL query.

CVE-2013-4996
Cross site scripting was possible via a crafted logo URL in
the navigation panel or a crafted entry in the Trusted Proxies list.

CVE-2013-5002
Authenticated users could inject arbitrary web script or HTML
via a crafted pageNumber value in Schema Export.

CVE-2013-5003Authenticated users could execute arbitrary SQL commands as
the phpMyAdmin control user
via the scale parameter PMD PDF
export and the pdf_page_number parameter in Schema Export.

CVE-2014-1879
Authenticated users could inject arbitrary web script or HTML
via a crafted file name in the Import function.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:3.4.11.1-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}