# OpenVAS Vulnerability Test
# $Id: deb_3373.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3373-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703373");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-4716", "CVE-2015-4717", "CVE-2015-4718", "CVE-2015-5953",
                  "CVE-2015-5954", "CVE-2015-6500", "CVE-2015-6670", "CVE-2015-7699");
  script_name("Debian Security Advisory DSA 3373-1 (owncloud - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-18 00:00:00 +0200 (Sun, 18 Oct 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3373.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"owncloud on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 7.0.4+dfsg-4~deb8u3.

For the testing distribution (stretch), these problems have been fixed
in version 7.0.10~dfsg-2 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in
version 7.0.10~dfsg-2 or earlier versions.

We recommend that you upgrade your owncloud packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered
in ownCloud, a cloud storage web service for files, music, contacts, calendars and
many more. These flaws may lead to the execution of arbitrary code, authorization
bypass, information disclosure, cross-site scripting or denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"owncloud", ver:"7.0.4+dfsg-4~deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}