# OpenVAS Vulnerability Test
# $Id: deb_2406_1.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2406-1 using nvtgen 1.0
# Script version: 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892406");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-0449", "CVE-2012-0442", "CVE-2011-3670", "CVE-2012-0444");
  script_name("Debian Security Advisory DSA 2406-1 (icedove - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2012/dsa-2406.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"icedove on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze7.

We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in Icedove, Debian's
variant of the Mozilla Thunderbird code base.

CVE-2011-3670Icedove does not not properly enforce the IPv6 literal address
syntax, which allows remote attackers to obtain sensitive
information by making XMLHttpRequest calls through a proxy and
reading the error messages.

CVE-2012-0442Memory corruption bugs could cause Icedove to crash or
possibly execute arbitrary code.

CVE-2012-0444Icedove does not properly initialize nsChildView data
structures, which allows remote attackers to cause a denial of
service (memory corruption and application crash) or possibly
execute arbitrary code via a crafted Ogg Vorbis file.

CVE-2012-0449Icedove allows remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via a malformed XSLT stylesheet that is
embedded in a document.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}