# OpenVAS Vulnerability Test
# $Id: deb_2166_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2166-1 (chromium-browser)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.69003");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0777", "CVE-2011-0778", "CVE-2011-0783", "CVE-2011-0983", "CVE-2011-0981", "CVE-2011-0984", "CVE-2011-0985");
  script_name("Debian Security Advisory DSA 2166-1 (chromium-browser)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202166-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Chromium browser.
The Common Vulnerabilities and Exposures project identifies the
following problems:


CVE-2011-0777

Use-after-free vulnerability in Google Chrome before 9.0.597.84 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via vectors related to image loading


CVE-2011-0778

Google Chrome before 9.0.597.84 does not properly restrict drag and drop
operations, which might allow remote attackers to bypass the Same Origin
Policy via unspecified vectors


CVE-2011-0783

Unspecified vulnerability in Google Chrome before 9.0.597.84 allows
user-assisted remote attackers to cause a denial of service
(application crash) via vectors involving a bad volume setting.


CVE-2011-0983

Google Chrome before 9.0.597.94 does not properly handle anonymous blocks,
which allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors that lead to a stale pointer.


CVE-2011-0981

Google Chrome before 9.0.597.94 does not properly perform event handling for
animations, which allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors that lead to a
stale pointer.


CVE-2011-0984

Google Chrome before 9.0.597.94 does not properly handle plug-ins, which
allows remote attackers to cause a denial of service (out-of-bounds read)
via unspecified vectors


CVE-2011-0985

Google Chrome before 9.0.597.94 does not properly perform process termination
upon memory exhaustion, which has unspecified impact and remote attack vectors.



For the stable distribution (squeeze), these problems have been fixed
in version 6.0.472.63~r59945-5+squeeze2

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed
in version 9.0.597.98~r74359-1");

  script_tag(name:"solution", value:"We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to chromium-browser
announced via advisory DSA 2166-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromium-browser", ver:"6.0.472.63~r59945-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"6.0.472.63~r59945-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"6.0.472.63~r59945-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"6.0.472.63~r59945-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}