# OpenVAS Vulnerability Test
# $Id: deb_2188_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2188-1 (webkit)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69325");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1783", "CVE-2010-2901", "CVE-2010-4199", "CVE-2010-4040", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2010-0474", "CVE-2011-0482", "CVE-2011-0778");
  script_name("Debian Security Advisory DSA 2188-1 (webkit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202188-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in webkit, a Web content engine
library for Gtk+. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2010-1783

WebKit does not properly handle dynamic modification of a
text node, which allows remote attackers to execute arbitrary code or cause
a denial of service (memory corruption and application crash) via a
crafted HTML document.

CVE-2010-2901

The rendering implementation in WebKit allows
remote attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via unknown vectors.

CVE-2010-4199

WebKit does not properly perform a cast of an
unspecified variable during processing of an SVG use element, which allows
remote attackers to cause a denial of service or possibly have unspecified
other impact via a crafted SVG document.

CVE-2010-4040

WebKit does not properly handle animated GIF images,
which allows remote attackers to cause a denial of service (memory corruption)
or possibly have unspecified other impact via a crafted image.

CVE-2010-4492

Use-after-free vulnerability in WebKit allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG animations.

CVE-2010-4493

Use-after-free vulnerability in Webkit allows remote attackers to cause a
denial of service via vectors related to the handling of mouse dragging events

CVE-2010-4577

The CSSParser::parseFontFaceSrc function in WebCore/css/CSSParser.cpp in
WebKit does not properly parse Cascading Style Sheets (CSS) token sequences,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via a crafted local font, related to Type Confusion.

CVE-2010-4578

WebKit does not properly perform cursor handling, which allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via unknown vectors that lead to stale pointers.

CVE-2011-0482

WebKit does not properly perform a cast of an unspecified variable during
handling of anchors, which allows remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted HTML document

CVE-2011-0778

WebKit does not properly restrict drag and drop operations, which might allow
remote attackers to bypass the Same Origin Policy via unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed
in version 1.2.7-0+squeeze1

For the testing distribution (wheezy), and the unstable distribution (sid),
these problems have been fixed in version 1.2.7-1

Security support for WebKit has been discontinued for the oldstable
distribution (lenny).
The current version in oldstable is not supported by upstream anymore
and is affected by several security issues. Backporting fixes for these
and any future issues has become unfeasible and therefore we need to
drop our security support for the version in oldstable.");

  script_tag(name:"solution", value:"We recommend that you upgrade your webkit packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to webkit
announced via advisory DSA 2188-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"girl1.0-webkit-1.0", ver:"1.2.7-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.7-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwebkit-1.0-2-dbg", ver:"1.2.7-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwebkit-1.0-common", ver:"1.2.7-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.2.7-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.2.7-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}