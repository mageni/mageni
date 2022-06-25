# OpenVAS Vulnerability Test
# $Id: deb_2124_1.nasl 8440 2018-01-17 07:58:46Z teissa $
# Description: Auto-generated from advisory DSA 2124-1 (xulrunner)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_insight = "Several vulnerabilities have been discovered in Xulrunner, the
component that provides the core functionality of Iceweasel, Debian's
variant of Mozilla's browser technology.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2010-3765
Xulrunner allows remote attackers to execute arbitrary code
via vectors related to nsCSSFrameConstructor::ContentAppended,
the appendChild method, incorrect index tracking, and the
creation of multiple frames, which triggers memory corruption.

CVE-2010-3174
CVE-2010-3176
Multiple unspecified vulnerabilities in the browser engine in
Xulrunner allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.

CVE-2010-3177
Multiple cross-site scripting (XSS) vulnerabilities in the
Gopher parser in Xulrunner allow remote attackers to inject
arbitrary web script or HTML via a crafted name of a (1) file
or (2) directory on a Gopher server.

CVE-2010-3178
Xulrunner does not properly handle certain modal calls made by
javascript: URLs in circumstances related to opening a new
window and performing cross-domain navigation, which allows
remote attackers to bypass the Same Origin Policy via a
crafted HTML document.

CVE-2010-3179
Stack-based buffer overflow in the text-rendering
functionality in Xulrunner allows remote attackers to execute
arbitrary code or cause a denial of service (memory corruption
and application crash) via a long argument to the
document.write method.

CVE-2010-3180
Use-after-free vulnerability in the nsBarProp function in
Xulrunner allows remote attackers to execute arbitrary code by
accessing the locationbar property of a closed window.

CVE-2010-3183
The LookupGetterOrSetter function in Xulrunner does not
properly support window.__lookupGetter__ function calls that
lack arguments, which allows remote attackers to execute
arbitrary code or cause a denial of service (incorrect pointer
dereference and application crash) via a crafted HTML
document.

In addition, this security update includes corrections for regressions
caused by the fixes for CVE-2010-0654 and CVE-2010-2769 in DSA-2075-1
and DSA-2106-1.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-6.

For the unstable distribution (sid) and the upcoming stable
distribution (squeeze), these problems have been fixed in version
3.5.15-1 of the iceweasel package.

We recommend that you upgrade your Xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 2124-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202124-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313495");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-11-17 03:33:48 +0100 (Wed, 17 Nov 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-3765", "CVE-2010-3174", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3183", "CVE-2010-0654", "CVE-2010-2769");
 script_name("Debian Security Advisory DSA 2124-1 (xulrunner)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-6", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
