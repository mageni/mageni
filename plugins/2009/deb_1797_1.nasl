# OpenVAS Vulnerability Test
# $Id: deb_1797_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1797-1 (xulrunner)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2009-0652

Moxie Marlinspike discovered that Unicode box drawing characters inside of
internationalised domain names could be used for phishing attacks.

CVE-2009-1302

Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman
and Gary Kwong reported crashes in the in the layout engine, which might
allow the execution of arbitrary code.

CVE-2009-1303

Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman
and Gary Kwong reported crashes in the in the layout engine, which might
allow the execution of arbitrary code.

CVE-2009-1304

Igor Bukanov and Bob Clary discovered crashes in the Javascript engine,
which might allow the execution of arbitrary code.

CVE-2009-1305

Igor Bukanov and Bob Clary discovered crashes in the Javascript engine,
which might allow the execution of arbitrary code.

CVE-2009-1306

Daniel Veditz discovered that the Content-Disposition: header is ignored
within the jar: URI scheme.

CVE-2009-1307

Gregory Fleischer discovered that the same-origin policy for Flash files
is inproperly enforced for files loaded through the view-source scheme,
which may result in bypass of cross-domain policy restrictions.

CVE-2009-1308

Cefn Hoile discovered that sites, which allow the embedding of third-party
stylesheets are vulnerable to cross-site scripting attacks through XBL
bindings.

CVE-2009-1309

moz_bug_r_a4 discovered bypasses of the same-origin policy in the
XMLHttpRequest Javascript API and the XPCNativeWrapper.

CVE-2009-1311

Paolo Amadini discovered that incorrect handling of POST data when
saving a web site with an embedded frame may lead to information disclosure.

CVE-2009-1312

It was discovered that Iceweasel allows Refresh: headers to redirect
to Javascript URIs, resulting in cross-site scripting.

For the stable distribution (lenny), these problems have been fixed
in version 1.9.0.9-0lenny2.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.0.9-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 1797-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201797-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304998");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1311", "CVE-2009-1312");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1797-1 (xulrunner)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.9-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
