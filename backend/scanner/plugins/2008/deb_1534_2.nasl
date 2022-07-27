# OpenVAS Vulnerability Test
# $Id: deb_1534_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1534-2 (iceape)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "A regression in mailnews handling has been fixed. For reference the
original advisory text below:

Several remote vulnerabilities have been discovered in the Iceape internet
suite, an unbranded version of the Seamonkey Internet Suite. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-4879

Peter Brodersen and Alexander Klink discovered that the
autoselection of SSL client certificates could lead to users
being tracked, resulting in a loss of privacy.

CVE-2008-1233

moz_bug_r_a4 discovered that variants of CVE-2007-3738 and
CVE-2007-5338 allow the execution of arbitrary code through
XPCNativeWrapper.

CVE-2008-1234

moz_bug_r_a4 discovered that insecure handling of event
handlers could lead to cross-site scripting.

CVE-2008-1235

Boris Zbarsky, Johnny Stenback, and moz_bug_r_a4 discovered
that incorrect principal handling can lead to cross-site
scripting and the execution of arbitrary code.

CVE-2008-1236

Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett and Mats
Palmgren discovered crashes in the layout engine, which might
allow the execution of arbitrary code.

CVE-2008-1237

georgi, tgirmann and Igor Bukanov discovered crashes in the
Javascript engine, which might allow the execution of arbitrary
code.

CVE-2008-1238

Gregory Fleischer discovered that HTTP Referrer headers were
handled incorrectly in combination with URLs containing Basic
Authentication credentials with empty usernames, resulting
in potential Cross-Site Request Forgery attacks.

CVE-2008-1240

Gregory Fleischer discovered that web content fetched through
the jar: protocol can use Java to connect to arbitrary ports.
This is only an issue in combination with the non-free Java
plugin.

CVE-2008-1241

Chris Thomas discovered that background tabs could generate
XUL popups overlaying the current tab, resulting in potential
spoofing attacks.

For the stable distribution (etch), these problems have been fixed in
version 1.0.13~pre080323b-0etch2.

We recommend that you upgrade your iceape packages.";
tag_summary = "The remote host is missing an update to iceape
announced via advisory DSA 1534-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201534-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302422");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-30 19:28:13 +0200 (Wed, 30 Apr 2008)");
 script_cve_id("CVE-2007-4879", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2007-3738", "CVE-2007-5338");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1534-2 (iceape)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mozilla-browser", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-psm", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dev", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-calendar", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-dev", ver:"1.8+1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-browser", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-calendar", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-gnome-support", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dbg", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dom-inspector", ver:"1.0.13~pre080323b-0etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
