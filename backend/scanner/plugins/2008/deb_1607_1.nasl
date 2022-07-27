# OpenVAS Vulnerability Test
# $Id: deb_1607_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1607-1 (iceweasel)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Iceweasel
webbrowser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-2798

Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered
crashes in the layout engine, which might allow the execution of
arbitrary code.

CVE-2008-2799

Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in
the Javascript engine, which might allow the execution of arbitrary code.

CVE-2008-2800

moz_bug_r_a4 discovered several cross-site scripting vulnerabilities.

CVE-2008-2801

Collin Jackson and Adam Barth discovered that Javascript code
could be executed in the context or signed JAR archives.

CVE-2008-2802

moz_bug_r_a4 discovered that XUL documements can escalate
privileges by accessing the pre-compiled fastload file.

CVE-2008-2803

moz_bug_r_a4 discovered that missing input sanitising in the
mozIJSSubScriptLoader.loadSubScript() function could lead to the
execution of arbitrary code. Iceweasel itself is not affected, but
some addons are.

CVE-2008-2805

Claudio Santambrogio discovered that missing access validation in
DOM parsing allows malicious web sites to force the browser to
upload local files to the server, which could lead to information
disclosure.

CVE-2008-2807

Daniel Glazman discovered that a programming error in the code for
parsing .properties files could lead to memory content being
exposed to addons, which could lead to information disclosure.

CVE-2008-2808

Masahiro Yamada discovered that file URLS in directory listings
were insufficiently escaped.

CVE-2008-2809

John G. Myers, Frank Benkstein and Nils Toedtmann discovered that
alternate names on self-signed certificates were handled
insufficiently, which could lead to spoofings secure connections.

CVE-2008-2811

Greg McManus discovered discovered a crash in the block reflow
code, which might allow the execution of arbitrary code.


For the stable distribution (etch), these problems have been fixed in
version 2.0.0.15-0etch1.

Iceweasel from the unstable distribution (sid) links dynamically
against the xulrunner library.

We recommend that you upgrade your iceweasel package.";
tag_summary = "The remote host is missing an update to iceweasel
announced via advisory DSA 1607-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201607-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300332");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-07-15 02:29:31 +0200 (Tue, 15 Jul 2008)");
 script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2811");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1607-1 (iceweasel)");



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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.15-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
