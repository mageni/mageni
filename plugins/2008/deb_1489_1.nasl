# OpenVAS Vulnerability Test
# $Id: deb_1489_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1489-1 (iceweasel)
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
web browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0412

Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren and Paul
Nickerson discovered crashes in the layout engine, which might allow
the execution of arbitrary code.

CVE-2008-0413

Carsten Book, Wesley Garland, Igor Bukanov, moz_bug_r_a4, shutdown,
Philip Taylor and tgirmann discovered crashes in the Javascript
engine, which might allow the execution of arbitrary code.

CVE-2008-0414

hong and Gregory Fleisher discovered that file input focus
vulnerabilities in the file upload control could allow information
disclosure of local files.

CVE-2008-0415

moz_bug_r_a4 and Boris Zbarsky discovered discovered several
vulnerabilities in Javascript handling, which could allow
privilege escalation.

CVE-2008-0417

Justin Dolske discovered that the password storage machanism could
be abused by malicious web sites to corrupt existing saved passwords.

CVE-2008-0418

Gerry Eisenhaur and moz_bug_r_a4 discovered that a directory
traversal vulnerability in chrome: URI handling could lead to
information disclosure.

CVE-2008-0419

David Bloom discovered a race condition in the image handling of
designMode elements, which can lead to information disclosure or
potentially the execution of arbitrary code.

CVE-2008-0591

Michal Zalewski discovered that timers protecting security-sensitive
dialogs (which disable dialog elements until a timeout is reached)
could be bypassed by window focus changes through Javascript.

CVE-2008-0592

It was discovered that malformed content declarations of saved
attachments could prevent a user in the opening local files
with a .txt file name, resulting in minor denial of service.

CVE-2008-0593

Martin Straka discovered that insecure stylesheet handling during
redirects could lead to information disclosure.

CVE-2008-0594

Emil Ljungdahl and Lars-Olof Moilanen discovered that phishing
protections could be bypassed with <div> elements.


For the stable distribution (etch), these problems have been fixed in
version 2.0.0.12-0etch1.

The Mozilla products from the old stable distribution (sarge) are no
longer supported with security updates.

We recommend that you upgrade your iceweasel packages.";
tag_summary = "The remote host is missing an update to iceweasel
announced via advisory DSA 1489-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201489-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300510");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1489-1 (iceweasel)");



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
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.12-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
