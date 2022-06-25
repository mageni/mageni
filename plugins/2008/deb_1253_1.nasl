# OpenVAS Vulnerability Test
# $Id: deb_1253_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1253-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge15.

For the testing and unstable distribution (sid and etch) these
problems have been fixed in version 2.0.0.1+dfsg-2 of iceweasel.

We recommend that you upgrade your firefox and iceweasel packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201253-1";
tag_summary = "The remote host is missing an update to mozilla-firefox
announced via advisory DSA 1253-1.

Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Firefox.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:

CVE-2006-6497

Several vulnerabilities in the layout engine allow remote
attackers to cause a denial of service and possibly permit them to
execute arbitrary code. [MFSA 2006-68]

CVE-2006-6498

Several vulnerabilities in the JavaScript engine allow remote
attackers to cause a denial of service and possibly permit them to
execute arbitrary code. [MFSA 2006-68]

CVE-2006-6499

A bug in the js_dtoa function allows remote attackers to cause a
denial of service. [MFSA 2006-68]

CVE-2006-6501

shutdown discovered a vulnerability that allows remote attackers
to gain privileges and install malicious code via the watch
JavaScript function. [MFSA 2006-70]

CVE-2006-6502

Steven Michaud discovered a programming bug that allows remote
attackers to cause a denial of service. [MFSA 2006-71]

CVE-2006-6503

moz_bug_r_a4 reported that the src attribute of an IMG element
could be used to inject JavaScript code. [MFSA 2006-72]";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301582");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503");
 script_bugtraq_id(21668);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1253-1 (mozilla-firefox)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge15", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge15", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge15", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
