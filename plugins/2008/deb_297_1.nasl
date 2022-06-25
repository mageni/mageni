# OpenVAS Vulnerability Test
# $Id: deb_297_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 297-1
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
tag_insight = "Two vulnerabilities have been discoverd in Snort, a popular network
intrusion detection system.  Snort comes with modules and plugins that
perform a variety of functions such as protocol analysis.  The
following issues have been identified:

Heap overflow in Snort stream4 preprocessor
(VU#139129, CVE-2003-0209, Bugtraq Id 7178)

Researchers at CORE Security Technologies have discovered a
remotely exploitable inteter overflow that results in overwriting
the heap in the stream4 preprocessor module.  This module allows
Snort to reassemble TCP packet fragments for further analysis.  An
attacker could insert arbitrary code that would be executed as
the user running Snort, probably root.

Buffer overflow in Snort RPC preprocessor
(VU#916785, CVE-2003-0033, Bugtraq Id 6963)

Researchers at Internet Security Systems X-Force have discovered a
remotely exploitable buffer overflow in the Snort RPC preprocessor
module.  Snort incorrectly checks the lengths of what is being
normalized against the current packet size.  An attacker could
exploit this to execute arbitrary code under the privileges of the
Snort process, probably root.

For the stable distribution (woody) these problems have been fixed in
version 1.8.4beta1-3.1.

The old stable distribution (potato) is not affected by these problems
since it doesn't contain the problematic code.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.0-1.

We recommend that you upgrade your snort package immediately.";
tag_summary = "The remote host is missing an update to snort
announced via advisory DSA 297-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20297-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302417");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0033", "CVE-2003-0209");
 script_bugtraq_id(7178,6963);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 297-1 (snort)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"snort-doc", ver:"1.8.4beta1-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snort-rules-default", ver:"1.8.4beta1-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snort", ver:"1.8.4beta1-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snort-common", ver:"1.8.4beta1-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snort-mysql", ver:"1.8.4beta1-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
