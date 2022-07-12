# OpenVAS Vulnerability Test
# $Id: deb_1917_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1917-1 (mimetex)
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
tag_insight = "Several vulnerabilities have been discovered in mimetex, a lightweight
alternative to MathML. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2009-1382

Chris Evans and Damien Miller, discovered multiple stack-based buffer overflow.
An attacker could execute arbitrary code via a TeX file with long picture,
circle, input tags.

CVE-2009-2459

Chris Evans discovered that mimeTeX contained certain directives that may be
unsuitable for handling untrusted user input. A remote attacker can obtain
sensitive information.


For the oldstable distribution (etch), these problems have been fixed in
version 1.50-1+etch1.

Due to a bug in the archive system, the fix for the stable distribution
(lenny) will be released as version 1.50-1+lenny1 once it is available.

For the testing distribution (squeeze), and the unstable distribution (sid),
these problems have been fixed in version 1.50-1.1.


We recommend that you upgrade your mimetex packages.";
tag_summary = "The remote host is missing an update to mimetex
announced via advisory DSA 1917-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201917-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307806");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-1382", "CVE-2009-2459");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1917-1 (mimetex)");



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
if ((res = isdpkgvuln(pkg:"mimetex", ver:"1.50-1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
