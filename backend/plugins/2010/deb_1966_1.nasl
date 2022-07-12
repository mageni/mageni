# OpenVAS Vulnerability Test
# $Id: deb_1966_1.nasl 8207 2017-12-21 07:30:12Z teissa $
# Description: Auto-generated from advisory DSA 1966-1 (horde3)
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
tag_insight = "Several vulnerabilities have been found in horde3, the horde web application
framework. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2009-3237

It has been discovered that horde3 is prone to cross-site scripting
attacks via crafted number preferences or inline MIME text parts when
using text/plain as MIME type.
For lenny this issue was already fixed, but as an additional security
precaution, the display of inline text was disabled in the configuration
file.

CVE-2009-3701

It has been discovered that the horde3 administration interface is prone
to cross-site scripting attacks due to the use of the PHP_SELF variable.
This issue can only be exploited by authenticated administrators.

CVE-2009-4363

It has been discovered that horde3 is prone to several cross-site
scripting attacks via crafted data:text/html values in HTML messages.


For the stable distribution (lenny), these problems have been fixed in
version 3.2.2+debian0-2+lenny2.

For the oldstable distribution (etch), these problems have been fixed in
version 3.1.3-4etch7.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 3.3.6+debian0-1.


We recommend that you upgrade your horde3 packages.";
tag_summary = "The remote host is missing an update to horde3
announced via advisory DSA 1966-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201966-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314639");
 script_version("$Revision: 8207 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-01-11 23:48:26 +0100 (Mon, 11 Jan 2010)");
 script_cve_id("CVE-2009-3237", "CVE-2009-3701", "CVE-2009-4363");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1966-1 (horde3)");



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
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.1.3-4etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.2.2+debian0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
