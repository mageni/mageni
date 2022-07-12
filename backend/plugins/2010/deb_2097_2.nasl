# OpenVAS Vulnerability Test
# $Id: deb_2097_2.nasl 8244 2017-12-25 07:29:28Z teissa $
# Description: Auto-generated from advisory DSA 2097-2 (phpmyadmin)
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
tag_insight = "The update in DSA 2097 for phpMyAdmin did not correctly apply the intended
changes, thereby not completely addressing the vulnerabilities. Updated
packages now fix the issues described in the original advisory text below.

Several remote vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2010-3055

The configuration setup script does not properly sanitise its output
file, which allows remote attackers to execute arbitrary PHP code via
a crafted POST request. In Debian, the setup tool is protected through
Apache HTTP basic authentication by default.

CVE-2010-3056

Various cross site scripting issues have been discovered that allow
a remote attacker to inject arbitrary web script or HTML.

For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny6.

For the testing (squeeze) and unstable distribution (sid), these problems
have been fixed in version 3.3.5.1-1.

We recommend that you upgrade your phpmyadmin package.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 2097-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202097-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313237");
 script_version("$Revision: 8244 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-3055", "CVE-2010-3056");
 script_name("Debian Security Advisory DSA 2097-2 (phpmyadmin)");



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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.11.8.1-5+lenny6", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
