# OpenVAS Vulnerability Test
# $Id: deb_1822_1.nasl 8970 2018-02-27 15:16:18Z cfischer $
# Description: Auto-generated from advisory DSA 1822-1 (mahara)
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
tag_insight = "It was discovered that mahara, an electronic portfolio, weblog, and resume
builder is prone to several cross-site scripting attacks, which allow an
attacker to inject arbitrary HTML or script code and steal potential sensitive
data from other users.


The oldstable distribution (etch) does not contain mahara.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.4-4+lenny3.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.5-1.


We recommend that you upgrade your mahara packages.";
tag_summary = "The remote host is missing an update to mahara
announced via advisory DSA 1822-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201822-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308508");
 script_version("$Revision: 8970 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-27 16:16:18 +0100 (Tue, 27 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1822-1 (mahara)");
 script_cve_id("CVE-2009-2170");

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
if ((res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
