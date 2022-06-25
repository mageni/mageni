# OpenVAS Vulnerability Test
# $Id: deb_1691_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1691-1 (moodle)
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
tag_insight = "Several remote vulnerabilities have been discovered in Moodle, an online
course management system. The following issues are addressed in this
update, ranging from cross site scripting to remote code execution.

Various cross site scripting issues in the Moodle codebase
(CVE-2008-3326, CVE-2008-3325, CVE-2007-3555, CVE-2008-5432,
MSA-08-0021, MDL-8849, MDL-12793, MDL-11414, MDL-14806,
MDL-10276).

Various cross site request forgery issues in the Moodle codebase
(CVE-2008-3325, MSA-08-0023).

Privilege escalation bugs in the Moodle codebase (MSA-08-0001, MDL-7755).

SQL injection issue in the hotpot module (MSA-08-0010).

An embedded copy of Smarty had several vulnerabilities
(CVE-2008-4811, CVE-2008-4810).
An embedded copy of Snoopy was vulnerable to cross site scripting
(CVE-2008-4796).
An embedded copy of Kses was vulnerable to cross site scripting
(CVE-2008-1502).

For the stable distribution (etch), these problems have been fixed in
version 1.6.3-2+etch1.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.2.dfsg-2.

We recommend that you upgrade your moodle (1.6.3-2+etch1) package.";
tag_summary = "The remote host is missing an update to moodle
announced via advisory DSA 1691-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201691-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300344");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-12-29 22:42:24 +0100 (Mon, 29 Dec 2008)");
 script_cve_id("CVE-2007-3555", "CVE-2008-1502", "CVE-2008-3325", "CVE-2008-3326", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5432");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1691-1 (moodle)");



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
if ((res = isdpkgvuln(pkg:"moodle", ver:"1.6.3-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
