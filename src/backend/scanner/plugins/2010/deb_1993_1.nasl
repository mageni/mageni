# OpenVAS Vulnerability Test
# $Id: deb_1993_1.nasl 8274 2018-01-03 07:28:17Z teissa $
# Description: Auto-generated from advisory DSA 1993-1 (otrs2)
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
tag_insight = "It was discovered that otrs2, the Open Ticket Request System, does not
properly sanitise input data that is used on SQL queries, which might be
used to inject arbitrary SQL to, for example, escalate privileges on a
system that uses otrs2.

The oldstable distribution (etch) is not affected.

For the stable distribution (lenny), the problem has been fixed in
version 2.2.7-2lenny3.

For the testing distribution (squeeze), the problem will be fixed soon.

For the unstable distribution (sid), the problem has been fixed in
version 2.4.7-1.

We recommend that you upgrade your otrs2 packages.";
tag_summary = "The remote host is missing an update to otrs2
announced via advisory DSA 1993-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201993-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314342");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-18 21:15:01 +0100 (Thu, 18 Feb 2010)");
 script_cve_id("CVE-2010-0438");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1993-1 (otrs2)");



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
if ((res = isdpkgvuln(pkg:"otrs2", ver:"2.2.7-2lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
