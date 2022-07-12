# OpenVAS Vulnerability Test
# $Id: deb_905_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 905-1
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
version 0.19.2-4.1.

For the unstable distribution (sid) these problems have been fixed in
version 0.19.3-0.1.

We recommend that you upgrade your mantis package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20905-1";
tag_summary = "The remote host is missing an update to mantis
announced via advisory DSA 905-1.

Several security related problems have been discovered in Mantis, a
web-based bug tracking system.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-3091

A cross-site scripting vulnerability allows attackers to inject
arbitrary web script or HTML.

CVE-2005-3335

A file inclusion vulnerability allows remote attackers to execute
arbitrary PHP code and include arbitrary local files.

CVE-2005-3336

An SQL injection vulnerability allows remote attackers to execute
arbitrary SQL commands.

CVE-2005-3338

Mantis can be tricked into displaying the otherwise hidden real
mail address of its users.

The old stable distribution (woody) is not affected by these problems.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301275");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-3091", "CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3338", "CVE-2005-3339");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 905-1 (mantis)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mantis", ver:"0.19.2-4.1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
