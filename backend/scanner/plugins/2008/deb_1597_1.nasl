# OpenVAS Vulnerability Test
# $Id: deb_1597_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1597-1 (mt-daapd)
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
tag_insight = "Three vulnerabilities have been discovered in the mt-daapd DAAP audio
server (also known as the Firefly Media Server).  The Common
Vulnerabilities and Exposures project identifies the following three
problems:

CVE-2007-5824

Insufficient validation and bounds checking of the Authorization:
HTTP header enables a heap buffer overflow, potentially enabling
the execution of arbitrary code.

CVE-2007-5825

Format string vulnerabilities in debug logging within the
authentication of XML-RPC requests could enable the execution of
arbitrary code.

CVE-2008-1771

An integer overflow weakness in the handling of HTTP POST
variables could allow a heap buffer overflow and potentially
arbitrary code execution.

For the stable distribution (etch), these problems have been fixed in
version 0.2.4+r1376-1.1+etch1.

For the unstable distribution (sid), these problems have been fixed in
version 0.9~r1696-1.3.

We recommend that you upgrade your mt-daapd package.";
tag_summary = "The remote host is missing an update to mt-daapd
announced via advisory DSA 1597-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201597-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302862");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-06-28 00:42:46 +0200 (Sat, 28 Jun 2008)");
 script_cve_id("CVE-2007-5824", "CVE-2007-5825", "CVE-2008-1771");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1597-1 (mt-daapd)");



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
if ((res = isdpkgvuln(pkg:"mt-daapd", ver:"0.2.4+r1376-1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
