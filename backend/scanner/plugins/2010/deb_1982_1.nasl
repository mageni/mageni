# OpenVAS Vulnerability Test
# $Id: deb_1982_1.nasl 8510 2018-01-24 07:57:42Z teissa $
# Description: Auto-generated from advisory DSA 1982-1 (hybserv)
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
tag_insight = "Julien Cristau discovered that hybserv, a daemon running IRC services
for IRCD-Hybrid, is prone to a denial of service attack via the commands
option.


For the stable distribution (lenny), this problem has been fixed in
version 1.9.2-4+lenny2.

Due to a bug in the archive system, it is not possible to release the
fix for the oldstable distribution (etch) simultaneously. Therefore,
etch will be fixed in version 1.9.2-4+etch1 as soon as it becomes
available.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.2-4.1.


We recommend that you upgrade your hybserv packages.";
tag_summary = "The remote host is missing an update to hybserv
announced via advisory DSA 1982-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201982-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313270");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2010-0303");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1982-1 (hybserv)");



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
if ((res = isdpkgvuln(pkg:"hybserv", ver:"1.9.2-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
