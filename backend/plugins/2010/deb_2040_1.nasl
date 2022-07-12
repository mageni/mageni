# OpenVAS Vulnerability Test
# $Id: deb_2040_1.nasl 8528 2018-01-25 07:57:36Z teissa $
# Description: Auto-generated from advisory DSA 2040-1 (squidguard)
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
tag_insight = "It was discovered that in squidguard, a URL redirector/filter/ACL plugin
for squid, several problems in src/sgLog.c and src/sgDiv.c allow remote
users to either:

* cause a denial of service, by requesting long URLs containing many
slashes; this forces the daemon into emergency mode, where it does
not process requests anymore.

* bypass rules by requesting URLs whose length is close to predefined
buffer limits, in this case 2048 for squidguard and 4096 or 8192 for
squid (depending on its version).

For the stable distribution (lenny), this problem has been fixed in
version 1.2.0-8.4+lenny1.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.0-9.

We recommend that you upgrade your squidguard package.";
tag_summary = "The remote host is missing an update to squidguard
announced via advisory DSA 2040-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202040-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.315126");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
 script_cve_id("CVE-2009-3700", "CVE-2009-3826");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2040-1 (squidguard)");



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
if ((res = isdpkgvuln(pkg:"squidguard", ver:"1.2.0-8.4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
