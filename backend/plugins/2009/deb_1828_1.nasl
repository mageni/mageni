# OpenVAS Vulnerability Test
# $Id: deb_1828_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1828-1 (ocsinventory-agent)
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
tag_insight = "It was discovered that the ocsinventory-agent which is part of the
ocsinventory suite, a hardware and software configuration indexing service,
is prone to an insecure perl module search path.  As the agent is started
via cron and the current directory (/ in this case) is included in the
default perl module path the agent scans every directory on the system
for its perl modules.  This enables an attacker to execute arbitrary code
via a crafted ocsinventory-agent perl module placed on the system.


The oldstable distribution (etch) does not contain ocsinventory-agent.

For the stable distribution (lenny), this problem has been fixed in
version 1:0.0.9.2repack1-4lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 1:0.0.9.2repack1-5

For the unstable distribution (sid), this problem has been fixed in
version 1:0.0.9.2repack1-5.


We recommend that you upgrade your ocsinventory-agent packages.";
tag_summary = "The remote host is missing an update to ocsinventory-agent
announced via advisory DSA 1828-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201828-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308227");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-15 04:21:35 +0200 (Wed, 15 Jul 2009)");
 script_cve_id("CVE-2009-0667");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1828-1 (ocsinventory-agent)");



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
if ((res = isdpkgvuln(pkg:"ocsinventory-agent", ver:"0.0.9.2repack1-4lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
