# OpenVAS Vulnerability Test
# $Id: deb_2042_1.nasl 8447 2018-01-17 16:12:19Z teissa $
# Description: Auto-generated from advisory DSA 2042-1 (iscsitarget)
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
tag_insight = "Florent Daigniere discovered multiple format string vulnerabilities in Linux
SCSI target framework (which is known as iscsitarget under Debian) allow remote
attackers to cause a denial of service in the ietd daemon. The flaw could be
trigger by sending a carefully-crafted Internet Storage Name Service (iSNS)
request.


For the stable distribution (lenny), this problem has been fixed in
version 0.4.16+svn162-3.1+lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 0.4.17+svn229-1.4.

For the unstable distribution (sid), this problem has been fixed in
version 0.4.17+svn229-1.4.";
tag_summary = "The remote host is missing an update to iscsitarget
announced via advisory DSA 2042-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202042-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314497");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-14 20:09:58 +0200 (Fri, 14 May 2010)");
 script_cve_id("CVE-2010-0743");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2042-1 (iscsitarget)");



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
if ((res = isdpkgvuln(pkg:"iscsitarget-source", ver:"0.4.16+svn162-3.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iscsitarget", ver:"0.4.16+svn162-3.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
