# OpenVAS Vulnerability Test
# $Id: deb_1273_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1273-1
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
tag_solution = "For the stable distribution (sarge), these problems have been fixed in
version 1.7-2sarge1

For the upcoming stable distribution (etch) and the unstable
distribution (sid) these packages have been fixed in version 1.8-4.

We recommend that you upgrade your nas package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201273-1";
tag_summary = "The remote host is missing an update to nas
announced via advisory DSA 1273-1.

Several vulnerabilities have been discovered in nas, the Network Audio
System.

CVE-2007-1543

A stack-based buffer overflow in the accept_att_local function in
server/os/connection.c in nas allows remote attackers to execute
arbitrary code via a long path slave name in a USL socket connection.

CVE-2007-1544

Integer overflow in the ProcAuWriteElement function in
server/dia/audispatch.c allows remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a large
max_samples value.

CVE-2007-1545

The AddResource function in server/dia/resource.c allows remote
attackers to cause a denial of service (server crash) via a
nonexistent client ID.

CVE-2007-1546

Array index error allows remote attackers to cause a denial of service
(crash) via (1) large num_action values in the ProcAuSetElements
function in server/dia/audispatch.c or (2) a large inputNum parameter
to the compileInputs function in server/dia/auutil.c.

CVE-2007-1547

The ReadRequestFromClient function in server/os/io.c allows remote
attackers to cause a denial of service (crash) via multiple
simultaneous connections, which triggers a NULL pointer dereference.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300297");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1543", "CVE-2007-1544", "CVE-2007-1545", "CVE-2007-1546", "CVE-2007-1547");
 script_bugtraq_id(23017);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1273-1 (nas)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"nas-doc", ver:"1.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaudio2", ver:"1.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaudio-dev", ver:"1.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nas-bin", ver:"1.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nas", ver:"1.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
