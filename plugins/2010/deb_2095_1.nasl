# OpenVAS Vulnerability Test
# $Id: deb_2095_1.nasl 8287 2018-01-04 07:28:11Z teissa $
# Description: Auto-generated from advisory DSA 2095-1 (lvm2)
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
tag_insight = "Alasdair Kergon discovered that the cluster logical volume manager daemon
(clvmd) in lvm2, The Linux Logical Volume Manager, does not verify client
credentials upon a socket connection, which allows local users to cause a
denial of service.

For the stable distribution (lenny), this problem has been fixed in
version 2.02.39-8

For the testing distribution (squeeze), and the unstable distribution (sid),
this problem has been fixed in version 2.02.66-3


We recommend that you upgrade your lvm2 package.";
tag_summary = "The remote host is missing an update to lvm2
announced via advisory DSA 2095-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202095-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314092");
 script_version("$Revision: 8287 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2526");
 script_name("Debian Security Advisory DSA 2095-1 (lvm2)");



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
if ((res = isdpkgvuln(pkg:"clvm", ver:"2.02.39-8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lvm2", ver:"2.02.39-8", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
