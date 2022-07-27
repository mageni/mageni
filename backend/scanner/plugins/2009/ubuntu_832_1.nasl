# OpenVAS Vulnerability Test
# $Id: ubuntu_832_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_832_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-832-1 (freeradius)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 8.04 LTS:
  freeradius                      1.1.7-1ubuntu0.2

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-832-1";

tag_insight = "It was discovered that FreeRADIUS did not correctly handle certain 
malformed attributes. A remote attacker could exploit this flaw and cause
the FreeRADIUS server to crash, resulting in a denial of service.";
tag_summary = "The remote host is missing an update to freeradius
announced via advisory USN-832-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306707");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
 script_cve_id("CVE-2009-3111");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Ubuntu USN-832-1 (freeradius)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-832-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"freeradius-dialupadmin", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-dbg", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-krb5", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-ldap", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-mysql", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius-postgresql", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"freeradius", ver:"1.1.7-1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
