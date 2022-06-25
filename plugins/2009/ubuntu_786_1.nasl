# OpenVAS Vulnerability Test
# $Id: ubuntu_786_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_786_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-786-1 (apr-util)
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
  libaprutil1                     1.2.12+dfsg-3ubuntu0.1

Ubuntu 8.10:
  libaprutil1                     1.2.12+dfsg-7ubuntu0.1

Ubuntu 9.04:
  libaprutil1                     1.2.12+dfsg-8ubuntu0.1

After a standard system upgrade you need to restart any services that use
apr-util, such as Apache or svnserve, to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-786-1";

tag_insight = "Matthew Palmer discovered an underflow flaw in apr-util. An attacker could
cause a denial of service via application crash in Apache using a crafted
SVNMasterURI directive, .htaccess file, or when using mod_apreq2.
Applications using libapreq2 are also affected. (CVE-2009-0023)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a denial of service via memory
resource consumption by sending a crafted request to an Apache server
configured to use mod_dav or mod_dav_svn. (CVE-2009-1955)

C. Michael Pilato discovered an off-by-one buffer overflow in apr-util when
formatting certain strings. For big-endian machines (powerpc, hppa and
sparc in Ubuntu), a remote attacker could cause a denial of service or
information disclosure leak. All other architectures for Ubuntu are
not considered to be at risk. (CVE-2009-1956)";
tag_summary = "The remote host is missing an update to apr-util
announced via advisory USN-786-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311577");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-15 19:20:43 +0200 (Mon, 15 Jun 2009)");
 script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Ubuntu USN-786-1 (apr-util)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-786-1/");

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
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-3ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-7ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-7ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-7ubuntu0.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-8ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-8ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-8ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
