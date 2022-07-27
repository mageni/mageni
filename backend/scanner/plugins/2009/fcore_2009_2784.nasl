# OpenVAS Vulnerability Test
# $Id: fcore_2009_2784.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-2784 (evolution-data-server)
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
tag_insight = "Update Information:

This update fixes two security issues:

Evolution Data Server did not properly
check the Secure/Multipurpose Internet Mail Extensions (S/MIME) signatures used
for public key encryption and signing of e-mail messages. An attacker could use
this flaw to spoof a signature by modifying the text of the e-mail message
displayed to the user. (CVE-2009-0547)

It was discovered that Evolution Data
Server did not properly validate NTLM (NT LAN Manager) authentication challenge
packets. A malicious server using NTLM authentication could cause an application
using Evolution Data Server to disclose portions of its memory or crash during
user authentication. (CVE-2009-0582)

ChangeLog:

* Tue Mar 17 2009 Matthew Barnes  - 2.25.5-4.fc10
- Add patch for RH bug #484925 (CVE-2009-0547, S/MIME signatures).
- Add patch for RH bug #487685 (CVE-2009-0582, NTLM authentication).
* Fri Mar 13 2009 Matthew Barnes  - 2.25.5-3.fc10
- Revise patch for RH bug #568332 to match upstream commit.
* Thu Mar 12 2009 Matthew Barnes  - 2.25.5-2.fc10
- Add patch for RH bug #568332 (thread leak in fsync() rate limiting).";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update evolution-data-server' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2784";
tag_summary = "The remote host is missing an update to evolution-data-server
announced via advisory FEDORA-2009-2784.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307542");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2009-0547", "CVE-2009-0582");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
 script_name("Fedora Core 10 FEDORA-2009-2784 (evolution-data-server)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=484925");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=487685");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.24.5~4.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~devel~2.24.5", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~doc~2.24.5", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~debuginfo~2.24.5", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
