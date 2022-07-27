# OpenVAS Vulnerability Test
# $Id: fcore_2009_3709.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3709 (ghostscript)
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

This update fixes several security flaws: CVE-2009-0792 (multiple integer
overflows and missing upper-bounds checks in icclib), CVE-2009-0196 (missing
boundary check in jbig2dec library), and CVE-2008-6679 (buffer overflow in
pdfwrite device).

ChangeLog:

* Wed Apr 15 2009 Tim Waugh  8.63-6
- Applied patch to fix CVE-2009-0792 (bug #491853).
- Applied patch to fix CVE-2009-0196 (bug #493379).
- Applied patch to fix CVE-2008-6679 (bug #493445).
* Fri Mar 20 2009 Tim Waugh  8.63-5
- Applied patch to fix CVE-2009-0583 (bug #487742) and CVE-2009-0584
(bug #487744).";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update ghostscript' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3709";
tag_summary = "The remote host is missing an update to ghostscript
announced via advisory FEDORA-2009-3709.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305789");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
 script_cve_id("CVE-2009-0792", "CVE-2009-0196", "CVE-2008-6679", "CVE-2009-0583", "CVE-2009-0584");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-3709 (ghostscript)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=493445");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=493379");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491853");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.63~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.63~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.63~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~8.63~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~8.63~6.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
