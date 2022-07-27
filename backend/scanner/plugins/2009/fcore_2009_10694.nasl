# OpenVAS Vulnerability Test
# $Id: fcore_2009_10694.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-10694 (xpdf)
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

- apply xpdf-3.02pl4 security patch to fix:    CVE-2009-1188/CVE-2009-3603,
CVE-2009-3604, CVE-2009-3606,    CVE-2009-3608, CVE-2009-3609

ChangeLog:

* Fri Oct 16 2009 Tom spot Callaway  - 1:3.02-15
- apply xpdf-3.02pl4 security patch to fix:
CVE-2009-3603, CVE-2009-3604, CVE-2009-3605, CVE-2009-3606
CVE-2009-3608, CVE-2009-3609";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update xpdf' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10694";
tag_summary = "The remote host is missing an update to xpdf
announced via advisory FEDORA-2009-10694.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305802");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609", "CVE-2009-3605", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-10694 (xpdf)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=495907");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=526911");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=526877");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=526637");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=526893");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~15.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-debuginfo", rpm:"xpdf-debuginfo~3.02~15.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
