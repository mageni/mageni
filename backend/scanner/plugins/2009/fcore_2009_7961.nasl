# OpenVAS Vulnerability Test
# $Id: fcore_2009_7961.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-7961 (blam)
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

Update to new upstream Firefox version 3.0.12, fixing multiple security issues
detailed in the upstream advisories:
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.12

Update also includes all packages depending on gecko-libs rebuilt against
new version of Firefox / XULRunner.

ChangeLog:

* Tue Jul 21 2009 Jan Horak  - 1.8.5-12
- Rebuild against newer gecko
* Thu Jun 11 2009 Christopher Aillon  - 1.8.5-11
- Rebuild against newer gecko";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update blam' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7961";
tag_summary = "The remote host is missing an update to blam
announced via advisory FEDORA-2009-7961.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304434");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2462", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-7961 (blam)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512131");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512133");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512135");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512128");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512136");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512137");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512142");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512146");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512147");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"blam", rpm:"blam~1.8.5~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"blam-debuginfo", rpm:"blam-debuginfo~1.8.5~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
