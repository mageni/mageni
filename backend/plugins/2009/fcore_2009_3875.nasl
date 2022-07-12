# OpenVAS Vulnerability Test
# $Id: fcore_2009_3875.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3875 (firefox)
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

http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.9
ChangeLog:

* Tue Apr 21 2009 Christopher Aillon  - 3.0.9-1
- Update to 3.0.9
* Fri Mar 27 2009 Christopher Aillon  - 3.0.8-1
- Update to 3.0.8";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update firefox' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3875";
tag_summary = "The remote host is missing an update to firefox
announced via advisory FEDORA-2009-3875.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311547");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
 script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-0652", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 9 FEDORA-2009-3875 (firefox)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496252");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496253");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496255");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496256");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=486704");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496262");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496263");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496266");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496267");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496270");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496271");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=496274");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.9~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.9~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
