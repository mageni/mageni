# OpenVAS Vulnerability Test
# $Id: fcore_2009_2882.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-2882 (thunderbird)
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

Several flaws were found in the processing of malformed HTML mail content. An
HTML mail message containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code as the user running Thunderbird.
(CVE-2009-0040, CVE-2009-0352, CVE-2009-0353, CVE-2009-0772, CVE-2009-0774,
CVE-2009-0775)    Several flaws were found in the way malformed content was
processed. An HTML mail message containing specially-crafted content could
potentially trick a Thunderbird user into surrendering sensitive information.
(CVE-2009-0355, CVE-2009-0776)    Note: JavaScript support is disabled by
default in Thunderbird. None of the above issues are exploitable unless
JavaScript is enabled.

ChangeLog:

* Fri Mar 20 2009 Christopher Aillon  - 2.0.0.21-1
- Update to 2.0.0.21
* Wed Jan  7 2009 Christopher Aillon  - 2.0.0.19-2
- Disable the crash dialog
* Mon Jan  5 2009 Christopher Aillon  2.0.0.19-1
- Update to 2.0.0.19";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update thunderbird' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2882";
tag_summary = "The remote host is missing an update to thunderbird
announced via advisory FEDORA-2009-2882.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306171");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0355", "CVE-2009-0776");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-2882 (thunderbird)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=486355");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=483139");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=483141");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=483143");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488273");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488283");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488287");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488290");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~2.0.0.21~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~2.0.0.21~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
