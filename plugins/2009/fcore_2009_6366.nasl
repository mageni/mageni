# OpenVAS Vulnerability Test
# $Id: fcore_2009_6366.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-6366 (firefox)
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

Update to new upstream Firefox version 3.0.11, fixing multiple security issues
detailed in the upstream advisories:
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.11

Update also includes all packages depending on gecko-libs rebuild
against new version of Firefox / XULRunner.

ChangeLog:

* Thu Jun 11 2009 Christopher Aillon  - 3.0.11-1
- Update to 3.0.11
* Mon Apr 27 2009 Jan Horak  - 3.0.10-1
- Update to 3.0.10
* Tue Apr 21 2009 Christopher Aillon  - 3.0.9-1
- Update to 3.0.9
* Fri Mar 27 2009 Christopher Aillon  - 3.0.8-1
- Update to 3.0.8
* Wed Mar  4 2009 Jan Horak  - 3.0.7-1
- Update to 3.0.7
* Thu Feb 26 2009 Jan Horak  - 3.0.6-2
- Fixed spelling mistake in firefox.sh.in
* Wed Feb  4 2009 Christopher Aillon  - 3.0.6-1
- Update to 3.0.6
* Wed Jan  7 2009 Jan Horak  - 3.0.5-2
- Fixed wrong LANG and LC_MESSAGES variables interpretation (#441973)
in startup script.
* Tue Dec 16 2008 Christopher Aillon  3.0.5-1
- Update to 3.0.5
* Thu Nov 13 2008 Jan Horak  3.0.4-2
- Removed firefox-2.0-getstartpage.patch patch
- Start page is set by different way";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update firefox' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6366";
tag_summary = "The remote host is missing an update to firefox
announced via advisory FEDORA-2009-6366.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310448");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-6366 (firefox)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503568");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503569");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503570");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503573");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503576");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503578");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503579");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503580");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503581");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503582");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=503583");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.11~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.11~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
