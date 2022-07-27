# OpenVAS Vulnerability Test
# $Id: fcore_2009_3868.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3868 (moin)
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

Update moin to 1.6.4. Fix the following CVEs: CVE-2008-0781 (again),
CVE-2008-3381, CVE-2009-0260, CVE-2009-0312. Fix AttachFile escaping problems,
upstream 1.7 changeset 5f51246a4df1 backported.
ChangeLog:

* Mon Apr 20 2009 Ville-Pekka Vainio  1.6.4-1
- Update to 1.6.4
- CVE-2008-3381 fixed upstream
- Re-fix CVE-2008-0781, upstream seems to have dropped the fix in 1.6,
used part of upstream 1.5 db212dfc58ef, backported upstream 1.7 5f51246a4df1
and 269a1fbc3ed7
- Fix CVE-2009-0260, patch from Debian etch
- Fix CVE-2009-0312
- Fix AttachFile escaping problems, backported upstream 1.7 5c4043e651b3";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update moin' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3868";
tag_summary = "The remote host is missing an update to moin
announced via advisory FEDORA-2009-3868.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310672");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
 script_cve_id("CVE-2008-0781", "CVE-2008-3381", "CVE-2009-0260", "CVE-2009-0312");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Fedora Core 10 FEDORA-2009-3868 (moin)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=457362");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=481547");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=432748");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=482791");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"moin", rpm:"moin~1.6.4~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
