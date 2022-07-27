# OpenVAS Vulnerability Test
# $Id: fcore_2009_8039.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-8039 (kdelibs)
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

This update fixes several security issues in KHTML (CVE-2009-1725,
CVE-2009-1690, CVE-2009-1687, CVE-2009-1698, CVE-2009-0945, CVE-2009-2537) which
may lead to a denial of service or potentially even arbitrary code execution.
In addition, libplasma was fixed to make Plasmaboard (a virtual keyboard applet)
work, and a bug in a Fedora patch which made builds of the SRPM on single-CPU
machines fail was fixed.

ChangeLog:

* Sun Jul 26 2009 Kevin Kofler  - 4.2.4-6
- fix CVE-2009-1725 - crash, possible ACE in numeric character references
- fix CVE-2009-1690 - crash, possible ACE in KHTML ( use-after-free)
- fix CVE-2009-1687 - possible ACE in KJS (FIXME: still crashes?)
- fix CVE-2009-1698 - crash, possible ACE in CSS style attribute handling
- fix CVE-2009-0945 - NULL-pointer dereference in the SVGList interface impl
* Thu Jul 23 2009 Jaroslav Reznik  - 4.2.4-5
- CVE-2009-2537 - select length DoS
- correct fixPopupForPlasmaboard.patch
* Wed Jul  8 2009 Kevin Kofler  - 4.2.4-4
- fix CMake dependency in parallel_devel patch (#510259, CHIKAMA Masaki)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update kdelibs' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8039";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory FEDORA-2009-8039.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306535");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-1725", "CVE-2009-1690", "CVE-2009-1687", "CVE-2009-1698", "CVE-2009-0945", "CVE-2009-2537");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 11 FEDORA-2009-8039 (kdelibs)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=513813");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=505571");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=506453");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=506469");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=506703");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=512911");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~4.2.4~6.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-common", rpm:"kdelibs-common~4.2.4~6.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~4.2.4~6.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~4.2.4~6.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~4.2.4~6.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
