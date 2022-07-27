# OpenVAS Vulnerability Test
# $Id: fcore_2009_5861.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-5861 (gupnp)
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

New upstream release that fixes a bug where the gupnp stack crashes when passed
empty content.
ChangeLog: http://git.gupnp.org/cgit.cgi?url=gupnp/tree/NEWS&id=ce714a6700ce03953a2886a66ec57db59205f4e6
Bug report: http://bugzilla.openedhand.com/show_bug.cgi?id=1604

Other bugs fixed: 
- bug#1570: gupnp doesn't set the pkgconfig lib dir correctly in 64 bit env.
- bug#1574: Avoid using asserts.
- bug#1592: gupnp_device_info_get_icon_url() does not return the closest match.
- bug#1604: Crash on action without any content.

ChangeLog:

* Wed Jun  3 2009 Peter Robinson  0.12.8-1
- New upstream release
* Mon Apr 27 2009 Peter Robinson  0.12.7-1
- New upstream release
* Wed Mar  4 2009 Peter Robinson  0.12.6-4
- Move docs to noarch sub package
* Mon Mar  2 2009 Peter Robinson  0.12.6-3
- Add some extra -devel Requires packages
* Tue Feb 24 2009 Fedora Release Engineering  - 0.12.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild
* Mon Feb 23 2009 Peter Robinson  0.12.6-1
- New upstream release
* Wed Jan 14 2009 Peter Robinson  0.12.5-1
- New upstream release
* Thu Dec 18 2008 Peter Robinson  0.12.4-3
- Add gtk-doc build req
* Sat Nov 22 2008 Peter Robinson  0.12.4-2
- Fix summary
* Mon Nov 17 2008 Peter Robinson  0.12.4-1
- New upstream release";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update gupnp' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5861";
tag_summary = "The remote host is missing an update to gupnp
announced via advisory FEDORA-2009-5861.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306255");
 script_cve_id("CVE-2009-2174");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Fedora Core 10 FEDORA-2009-5861 (gupnp)");



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
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gupnp", rpm:"gupnp~0.12.8~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gupnp-devel", rpm:"gupnp-devel~0.12.8~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gupnp-debuginfo", rpm:"gupnp-debuginfo~0.12.8~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gupnp-docs", rpm:"gupnp-docs~0.12.8~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
