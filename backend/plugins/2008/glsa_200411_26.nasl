# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Improper file ownership allows user-owned files to be run with root
privileges by init scripts.";
tag_solution = "All GIMPS users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/gimps-23.9-r1'

All SETI@home users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/setiathome-3.03-r2'

All ChessBrain users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/chessbrain-20407-r1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-26
http://bugs.gentoo.org/show_bug.cgi?id=69868";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200411-26.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303381");
 script_cve_id("CVE-2004-1115","CVE-2004-1116","CVE-2004-1117");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_name("Gentoo Security Advisory GLSA 200411-26 (GIMPS,SETI@home,ChessBrain)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"app-sci/gimps", unaffected: make_list("ge 23.9-r1"), vulnerable: make_list("le 23.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-sci/setiathome", unaffected: make_list("ge 3.08-r4", "rge 3.03-r2"), vulnerable: make_list("le 3.08-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-sci/chessbrain", unaffected: make_list("ge 20407-r1"), vulnerable: make_list("le 20407"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
