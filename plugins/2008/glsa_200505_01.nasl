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
tag_insight = "Various modules of the Horde Framework are vulnerable to multiple
cross-site scripting (XSS) vulnerabilities.";
tag_solution = "All Horde users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-2.2.8'

All Horde Vacation users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-vacation-2.2.2'

All Horde Turba users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-turba-1.2.5'

All Horde Passwd users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-passwd-2.2.2'

All Horde Nag users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-nag-1.1.3'

All Horde Mnemo users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-mnemo-1.1.4'

All Horde Kronolith users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-kronolith-1.1.4'

All Horde IMP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-imp-3.2.8'

All Horde Accounts users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-accounts-2.1.2'

All Horde Forwards users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-forwards-2.2.2'

All Horde Chora users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-chora-1.2.3'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-01
http://bugs.gentoo.org/show_bug.cgi?id=90365
http://marc.theaimsgroup.com/?l=horde-announce&r=1&b=200504&w=2";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200505-01.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301428");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Gentoo Security Advisory GLSA 200505-01 (Horde)");



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
if ((res = ispkgvuln(pkg:"www-apps/horde-vacation", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-turba", unaffected: make_list("ge 1.2.5"), vulnerable: make_list("lt 1.2.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-passwd", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-nag", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-mnemo", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-kronolith", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-imp", unaffected: make_list("ge 3.2.8"), vulnerable: make_list("lt 3.2.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-accounts", unaffected: make_list("ge 2.1.2"), vulnerable: make_list("lt 2.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-forwards", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-chora", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 2.2.8"), vulnerable: make_list("lt 2.2.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
