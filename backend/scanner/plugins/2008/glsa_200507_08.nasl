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
tag_insight = "phpGroupWare and eGroupWare include an XML-RPC implementation which allows
remote attackers to execute arbitrary PHP script commands.";
tag_solution = "All phpGroupWare users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-app/phpgroupware-0.9.16.006'

All eGroupWare users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-app/egroupware-1.0.0.008'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200507-08
http://bugs.gentoo.org/show_bug.cgi?id=97460
http://bugs.gentoo.org/show_bug.cgi?id=97651";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200507-08.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301705");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(14088);
 script_cve_id("CVE-2005-1921");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200507-08 (phpgroupware egroupware)");



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
if ((res = ispkgvuln(pkg:"www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.006"), vulnerable: make_list("lt 0.9.16.006"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/egroupware", unaffected: make_list("ge 1.0.0.008"), vulnerable: make_list("lt 1.0.0.008"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
