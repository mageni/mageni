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
tag_insight = "OpenOffice.org uses insecure temporary files which could allow a malicious
local user to gain knowledge of sensitive information from other users'
documents.";
tag_solution = "All affected OpenOffice.org users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=app-office/openoffice-1.1.3'
    # emerge '>=app-office/openoffice-1.1.3'

All affected OpenOffice.org binary users should upgrade to the latest
version:

    # emerge sync

    # emerge -pv '>=app-office/openoffice-bin-1.1.3'
    # emerge '>=app-office/openoffice-bin-1.1.3'

All affected OpenOffice.org Ximian users should upgrade to the latest
version:

    # emerge sync

    # emerge -pv '>=app-office/openoffice-ximian-1.3.4'
    # emerge '>=app-office/openoffice-1.3.4'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-17
http://bugs.gentoo.org/show_bug.cgi?id=63556
http://www.openoffice.org/issues/show_bug.cgi?id=33357";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200410-17.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300956");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(11151);
 script_cve_id("CVE-2004-0752");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Gentoo Security Advisory GLSA 200410-17 (openoffice)");



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
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("lt 1.1.2", "ge 1.1.3"), vulnerable: make_list("eq 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("lt 1.1.2", "ge 1.1.3"), vulnerable: make_list("eq 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian", unaffected: make_list("lt 1.1.60", "ge 1.3.4"), vulnerable: make_list("eq 1.1.60", "eq 1.1.61"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
