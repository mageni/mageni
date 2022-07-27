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
tag_insight = "Several format string vulnerabilities are present in the Neon library
included in OpenOffice.org, allowing remote execution of arbitrary code
when connected to an untrusted WebDAV server.";
tag_solution = "There is no Ximian OpenOffice.org binary version including the fix yet. All
users of the openoffice-ximian-bin package making use of the WebDAV
openoffice-ximian source-based package should:

# emerge sync
# emerge -pv '>=app-office/openoffice-VERSION'
# emerge '>=app-office/openoffice-VERSION'

openoffice users on x86 should use version: 1.1.1-r1
openoffice users on sparc should use version: 1.1.0-r3
openoffice users on ppc should use version: 1.0.3-r1
openoffice-ximian users should use version: 1.1.51-r1
openoffice-bin users should use version: 1.1.2

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200405-04
http://bugs.gentoo.org/show_bug.cgi?id=47926
http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200405-04.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303803");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(10136);
 script_cve_id("CVE-2004-0179");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200405-04 (openoffice)");



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
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.1.1-r1"), vulnerable: make_list("le 1.1.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.0.3-r2"), vulnerable: make_list("le 1.0.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.1.0-r4"), vulnerable: make_list("le 1.1.0-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian", unaffected: make_list("ge 1.1.51-r1"), vulnerable: make_list("le 1.1.51"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian-bin", unaffected: make_list(), vulnerable: make_list("le 1.1.52"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
