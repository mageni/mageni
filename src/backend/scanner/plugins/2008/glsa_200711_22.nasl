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
tag_insight = "Poppler and various KDE components are vulnerable to multiple memory
management issues possibly resulting in the execution of arbitrary code.";
tag_solution = "All Poppler users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/poppler-0.6.1-r1'

All KPDF users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.5.7-r3'

All KDE Graphics Libraries users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.5.7-r3'

All KWord users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/kword-1.6.3-r2'

All KOffice users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.6.3-r2'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-22
http://bugs.gentoo.org/show_bug.cgi?id=196735
http://bugs.gentoo.org/show_bug.cgi?id=198409";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200711-22.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302875");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200711-22 (poppler koffice kword kdegraphics kpdf)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"app-text/poppler", unaffected: make_list("ge 0.6.1-r1"), vulnerable: make_list("lt 0.6.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kpdf", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/kword", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/koffice", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
