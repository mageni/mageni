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
tag_insight = "KPdf and KWord both include vulnerable Xpdf code to handle PDF files,
making them vulnerable to the execution of arbitrary code.";
tag_solution = "All kdegraphics users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.4.3-r3'

All Kpdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.4.3-r3'

All KOffice users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.4.2-r6'

All KWord users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/kword-1.4.2-r6'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200601-02
http://bugs.gentoo.org/show_bug.cgi?id=114429
http://bugs.gentoo.org/show_bug.cgi?id=115851
http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml
http://www.kde.org/info/security/advisory-20051207-2.txt";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200601-02.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303177");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200601-02 (kdegraphics, kpdf, koffice, kword)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("ge 3.4.3-r3"), vulnerable: make_list("lt 3.4.3-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kpdf", unaffected: make_list("ge 3.4.3-r3"), vulnerable: make_list("lt 3.4.3-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/koffice", unaffected: make_list("ge 1.4.2-r6"), vulnerable: make_list("lt 1.4.2-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/kword", unaffected: make_list("ge 1.4.2-r6"), vulnerable: make_list("lt 1.4.2-r6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
