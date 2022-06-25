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
tag_insight = "Multiple vulnerabilities were discovered in PTeX, possibly allowing the
execution of arbitrary code or overwriting arbitrary files.";
tag_solution = "All PTeX users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ptex-3.1.10_p20071203'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200805-13
http://bugs.gentoo.org/show_bug.cgi?id=196673
http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml
http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml
http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml
http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml
http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml
http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200805-13.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300248");
 script_cve_id("CVE-2007-0650","CVE-2007-2756","CVE-2007-3387","CVE-2007-3472","CVE-2007-3473","CVE-2007-3474","CVE-2007-3475","CVE-2007-3476","CVE-2007-3477","CVE-2007-3478","CVE-2007-4033","CVE-2007-4352","CVE-2007-5392","CVE-2007-5393","CVE-2007-5935","CVE-2007-5936","CVE-2007-5937");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_name("Gentoo Security Advisory GLSA 200805-13 (ptex)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"app-text/ptex", unaffected: make_list("ge 3.1.10_p20071203"), vulnerable: make_list("lt 3.1.10_p20071203"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
