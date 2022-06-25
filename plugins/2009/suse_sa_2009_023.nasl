# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_023.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SA:2009:023 (MozillaFirefox)
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
tag_insight = "The Mozilla Firefox Browser was refreshed to the current MOZILLA_1_8
branch state around fix level 2.0.0.22, backporting various security
fixes from the Firefox 3.0.8 browser version.

Security issues identified as being fixed are:
MFSA 2009-01 / CVE-2009-0352 / CVE-2009-0353: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-07 / CVE-2009-0772 / CVE-2009-0774: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher Georgi
Guninski reported that a website could use nsIRDFService and a
cross-domain redirect to steal arbitrary XML data from another domain,
a violation of the same-origin policy. This vulnerability could be used
by a malicious website to steal private data from users authenticated
to the redirected website.

MFSA 2009-10 / CVE-2009-0040: Google security researcher Tavis
Ormandy reported several memory safety hazards to the libpng project,
an external library used by Mozilla to render PNG images. These
vulnerabilities could be used by a malicious website to crash a
victim's browser and potentially execute arbitrary code on their
computer. libpng was upgraded to version 1.2.35 which contains fixes
for these flaws.

MFSA 2009-12 / CVE-2009-1169: Security researcher Guido Landi
discovered that a XSL stylesheet could be used to crash the browser
during a XSL transformation. An attacker could potentially use this
crash to run arbitrary code on a victim's computer.
This vulnerability was also previously reported as a stability problem
by Ubuntu community member, Andre. Ubuntu community member Michael
Rooney reported Andre's findings to Mozilla, and Mozilla community
member Martin helped reduce Andre's original test case and contributed
a patch to fix the vulnerability.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:023";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:023.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309717");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
 script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SuSE Security Advisory SUSE-SA:2009:023 (MozillaFirefox)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.21post~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.21post~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
