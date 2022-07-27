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
tag_insight = "Several vulnerabilities in Mozilla Thunderbird allow attacks ranging from
script execution with elevated privileges to information leaks.";
tag_solution = "All Mozilla Thunderbird users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-1.0.8'

All Mozilla Thunderbird binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-bin-1.0.8'

Note: There is no stable fixed version for the ALPHA architecture yet.
Users of Mozilla Thunderbird on ALPHA should consider unmerging it until
such a version is available.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200605-09
http://bugs.gentoo.org/show_bug.cgi?id=130888
http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200605-09.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301539");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200605-09 (mozilla-thunderbird)");



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
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
