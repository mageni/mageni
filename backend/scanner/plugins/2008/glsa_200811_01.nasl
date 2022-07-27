#
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
tag_insight = "Multiple vulnerabilities have been discovered in Opera, allowing for the
execution of arbitrary code.";
tag_solution = "All Opera users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.62'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200811-01
http://bugs.gentoo.org/show_bug.cgi?id=235298
http://bugs.gentoo.org/show_bug.cgi?id=240500
http://bugs.gentoo.org/show_bug.cgi?id=243060
http://bugs.gentoo.org/show_bug.cgi?id=244980";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200811-01.";

                                                                                
                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303851");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
 script_cve_id("CVE-2008-4195", "CVE-2008-4196", "CVE-2008-4197", "CVE-2008-4198", "CVE-2008-4199", "CVE-2008-4200", "CVE-2008-4292", "CVE-2008-4694", "CVE-2008-4695", "CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4794", "CVE-2008-4795");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200811-01 (opera)");



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
if ((res = ispkgvuln(pkg:"www-client/opera", unaffected: make_list("ge 9.62"), vulnerable: make_list("lt 9.62"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
