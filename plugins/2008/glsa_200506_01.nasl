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
tag_insight = "Various utilities from the GNU Binutils and elfutils packages are
vulnerable to a heap based buffer overflow, potentially resulting in the
execution of arbitrary code.";
tag_solution = "All GNU Binutils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/binutils

All elfutils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/elfutils-0.108'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200506-01
http://bugs.gentoo.org/show_bug.cgi?id=91398
http://bugs.gentoo.org/show_bug.cgi?id=91817";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200506-01.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301980");
 script_cve_id("CVE-2005-1704");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_name("Gentoo Security Advisory GLSA 200506-01 (binutils)");



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
if ((res = ispkgvuln(pkg:"dev-libs/elfutils", unaffected: make_list("ge 0.108"), vulnerable: make_list("lt 0.108"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-devel/binutils", unaffected: make_list("rge 2.14.90.0.8-r3", "rge 2.15.90.0.1.1-r5", "rge 2.15.90.0.3-r5", "rge 2.15.91.0.2-r2", "rge 2.15.92.0.2-r10", "ge 2.16-r1"), vulnerable: make_list("lt 2.16-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
