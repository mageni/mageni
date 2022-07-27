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
tag_insight = "Samba contains two buffer overflow vulnerabilities potentially resulting in
the execution of arbitrary code, one of which is currently unfixed.";
tag_solution = "The Samba 3.0.27 ebuild that resolves both vulnerabilities is currently
masked due to a regression in the patch for the second vulnerability.

Since no working patch exists yet, all Samba users should upgrade to
3.0.26a-r2, which contains a fix for the first vulnerability
(CVE-2007-5398):

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/samba-3.0.26a-r2'

An update to this temporary GLSA will be sent when the second
vulnerability will be fixed.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-29
http://bugs.gentoo.org/show_bug.cgi?id=197519";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200711-29.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303439");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2007-4572", "CVE-2007-5398");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200711-29 (samba)");



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
if ((res = ispkgvuln(pkg:"net-fs/samba", unaffected: make_list("ge 3.0.26a-r2"), vulnerable: make_list("lt 3.0.26a-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
