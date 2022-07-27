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
tag_insight = "There are multiple vulnerabilities in tcpdump and libpcap related to
parsing of ISAKMP packets.";
tag_solution = "All tcpdump users should upgrade to the latest available version.
ADDITIONALLY, the net-libs/libpcap package should be upgraded.

    # emerge sync

    # emerge -pv '>=net-libs/libpcap-0.8.3-r1'
'>=net-analyzer/tcpdump-3.8.3-r1'
    # emerge '>=net-libs/libpcap-0.8.3-r1'
'>=net-analyzer/tcpdump-3.8.3-r1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200404-03
http://bugs.gentoo.org/show_bug.cgi?id=38206
http://bugs.gentoo.org/show_bug.cgi?id=46258
http://www.rapid7.com/advisories/R7-0017.html
http://rhn.redhat.com/errata/RHSA-2004-008.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200404-03.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301044");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2003-0989");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200404-03 (tcpdump)");



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
if ((res = ispkgvuln(pkg:"net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r1"), vulnerable: make_list("le 3.8.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/libpcap", unaffected: make_list("ge 0.8.3-r1"), vulnerable: make_list("le 0.8.1-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
