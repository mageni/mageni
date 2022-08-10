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
tag_insight = "Remote buffer overflow vulnerabilities have been found in Courier-IMAP and
Courier MTA. These exploits may allow the execution of arbitrary code,
allowing unauthorized access to a vulnerable system.";
tag_solution = "All users should upgrade to current versions of the affected packages:

    # emerge sync

    # emerge -pv '>=net-mail/courier-imap-3.0.0'
    # emerge '>=net-mail/courier-imap-3.0.0'

    # ** Or; depending on your installation... **

    # emerge -pv '>=net-mail/courier-0.45'
    # emerge '>=net-mail/courier-0.45'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-06
http://bugs.gentoo.org/show_bug.cgi?id=45584";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200403-06.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302823");
 script_version("$Revision: 7585 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(9845);
 script_cve_id("CVE-2004-0224");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200403-06 (Courier)");



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
if ((res = ispkgvuln(pkg:"net-mail/courier-imap", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/courier", unaffected: make_list("ge 0.45"), vulnerable: make_list("lt 0.45"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
