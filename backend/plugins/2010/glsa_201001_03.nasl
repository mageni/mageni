#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "Multiple vulnerabilities were found in PHP, the worst of which leading to
    the remote execution of arbitrary code.";
tag_solution = "All PHP users should upgrade to the latest version. As PHP is
    statically linked against a vulnerable version of the c-client library
    when the imap or kolab USE flag is enabled (GLSA 200911-03), users
    should upgrade net-libs/c-client beforehand:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.12'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201001-03
http://bugs.gentoo.org/show_bug.cgi?id=249875
http://bugs.gentoo.org/show_bug.cgi?id=255121
http://bugs.gentoo.org/show_bug.cgi?id=260576
http://bugs.gentoo.org/show_bug.cgi?id=261192
http://bugs.gentoo.org/show_bug.cgi?id=266125
http://bugs.gentoo.org/show_bug.cgi?id=274670
http://bugs.gentoo.org/show_bug.cgi?id=280602
http://bugs.gentoo.org/show_bug.cgi?id=285434
http://bugs.gentoo.org/show_bug.cgi?id=292132
http://bugs.gentoo.org/show_bug.cgi?id=293888
http://bugs.gentoo.org/show_bug.cgi?id=297369
http://bugs.gentoo.org/show_bug.cgi?id=297370
http://www.gentoo.org/security/en/glsa/glsa-200911-03.xml";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201001-03.";

                                                                                
                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314161");
 script_version("$Revision: 8356 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-07 13:59:33 +0100 (Thu, 07 Jan 2010)");
 script_cve_id("CVE-2008-5498", "CVE-2008-5514", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658", "CVE-2008-5814", "CVE-2008-5844", "CVE-2008-7002", "CVE-2009-0754", "CVE-2009-1271", "CVE-2009-1272", "CVE-2009-2626", "CVE-2009-2687", "CVE-2009-3291");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 201001-03 (php)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.2.12"), vulnerable: make_list("lt 5.2.12"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
