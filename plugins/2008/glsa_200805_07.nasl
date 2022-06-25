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
tag_insight = "Multiple vulnerabilities have been discovered in components shipped with
LTSP which allow remote attackers to compromise terminal clients.";
tag_solution = "LTSP 4.2 is not maintained upstream in favor of version 5. Since version 5
is not yet available in Gentoo, the package has been masked. We recommend
that users unmerge LTSP:

    # emerge --unmerge net-misc/ltsp

If you have a requirement for Linux Terminal Servers, please either set up
a terminal server by hand or use one of the distributions that already
migrated to LTSP 5. If you want to contribute to the integration of LTSP 5
in Gentoo, or want to follow its development, find details in bug 177580.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200805-07
http://bugs.gentoo.org/show_bug.cgi?id=215699
http://www.gentoo.org/security/en/glsa/glsa-200705-02.xml
http://www.gentoo.org/security/en/glsa/glsa-200705-06.xml
http://www.gentoo.org/security/en/glsa/glsa-200705-22.xml
http://www.gentoo.org/security/en/glsa/glsa-200705-24.xml
http://www.gentoo.org/security/en/glsa/glsa-200710-06.xml
http://www.gentoo.org/security/en/glsa/glsa-200710-16.xml
http://www.gentoo.org/security/en/glsa/glsa-200710-30.xml
http://www.gentoo.org/security/en/glsa/glsa-200711-08.xml
http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml
https://bugs.gentoo.org/177580";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200805-07.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300095");
 script_cve_id("CVE-2006-3738","CVE-2007-1351","CVE-2007-1667","CVE-2007-2445","CVE-2007-2754","CVE-2007-3108","CVE-2007-4730","CVE-2007-4995","CVE-2007-5135","CVE-2007-5266","CVE-2007-5268","CVE-2007-5269","CVE-2007-5760","CVE-2007-5958","CVE-2007-6427","CVE-2007-6428","CVE-2007-6429","CVE-2008-0006");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_name("Gentoo Security Advisory GLSA 200805-07 (ltsp)");



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
if ((res = ispkgvuln(pkg:"net-misc/ltsp", unaffected: make_list(), vulnerable: make_list("lt 5.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
