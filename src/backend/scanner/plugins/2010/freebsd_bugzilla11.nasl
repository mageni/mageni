#
#VID 8cbf4d65-af9a-11df-89b8-00151735203a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 8cbf4d65-af9a-11df-89b8-00151735203a
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
tag_insight = "The following package is affected: bugzilla

CVE-2010-2756
Search.pm in Bugzilla 2.19.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1
through 3.6.1, and 3.7 through 3.7.2 allows remote attackers to
determine the group memberships of arbitrary users via vectors
involving the Search interface, boolean charts, and group-based
pronouns.

CVE-2010-2757
The sudo feature in Bugzilla 2.22rc1 through 3.2.7, 3.3.1 through
3.4.7, 3.5.1 through 3.6.1, and 3.7 through 3.7.2 does not properly
send impersonation notifications, which makes it easier for remote
authenticated users to impersonate other users without discovery.

CVE-2010-2758
Bugzilla 2.17.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1 through
3.6.1, and 3.7 through 3.7.2 generates different error messages
depending on whether a product exists, which makes it easier for
remote attackers to guess product names via unspecified use of the (1)
Reports or (2) Duplicates page.

CVE-2010-2759
Bugzilla 2.23.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1 through
3.6.1, and 3.7 through 3.7.2, when PostgreSQL is used, does not
properly handle large integers in (1) bug and (2) attachment phrases,
which allows remote authenticated users to cause a denial of service
(bug invisibility) via a crafted comment.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.mozilla.org/show_bug.cgi?id=417048
https://bugzilla.mozilla.org/show_bug.cgi?id=450013
https://bugzilla.mozilla.org/show_bug.cgi?id=577139
https://bugzilla.mozilla.org/show_bug.cgi?id=519835
https://bugzilla.mozilla.org/show_bug.cgi?id=583690
http://www.vuxml.org/freebsd/8cbf4d65-af9a-11df-89b8-00151735203a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314573");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2756", "CVE-2010-2757", "CVE-2010-2758", "CVE-2010-2759");
 script_name("FreeBSD Ports: bugzilla");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"2.17.1")>0 && revcomp(a:bver, b:"3.6.2")<0) {
    txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
