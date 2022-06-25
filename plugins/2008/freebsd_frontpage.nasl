#
#VID c0171f59-ea8a-11da-be02-000c6ec775d9
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
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
tag_insight = "The following packages are affected:
   frontpage
   mod_frontpage13
   mod_frontpage20
   mod_frontpage21
   mod_frontpage22

CVE-2006-0015
Cross-site scripting (XSS) vulnerability in
_vti_bin/_vti_adm/fpadmdll.dll in Microsoft FrontPage Server
Extensions 2002 and SharePoint Team Services allows remote attackers
to inject arbitrary web script or HTML, then leverage the attack to
execute arbitrary programs or create new accounts, via the (1)
operation, (2) command, and (3) name parameters.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.microsoft.com/technet/security/bulletin/MS06-017.mspx
http://www.rtr.com/fpsupport/fpse_release_may_2_2006.htm
http://marc.theaimsgroup.com/?l=bugtraq&m=114487846329000
http://www.vuxml.org/freebsd/c0171f59-ea8a-11da-be02-000c6ec775d9.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300638");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(17452);
 script_cve_id("CVE-2006-0015");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: frontpage -- cross site scripting vulnerability");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"frontpage");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.2.4803")<0) {
    txt += 'Package frontpage version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_frontpage13");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.2.4803")<0) {
    txt += 'Package mod_frontpage13 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_frontpage20");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.2.4803")<0) {
    txt += 'Package mod_frontpage20 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_frontpage21");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.2.4803")<0) {
    txt += 'Package mod_frontpage21 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_frontpage22");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.2.4803")<0) {
    txt += 'Package mod_frontpage22 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
