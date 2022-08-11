#
#VID e19e74a4-a712-11df-b234-001b2134ef46
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e19e74a4-a712-11df-b234-001b2134ef46
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
tag_insight = "The following packages are affected:
   linux-flashplugin
   linux-f8-flashplugin
   linux-f10-flashplugin

CVE-2010-0209
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-2213, CVE-2010-2214, and
CVE-2010-2216.
CVE-2010-2188
Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64, and
Adobe AIR before 2.0.2.12610, allows attackers to cause a denial of
service (memory corruption) or possibly execute arbitrary code by
calling the ActionScript native object 2200 connect method multiple
times with different arguments, a different vulnerability than
CVE-2010-2160, CVE-2010-2165, CVE-2010-2166, CVE-2010-2171,
CVE-2010-2175, CVE-2010-2176, CVE-2010-2177, CVE-2010-2178,
CVE-2010-2180, CVE-2010-2182, CVE-2010-2184, and CVE-2010-2187.
CVE-2010-2213
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2214, and
CVE-2010-2216.
CVE-2010-2214
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2213, and
CVE-2010-2216.
CVE-2010-2215
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to trick a user into (1)
selecting a link or (2) completing a dialog, related to a
'click-jacking' issue.
CVE-2010-2216
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2213, and
CVE-2010-2214.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.adobe.com/support/security/bulletins/apsb10-16.html
http://www.vuxml.org/freebsd/e19e74a4-a712-11df-b234-001b2134ef46.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.315114");
 script_version("$Revision: 8244 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0209", "CVE-2010-2188", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215", "CVE-2010-2216");
 script_name("FreeBSD Ports: linux-flashplugin");



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
bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r280")<0) {
    txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-f8-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.1r82")<0) {
    txt += 'Package linux-f8-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.1r82")<0) {
    txt += 'Package linux-f10-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
