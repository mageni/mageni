#
#VID df333ede-a8ce-11d8-9c6d-0020ed76ef5a
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
   linux-opera
   opera
   kdelibs

CVE-2004-0411
The URI handlers in Konqueror for KDE 3.2.2 and earlier do not
properly filter '-' characters that begin a hostname in a (1) telnet,
(2) rlogin, (3) ssh, or (4) mailto URI, which allows remote attackers
to manipulate the options that are passed to the associated programs,
possibly to read arbitrary files or execute arbitrary code.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.idefense.com/application/poi/display?id=104&type=vulnerabilities
http://www.kde.org/info/security/advisory-20040517-1.txt
http://freebsd.kde.org/index.php#n20040517
http://www.vuxml.org/freebsd/df333ede-a8ce-11d8-9c6d-0020ed76ef5a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301092");
 script_version("$Revision: 4128 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-22 07:37:51 +0200 (Thu, 22 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(10358);
 script_cve_id("CVE-2004-0411");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: linux-opera, opera");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.50")<0) {
    txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.50")<0) {
    txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.2_3")<0) {
    txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
