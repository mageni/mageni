#
#VID a89b76a7-f6bd-11dd-94d9-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a89b76a7-f6bd-11dd-94d9-0030843d3802
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: amaya

CVE-2008-5282
Multiple stack-based buffer overflows in W3C Amaya Web Browser 10.0.1
allow remote attackers to execute arbitrary code via (1) a link with a
long HREF attribute, and (2) a DIV tag with a long id attribute.

CVE-2009-0323
Multiple stack-based buffer overflows in W3C Amaya Web Browser 10.0
and 11.0 allow remote attackers to execute arbitrary code via (1) a
long type parameter in an input tag, which is not properly handled by
the EndOfXmlAttributeValue function; (2) an 'HTML GI' in a start tag,
which is not properly handled by the ProcessStartGI function; and
unspecified vectors in (3) html2thot.c and (4) xml2thot.c, related to
the msgBuffer variable.  NOTE: these are different vectors than
CVE-2008-6005.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/32848/
http://www.bmgsec.com.au/advisory/41/
http://www.bmgsec.com.au/advisory/40/
http://milw0rm.com/exploits/7467
http://www.coresecurity.com/content/amaya-buffer-overflows
http://www.vuxml.org/freebsd/a89b76a7-f6bd-11dd-94d9-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308498");
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2008-5282", "CVE-2009-0323");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: amaya");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"amaya");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package amaya version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
