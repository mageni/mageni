#
#VID 708c65a5-7c58-11de-a994-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 708c65a5-7c58-11de-a994-0030843d3802
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
tag_insight = "The following package is affected: mono

CVE-2009-0217
The design of the W3C XML Signature Syntax and Processing (XMLDsig)
recommendation, as implemented in products including (1) the Oracle
Security Developer Tools component in Oracle Application Server
10.1.2.3, 10.1.3.4, and 10.1.4.3IM; (2) the WebLogic Server component
in BEA Product Suite 10.3, 10.0 MP1, 9.2 MP3, 9.1, 9.0, and 8.1 SP6;
(3) Mono before 2.4.2.2; (4) XML Security Library before 1.2.12; (5)
IBM WebSphere Application Server Versions 6.0 through 6.0.2.33, 6.1
through 6.1.0.23, and 7.0 through 7.0.0.1; and other products uses a
parameter that defines an HMAC truncation length (HMACOutputLength)
but does not require a minimum for this length, which allows attackers
to spoof HMAC-based signatures and bypass authentication by specifying
a truncation length with a small number of bits.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/35852/
http://www.kb.cert.org/vuls/id/466161
http://www.vuxml.org/freebsd/708c65a5-7c58-11de-a994-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306834");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-0217");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("FreeBSD Ports: mono");



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
bver = portver(pkg:"mono");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.2.2")<0) {
    txt += 'Package mono version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
