#
#VID 8ad1c404-3e78-11df-a5a1-0050568452ac
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 8ad1c404-3e78-11df-a5a1-0050568452ac
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
tag_insight = "The following package is affected: ZendFramework";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://dojotoolkit.org/blog/post/dylan/2010/03/dojo-security-advisory/
http://framework.zend.com/security/advisory/ZF2010-07
http://osdir.com/ml/bugtraq.security/2010-03/msg00133.html
http://packetstormsecurity.org/1003-exploits/dojo-xss.txt
http://secunia.com/advisories/38964
http://www.gdssecurity.com/l/b/2010/03/12/multiple-dom-based-xss-in-dojo-toolkit-sdk/
http://www.vuxml.org/freebsd/8ad1c404-3e78-11df-a5a1-0050568452ac.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313999");
 script_version("$Revision: 8485 $");
 script_cve_id("CVE-2010-2272", "CVE-2010-2273", "CVE-2010-2274",
               "CVE-2010-2275", "CVE-2010-2276");
 script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: ZendFramework");



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
bver = portver(pkg:"ZendFramework");
if(!isnull(bver) && revcomp(a:bver, b:"1.10.3")<0) {
    txt += 'Package ZendFramework version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
