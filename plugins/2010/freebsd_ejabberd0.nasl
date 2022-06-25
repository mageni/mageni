#
#VID a04a3c13-4932-11df-83fb-0015587e2cc1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a04a3c13-4932-11df-83fb-0015587e2cc1
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
tag_insight = "The following package is affected: ejabberd

CVE-2010-0305
ejabberd_c2s.erl in ejabberd before 2.1.3 allows remote attackers to
cause a denial of service (daemon crash) via a large number of c2s
(aka client2server) messages that trigger a queue overload.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/38337
http://support.process-one.net/browse/EJAB-1173
http://www.openwall.com/lists/oss-security/2010/01/29/1
http://xforce.iss.net/xforce/xfdb/56025
http://www.vuxml.org/freebsd/a04a3c13-4932-11df-83fb-0015587e2cc1.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314362");
 script_version("$Revision: 8244 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2010-0305");
 script_bugtraq_id(38003);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Ports: ejabberd");



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
bver = portver(pkg:"ejabberd");
if(!isnull(bver) && revcomp(a:bver, b:"2.1.3")<0) {
    txt += 'Package ejabberd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
