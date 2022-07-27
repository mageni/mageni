#
#VID 6a523dba-eeab-11dd-ab4f-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6a523dba-eeab-11dd-ab4f-0030843d3802
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
tag_insight = "The following package is affected: moinmoin

CVE-2009-0260
Multiple cross-site scripting (XSS) vulnerabilities in
action/AttachFile.py in MoinMoin before 1.8.1 allow remote attackers
to inject arbitrary web script or HTML via an AttachFile action to the
WikiSandBox component with (1) the rename parameter or (2) the drawing
parameter (aka the basename variable).

CVE-2009-0312
Cross-site scripting (XSS) vulnerability in the antispam feature
(security/antispam.py) in MoinMoin 1.7 and 1.8.1 allows remote
attackers to inject arbitrary web script or HTML via crafted,
disallowed content.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/33593/
http://hg.moinmo.in/moin/1.8/file/c76d50dac855
http://hg.moinmo.in/moin/1.8/rev/89b91bf87dad
http://moinmo.in/SecurityFixes#moin1.8.1
http://www.vuxml.org/freebsd/6a523dba-eeab-11dd-ab4f-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310776");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2009-0260", "CVE-2009-0312");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("FreeBSD Ports: moinmoin");



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
bver = portver(pkg:"moinmoin");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.1")<0) {
    txt += 'Package moinmoin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
