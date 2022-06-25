#
#VID 71597e3e-f6b8-11dd-94d9-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 71597e3e-f6b8-11dd-94d9-0030843d3802
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
tag_insight = "The following package is affected: websvn

CVE-2008-5918
Cross-site scripting (XSS) vulnerability in the
getParameterisedSelfUrl function in index.php in WebSVN 2.0 and
earlier allows remote attackers to inject arbitrary web script or HTML
via the PATH_INFO.

CVE-2008-5919
Directory traversal vulnerability in rss.php in WebSVN 2.0 and
earlier, when magic_quotes_gpc is disabled, allows remote attackers to
overwrite arbitrary files via directory traversal sequences in the rev
parameter.

CVE-2009-0240
listing.php in WebSVN 2.0 and possibly 1.7 beta, when using an SVN
authz file, allows remote authenticated users to read changelogs or
diffs for restricted projects via a modified repname parameter.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/32338/
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191
http://www.gulftech.org/?node=research&article_id=00132-10202008
http://www.vuxml.org/freebsd/71597e3e-f6b8-11dd-94d9-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308231");
 script_version("$Revision: 4865 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2009-0240");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: websvn");



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
bver = portver(pkg:"websvn");
if(!isnull(bver) && revcomp(a:bver, b:"2.1.0")<0) {
    txt += 'Package websvn version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
