#
#VID 27d78386-d35f-11dd-b800-001b77d09812
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 27d78386-d35f-11dd-b800-001b77d09812
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
tag_insight = "The following packages are affected:
   awstats
   awstats-devel

CVE-2008-3714
Cross-site scripting (XSS) vulnerability in awstats.pl in AWStats 6.8
allows remote attackers to inject arbitrary web script or HTML via the
query_string, a different vulnerability than CVE-2006-3681 and
CVE-2006-1945.

CVE-2008-5080
awstats.pl in AWStats 6.8 and earlier does not properly remove quote
characters, which allows remote attackers to conduct cross-site
scripting (XSS) attacks via the query_string parameter.  NOTE: this
issue exists because of an incomplete fix for CVE-2008-3714.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/31519
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432
http://www.vuxml.org/freebsd/27d78386-d35f-11dd-b800-001b77d09812.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309283");
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
 script_cve_id("CVE-2008-3714", "CVE-2008-5080");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("FreeBSD Ports: awstats");



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
bver = portver(pkg:"awstats");
if(!isnull(bver) && revcomp(a:bver, b:"6.9,1")<0) {
    txt += 'Package awstats version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"awstats-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package awstats-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
