#
#VID 9d3020e4-a2c4-11dd-a9f9-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 9d3020e4-a2c4-11dd-a9f9-0030843d3802
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
tag_insight = "The following package is affected: flyspray

CVE-2007-6461
Multiple cross-site scripting (XSS) vulnerabilities in index.php in
Flyspray 0.9.9 through 0.9.9.3 allow remote attackers to inject
arbitrary web script or HTML via (1) the query string in an index
action, related to the savesearch JavaScript function; and (2) the
details parameter in a details action, related to the History tab and
the getHistory JavaScript function.

CVE-2008-1165
Multiple cross-site scripting (XSS) vulnerabilities in Flyspray 0.9.9
through 0.9.9.4 allow remote attackers to inject arbitrary web script
or HTML via (1) a forced SQL error message or (2) old_value and
new_value database fields in task summaries, related to the
item_summary parameter in a details action in index.php.  NOTE: some of
these details are obtained from third party information.

CVE-2008-1166
Flyspray 0.9.9.4 generates different error messages depending on
whether the username is valid or invalid, which allows remote
attackers to enumerate usernames.  NOTE: the provenance of this
information is unknown; the details are obtained solely from third
party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/29215
http://www.vuxml.org/freebsd/9d3020e4-a2c4-11dd-a9f9-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303040");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
 script_cve_id("CVE-2007-6461", "CVE-2008-1165", "CVE-2008-1166");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("FreeBSD Ports: flyspray");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"flyspray");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.9.5.1")<0) {
    txt += 'Package flyspray version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
