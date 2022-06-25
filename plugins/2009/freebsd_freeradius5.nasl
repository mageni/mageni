#
#VID 1b3f854b-e4bd-11de-b276-000d8787e1be
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1b3f854b-e4bd-11de-b276-000d8787e1be
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
tag_insight = "The following package is affected: freeradius

CVE-2009-3111
The rad_decode function in FreeRADIUS before 1.1.8 allows remote
attackers to cause a denial of service (radiusd crash) via zero-length
Tunnel-Password attributes.  NOTE: this is a regression error related
to CVE-2003-0967.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";

tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309747");
 script_version("$Revision: 5656 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-21 12:03:12 +0100 (Tue, 21 Mar 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-3111");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Ports: freeradius");

 script_xref(name:"URL", value:"http://freeradius.org/security.html");
 script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9642");
 script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/1b3f854b-e4bd-11de-b276-000d8787e1be.html");

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
bver = portver(pkg:"freeradius");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.8")<0) {
    txt += 'Package freeradius version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
