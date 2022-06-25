#
#VID 018a84d0-2548-11df-b4a3-00e0815b8da8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 018a84d0-2548-11df-b4a3-00e0815b8da8
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
tag_insight = "The following package is affected: sudo

CVE-2010-0426
sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a
pseudo-command is enabled, permits a match between the name of the
pseudo-command and the name of an executable file in an arbitrary
directory, which allows local users to gain privileges via a crafted
executable file, as demonstrated by a file named sudoedit in a user's
home directory.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.sudo.ws/pipermail/sudo-announce/2010-February/000092.html
http://www.sudo.ws/sudo/alerts/sudoedit_escalate.html
http://secunia.com/advisories/38659
http://www.vuxml.org/freebsd/018a84d0-2548-11df-b4a3-00e0815b8da8.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314532");
 script_version("$Revision: 8469 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
 script_cve_id("CVE-2010-0426");
 script_bugtraq_id(38362);
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: sudo");



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
bver = portver(pkg:"sudo");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2.4")<0) {
    txt += 'Package sudo version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
