#
#VID 3efc106e-c451-11dd-a721-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 3efc106e-c451-11dd-a721-0030843d3802
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
tag_insight = "The following package is affected: dovecot-managesieve

CVE-2008-5301
Directory traversal vulnerability in the ManageSieve implementation in
Dovecot 1.0.15, 1.1, and 1.2 allows remote attackers to read and
modify arbitrary .sieve files via a '..' (dot dot) in a script name.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.vupen.com/english/advisories/2008/3190
http://secunia.com/Advisories/32768/
http://dovecot.org/list/dovecot/2008-November/035259.html
http://www.vuxml.org/freebsd/3efc106e-c451-11dd-a721-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301087");
 script_version("$Revision: 4078 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-16 07:34:17 +0200 (Fri, 16 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
 script_cve_id("CVE-2008-5301");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_name("FreeBSD Ports: dovecot-managesieve");



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
bver = portver(pkg:"dovecot-managesieve");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
    txt += 'Package dovecot-managesieve version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.11.0")>=0 && revcomp(a:bver, b:"0.11.1")<0) {
    txt += 'Package dovecot-managesieve version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
