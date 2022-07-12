#
#VID daf045d7-b211-11dd-a987-000c29ca8953
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID daf045d7-b211-11dd-a987-000c29ca8953
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
tag_insight = "The following packages are affected:
   net-snmp
   net-snmp53

CVE-2008-4309
Integer overflow in the netsnmp_create_subtree_cache function in
agent/snmp_agent.c in net-snmp 5.4 before 5.4.2.1, 5.3 before 5.3.2.3,
and 5.2 before 5.2.5.1 allows remote attackers to cause a denial of
service (crash) via a crafted SNMP GETBULK request, which triggers a
heap-based buffer overflow,  related to the number of responses or
repeats.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://sourceforge.net/forum/forum.php?forum_id=882903
http://www.openwall.com/lists/oss-security/2008/10/31/1
http://net-snmp.svn.sourceforge.net/viewvc/net-snmp/tags/Ext-5-2-5-1/net-snmp/agent/snmp_agent.c?r1=17271&r2=17272&pathrev=17272
http://www.vuxml.org/freebsd/daf045d7-b211-11dd-a987-000c29ca8953.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303396");
 script_version("$Revision: 4144 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-26 07:28:56 +0200 (Mon, 26 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
 script_cve_id("CVE-2008-4309");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Ports: net-snmp");



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
bver = portver(pkg:"net-snmp");
if(!isnull(bver) && revcomp(a:bver, b:"5.4.2.1")<0) {
    txt += 'Package net-snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"net-snmp53");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.2.3")<0) {
    txt += 'Package net-snmp53 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
