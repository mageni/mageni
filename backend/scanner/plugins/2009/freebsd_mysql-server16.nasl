#
#VID 66a770b4-e008-11dd-a765-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 66a770b4-e008-11dd-a765-0030843d3802
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
tag_insight = "The following package is affected: mysql-server

CVE-2008-3963
MySQL 5.0 before 5.0.66, 5.1 before 5.1.26, and 6.0 before 6.0.6 does
not properly handle a b'' (b single-quote single-quote) token, aka an
empty bit-string literal, which allows remote attackers to cause a
denial of service (daemon crash) by using this token in a SQL
statement.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugs.mysql.com/bug.php?id=35658
http://dev.mysql.com/doc/refman/5.0/en/releasenotes-es-5-0-66.html
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html
http://dev.mysql.com/doc/refman/6.0/en/news-6-0-6.html
http://secunia.com/advisories/31769
http://www.vuxml.org/freebsd/66a770b4-e008-11dd-a765-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307570");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2008-3963");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_name("FreeBSD Ports: mysql-server");



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
bver = portver(pkg:"mysql-server");
if(!isnull(bver) && revcomp(a:bver, b:"5.0")>=0 && revcomp(a:bver, b:"5.0.66")<0) {
    txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.1")>=0 && revcomp(a:bver, b:"5.1.26")<0) {
    txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"6.0")>=0 && revcomp(a:bver, b:"6.0.6")<0) {
    txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
