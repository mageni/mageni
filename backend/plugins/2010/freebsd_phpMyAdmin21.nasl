#
#VID 274922b8-ad20-11df-af1f-00e0814cab4e
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 274922b8-ad20-11df-af1f-00e0814cab4e
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
tag_insight = "The following packages are affected:
   phpMyAdmin
   phpMyAdmin211

CVE-2010-3056
Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
2.11.x before 2.11.10.1 and 3.x before 3.3.5.1 allow remote attackers
to inject arbitrary web script or HTML via vectors related to (1)
db_search.php, (2) db_sql.php, (3) db_structure.php, (4)
js/messages.php, (5) libraries/common.lib.php, (6)
libraries/database_interface.lib.php, (7)
libraries/dbi/mysql.dbi.lib.php, (8) libraries/dbi/mysqli.dbi.lib.php,
(9) libraries/db_info.inc.php, (10) libraries/sanitizing.lib.php, (11)
libraries/sqlparser.lib.php, (12) server_databases.php, (13)
server_privileges.php, (14) setup/config.php, (15) sql.php, (16)
tbl_replace.php, and (17) tbl_sql.php.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.phpmyadmin.net/home_page/security/PMASA-2010-5.php
http://www.vuxml.org/freebsd/274922b8-ad20-11df-af1f-00e0814cab4e.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314736");
 script_version("$Revision: 8338 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2010-3056");
 script_name("FreeBSD Ports: phpMyAdmin");



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
bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.5.1")<0) {
    txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"phpMyAdmin211");
if(!isnull(bver) && revcomp(a:bver, b:"2.11.10.1")<0) {
    txt += 'Package phpMyAdmin211 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
