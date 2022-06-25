#
#VID 738f8f9e-d661-11dd-a765-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 738f8f9e-d661-11dd-a765-0030843d3802
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

CVE-2008-2079
MySQL 4.1.x before 4.1.24, 5.0.x before 5.0.60, 5.1.x before 5.1.24,
and 6.0.x before 6.0.5 allows local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are within the
MySQL home data directory, which can point to tables that are created
in the future.
CVE-2008-4097
MySQL 5.0.51a allows local users to bypass certain privilege checks by
calling CREATE TABLE on a MyISAM table with modified (1) DATA
DIRECTORY or (2) INDEX DIRECTORY arguments that are associated with
symlinks within pathnames for subdirectories of the MySQL home data
directory, which are followed when tables are created in the future.
NOTE: this vulnerability exists because of an incomplete fix for
CVE-2008-2079.
CVE-2008-4098
MySQL before 5.0.67 allows local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are originally
associated with pathnames without symlinks, and that can point to
tables created at a future time at which a pathname is modified to
contain a symlink to a subdirectory of the MySQL home data directory.
NOTE: this vulnerability exists because of an incomplete fix for
CVE-2008-4097.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugs.mysql.com/bug.php?id=32167
http://dev.mysql.com/doc/refman/4.1/en/news-4-1-25.html
http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-75.html
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-28.html
http://dev.mysql.com/doc/refman/6.0/en/news-6-0-6.html
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=480292#25
http://www.vuxml.org/freebsd/738f8f9e-d661-11dd-a765-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309299");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-01-02 18:22:54 +0100 (Fri, 02 Jan 2009)");
 script_cve_id("CVE-2008-2079", "CVE-2008-4097", "CVE-2008-4098");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
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
if(!isnull(bver) && revcomp(a:bver, b:"4.1")>=0 && revcomp(a:bver, b:"4.1.25")<0) {
    txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.0")>=0 && revcomp(a:bver, b:"5.0.75")<0) {
    txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.1")>=0 && revcomp(a:bver, b:"5.1.28")<0) {
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
