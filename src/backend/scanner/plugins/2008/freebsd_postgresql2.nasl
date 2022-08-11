#
#VID 17f53c1d-2ae9-11db-a6e2-000e0c2e438a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
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
   postgresql
   postgresql-server
   ja-postgresql

CVE-2006-2313
PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before
7.4.13, 7.3.x before 7.3.15, and earlier versions allows
context-dependent attackers to bypass SQL injection protection methods
in applications via invalid encodings of multibyte characters, aka one
variant of 'Encoding-Based SQL Injection.'

CVE-2006-2314
PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before
7.4.13, 7.3.x before 7.3.15, and earlier versions allows
context-dependent attackers to bypass SQL injection protection methods
in applications that use multibyte encodings that allow the '\'
(backslash) byte 0x5c to be the trailing byte of a multibyte
character, such as SJIS, BIG5, GBK, GB18030, and UHC, which cannot be
handled correctly by a client that does not understand multibyte
encodings, aka a second variant of 'Encoding-Based SQL Injection.'
NOTE: it could be argued that this is a class of issue related to
interaction errors between the client and PostgreSQL, but a CVE has
been assigned since PostgreSQL is treating this as a preventative
measure against this class of problem.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.postgresql.org/docs/techdocs.50
http://www.vuxml.org/freebsd/17f53c1d-2ae9-11db-a6e2-000e0c2e438a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301637");
 script_version("$Revision: 4164 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-28 09:03:16 +0200 (Wed, 28 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");
 script_bugtraq_id(18092);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: postgresql, postgresql-server, ja-postgresql");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.15")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.13")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.8")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1.0")>=0 && revcomp(a:bver, b:"8.1.4")<0) {
    txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"postgresql-server");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.15")<0) {
    txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.13")<0) {
    txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.8")<0) {
    txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1.0")>=0 && revcomp(a:bver, b:"8.1.4")<0) {
    txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.15")<0) {
    txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.13")<0) {
    txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.8")<0) {
    txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1.0")>=0 && revcomp(a:bver, b:"8.1.4")<0) {
    txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
