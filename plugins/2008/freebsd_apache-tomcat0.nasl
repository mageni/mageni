#
#VID 872623af-39ec-11dc-b8cc-000fea449b8a
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
   apache-tomcat
   tomcat
   jakarta-tomcat

CVE-2005-2090
Jakarta Tomcat 5.0.19 (Coyote/1.1) and Tomcat 4.1.24 (Coyote/1.0)
allows remote attackers to poison the web cache, bypass web
application firewall protection, and conduct XSS attacks via an HTTP
request with both a 'Transfer-Encoding: chunked' header and a
Content-Length header, which causes Tomcat to incorrectly handle and
forward the body of the request in a way that causes the receiving
server to process it as a separate HTTP request, aka 'HTTP Request
Smuggling.'";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304334");
 script_version("$Revision: 4075 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-15 15:13:05 +0200 (Thu, 15 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-2090", "CVE-2007-0450", "CVE-2007-1358");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("FreeBSD Ports: apache-tomcat");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
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
bver = portver(pkg:"apache-tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.0")>=0 && revcomp(a:bver, b:"4.1.36")<0) {
    txt += 'Package apache-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.11")<0) {
    txt += 'Package apache-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0")>0 && revcomp(a:bver, b:"5.5.23")<0) {
    txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"jakarta-tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")>=0 && revcomp(a:bver, b:"4.1.0")<0) {
    txt += 'Package jakarta-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0")>0 && revcomp(a:bver, b:"5.5.23")<0) {
    txt += 'Package jakarta-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
