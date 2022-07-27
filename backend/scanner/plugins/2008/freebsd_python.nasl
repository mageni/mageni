#
#VID 6afa87d3-764b-11d9-b0e7-0000e249a0a2
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
   python
   python23
   python22
   python-devel

CVE-2005-0089
The SimpleXMLRPCServer library module in Python 2.2, 2.3 before 2.3.5,
and 2.4, when used by XML-RPC servers that use the register_instance
method to register an object without a _dispatch method, allows remote
attackers to read or modify globals of the associated module, and
possibly execute arbitrary code, via dotted attributes.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.python.org/security/PSF-2005-001/
http://www.vuxml.org/freebsd/6afa87d3-764b-11d9-b0e7-0000e249a0a2.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303223");
 script_version("$Revision: 4164 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-28 09:03:16 +0200 (Wed, 28 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(12437);
 script_cve_id("CVE-2005-0089");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: python, python23, python22, python-devel");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"python");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
    txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
    txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
    txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
    txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"python23");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
    txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
    txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
    txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
    txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"python22");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
    txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
    txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
    txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
    txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"python-devel");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
    txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
    txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
    txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
    txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
