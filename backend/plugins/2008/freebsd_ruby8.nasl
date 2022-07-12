#
#VID f7ba20aa-6b5a-11dd-9d79-001fc61c2a55
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
   ruby
   ruby+pthreads
   ruby+pthreads+oniguruma
   ruby+oniguruma";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ruby-lang.org/en/news/2008/08/08/multiple-vulnerabilities-in-ruby/
http://www.vuxml.org/freebsd/f7ba20aa-6b5a-11dd-9d79-001fc61c2a55.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300575");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_version("$Revision: 4175 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-29 07:45:50 +0200 (Thu, 29 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3905");
 script_name("FreeBSD Ports: ruby, ruby+pthreads, ruby+pthreads+oniguruma, ruby+oniguruma");



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
bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.6.111_5,1")<0) {
    txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0) {
    txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+pthreads");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.6.111_5,1")<0) {
    txt += 'Package ruby+pthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0) {
    txt += 'Package ruby+pthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+pthreads+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.6.111_5,1")<0) {
    txt += 'Package ruby+pthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0) {
    txt += 'Package ruby+pthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.6.111_5,1")<0) {
    txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0) {
    txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
