#
#VID 594ad3c5-a39b-11da-926c-0800209adf0e
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
   ssh2
   ssh2-nox11

CVE-2006-0705
Format string vulnerability in a logging function as used by various
SFTP servers, including (1) AttachmateWRQ Reflection for Secure IT
UNIX Server before 6.0.0.9, (2) Reflection for Secure IT Windows
Server before 6.0 build 38, (3) F-Secure SSH Server for Windows before
5.3 build 35, (4) F-Secure SSH Server for UNIX 3.0 through 5.0.8, (5)
SSH Tectia Server 4.3.6 and earlier and 4.4.0, and (6) SSH Shell
Server 3.2.9 and earlier, allows remote authenticated users to execute
arbitrary commands via unspecified vectors, involving crafted
filenames and the stat command.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ssh.com/company/newsroom/article/715/
http://www.frsirt.com/english/advisories/2006/0554
http://securitytracker.com/id?1015619
http://secunia.com/advisories/18828
http://xforce.iss.net/xforce/xfdb/24651
http://www.vuxml.org/freebsd/594ad3c5-a39b-11da-926c-0800209adf0e.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300346");
 script_version("$Revision: 4188 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-30 07:56:47 +0200 (Fri, 30 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-0705");
 script_bugtraq_id(16640);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("FreeBSD Ports: ssh2, ssh2-nox11");



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
bver = portver(pkg:"ssh2");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.9.1_5")<0) {
    txt += 'Package ssh2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ssh2-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.9.1_5")<0) {
    txt += 'Package ssh2-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
