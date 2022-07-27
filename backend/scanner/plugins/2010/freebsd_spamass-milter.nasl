#
#VID 7132c842-58e2-11df-8d80-0015587e2cc1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 7132c842-58e2-11df-8d80-0015587e2cc1
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
tag_insight = "The following package is affected: spamass-milter

CVE-2010-1132
The mlfi_envrcpt function in spamass-milter.cpp in SpamAssassin Milter
Plugin 0.3.1, when using the expand option, allows remote attackers to
execute arbitrary system commands via shell metacharacters in the RCPT
TO field of an email message.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://archives.neohapsis.com/archives/fulldisclosure/2010-03/0139.html
http://xforce.iss.net/xforce/xfdb/56732
http://www.vuxml.org/freebsd/7132c842-58e2-11df-8d80-0015587e2cc1.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313875");
 script_version("$Revision: 8250 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-05-14 20:09:58 +0200 (Fri, 14 May 2010)");
 script_cve_id("CVE-2010-1132");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: spamass-milter");



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
bver = portver(pkg:"spamass-milter");
if(!isnull(bver) && revcomp(a:bver, b:"0.3.1_8")<=0) {
    txt += 'Package spamass-milter version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
