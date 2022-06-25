#
#VID 2a6a966f-1774-11df-b5c1-0026189baca3
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 2a6a966f-1774-11df-b5c1-0026189baca3
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
tag_insight = "The following package is affected: fetchmail

CVE-2010-0562
The sdump function in sdump.c in fetchmail 6.3.11, 6.3.12, and 6.3.13,
when running in verbose mode on platforms for which char is signed,
allows remote attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via an SSL X.509 certificate
containing non-printable characters with the high bit set, which
triggers a heap-based buffer overflow during escaping.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.fetchmail.info/fetchmail-SA-2010-01.txt
https://lists.berlios.de/pipermail/fetchmail-announce/2010-February/000073.html
http://www.vuxml.org/freebsd/2a6a966f-1774-11df-b5c1-0026189baca3.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313747");
 script_version("$Revision: 8356 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-18 21:15:01 +0100 (Thu, 18 Feb 2010)");
 script_cve_id("CVE-2010-0562");
 script_bugtraq_id(38088);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: fetchmail");



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
bver = portver(pkg:"fetchmail");
if(!isnull(bver) && revcomp(a:bver, b:"6.3.11")>=0 && revcomp(a:bver, b:"6.3.14")<0) {
    txt += 'Package fetchmail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
