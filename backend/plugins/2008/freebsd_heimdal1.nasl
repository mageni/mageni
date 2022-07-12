#
#VID b62c80c2-b81a-11da-bec5-00123ffe8333
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
tag_insight = "The following package is affected: heimdal

CVE-2005-0469
Buffer overflow in the slc_add_reply function in various BSD-based
Telnet clients, when handling LINEMODE suboptions, allows remote
attackers to execute arbitrary code via a reply with a large number of
Set Local Character (SLC) commands.

CVE-2005-2040
Multiple buffer overflows in the getterminaltype function in telnetd
for Heimdal before 0.6.5 may allow remote attackers to execute
arbitrary code, a different vulnerability than CVE-2005-0468 and
CVE-2005-0469.

CVE-2006-0582
Unspecified vulnerability in rshd in Heimdal 0.6.x before 0.6.6 and
0.7.x before 0.7.2, when storing forwarded credentials, allows
attackers to overwrite arbitrary files and change file ownership via
unknown vectors.

CVE-2006-0677
telnetd in Heimdal 0.6.x before 0.6.6 and 0.7.x before 0.7.2 allows
remote unauthenticated attackers to cause a denial of service (server
crash) via unknown vectors that trigger a null dereference.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.pdc.kth.se/heimdal/advisory/2005-04-20
http://www.pdc.kth.se/heimdal/advisory/2005-06-20
http://www.pdc.kth.se/heimdal/advisory/2006-02-06
http://www.vuxml.org/freebsd/b62c80c2-b81a-11da-bec5-00123ffe8333.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302179");
 script_version("$Revision: 4118 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-20 07:32:38 +0200 (Tue, 20 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-0469", "CVE-2005-2040", "CVE-2006-0582", "CVE-2006-0677");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("FreeBSD Ports: heimdal");



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
bver = portver(pkg:"heimdal");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.6")<0) {
    txt += 'Package heimdal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
