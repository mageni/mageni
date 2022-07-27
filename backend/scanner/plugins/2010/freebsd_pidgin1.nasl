#
#VID a2c4d3d5-4c7b-11df-83fb-0015587e2cc1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a2c4d3d5-4c7b-11df-83fb-0015587e2cc1
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
   pidgin
   libpurple

CVE-2010-0277
slp.c in the MSN protocol plugin in libpurple in Pidgin before 2.6.6,
including 2.6.4, and Adium 1.3.8 allows remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly have unspecified other impact via a malformed MSNSLP INVITE
request in an SLP message, a different issue than CVE-2010-0013.

CVE-2010-0420
libpurple in Finch in Pidgin before 2.6.6, when an XMPP multi-user
chat (MUC) room is used, does not properly parse nicknames containing
<br> sequences, which allows remote attackers to cause a denial of
service (application crash) via a crafted nickname.

CVE-2010-0423
gtkimhtml.c in Pidgin before 2.6.6 allows remote attackers to cause a
denial of service (CPU consumption and application hang) by sending
many smileys in a (1) IM or (2) chat.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://pidgin.im/news/security/?id=43
http://pidgin.im/news/security/?id=44
http://pidgin.im/news/security/?id=45
http://www.vuxml.org/freebsd/a2c4d3d5-4c7b-11df-83fb-0015587e2cc1.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313163");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
 script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
 script_bugtraq_id(38294);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Ports: pidgin");



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
bver = portver(pkg:"pidgin");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.6")<0) {
    txt += 'Package pidgin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libpurple");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.6")<0) {
    txt += 'Package libpurple version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
