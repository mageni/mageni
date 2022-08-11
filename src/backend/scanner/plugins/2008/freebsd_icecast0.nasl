#
#VID 5e92e8a2-5d7b-11d8-80e3-0020ed76ef5a
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
tag_insight = "The following package is affected: icecast

CVE-2002-0177
Buffer overflows in icecast 1.3.11 and earlier allows remote attackers
to execute arbitrary code via a long HTTP GET request from an MP3
client.

CVE-2001-1230
Buffer overflows in Icecast before 1.3.10 allow remote attackers to
cause a denial of service (crash) and execute arbitrary code.

CVE-2001-1229
Buffer overflows in (1) Icecast before 1.3.9 and (2) libshout before
1.0.4 allow remote attackers to cause a denial of service (crash) and
execute arbitrary code.

CVE-2001-1083
Icecast 1.3.7, and other versions before 1.3.11 with HTTP server file
streaming support enabled allows remote attackers to cause a denial of
service (crash) via a URL that ends in . (dot), / (forward slash), or
\ (backward slash).
CVE-2001-0784
Directory traversal vulnerability in Icecast 1.3.10 and earlier allows
remote attackers to read arbitrary files via a modified .. (dot dot)
attack using encoded URL characters.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303557");
 script_version("$Revision: 4118 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-20 07:32:38 +0200 (Tue, 20 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2002-0177", "CVE-2001-1230", "CVE-2001-1229", "CVE-2001-1083", "CVE-2001-0784");
 script_bugtraq_id(4415,2933);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: icecast");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"icecast");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.12")<0) {
    txt += 'Package icecast version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
