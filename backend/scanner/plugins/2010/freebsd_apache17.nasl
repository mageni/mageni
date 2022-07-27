#
#VID 28a7310f-9855-11df-8d36-001aa0166822
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 28a7310f-9855-11df-8d36-001aa0166822
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
tag_insight = "The following package is affected: apache

CVE-2010-1452
The (1) mod_cache and (2) mod_dav modules in the Apache HTTP Server
2.2.x before 2.2.16 allow remote attackers to cause a denial of
service (process crash) via a request that lacks a path.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.apache.org/dist/httpd/CHANGES_2.2.16
https://issues.apache.org/bugzilla/show_bug.cgi?id=49246
http://svn.apache.org/viewvc?view=revision&revision=966349
http://www.vuxml.org/freebsd/28a7310f-9855-11df-8d36-001aa0166822.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312915");
 script_version("$Revision: 8258 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-1452");
 script_name("FreeBSD Ports: apache");



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
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>=0 && revcomp(a:bver, b:"2.2.16")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
