#
#VID c97d7a37-2233-11df-96dd-001b2134ef46
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID c97d7a37-2233-11df-96dd-001b2134ef46
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
tag_insight = "The following package is affected: openoffice.org

For details on the issues addressed in this update, please visit the
referenced security advisories.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.openoffice.org/security/bulletin.html
http://www.openoffice.org/security/cves/CVE-2006-4339.html
http://www.openoffice.org/security/cves/CVE-2009-0217.html
http://www.openoffice.org/security/cves/CVE-2009-2493.html
http://www.openoffice.org/security/cves/CVE-2009-2949.html
http://www.openoffice.org/security/cves/CVE-2009-2950.html
http://www.openoffice.org/security/cves/CVE-2009-3301-3302.html
http://www.vuxml.org/freebsd/c97d7a37-2233-11df-96dd-001b2134ef46.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313304");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
 script_cve_id("CVE-2006-4339", "CVE-2009-0217", "CVE-2009-2493", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: openoffice.org");



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
bver = portver(pkg:"openoffice.org");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.0")<0) {
    txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.2.20010101")>=0 && revcomp(a:bver, b:"3.2.20100203")<0) {
    txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.3.20010101")>=0 && revcomp(a:bver, b:"3.3.20100207")<0) {
    txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
