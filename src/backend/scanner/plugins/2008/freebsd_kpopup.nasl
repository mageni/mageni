#
#VID 1613db79-8e52-11da-8426-000fea0a9611
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
tag_insight = "The following package is affected: kpopup

CVE-2003-1170
Format string vulnerability in main.cpp in kpopup 0.9.1 and 0.9.5pre2
allows local users to cause a denial of service (segmentation fault)
and possibly execute arbitrary code via format string specifiers in
command line arguments.

CVE-2003-1167
misc.cpp in KPopup 0.9.1 trusts the PATH variable when executing
killall, which allows local users to elevate their privileges by
modifying the PATH variable to reference a malicious killall program.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.henschelsoft.de/kpopup_en.html
http://www.vuxml.org/freebsd/1613db79-8e52-11da-8426-000fea0a9611.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303510");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2003-1170", "CVE-2003-1167");
 script_bugtraq_id(8918,8915);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: kpopup");



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
bver = portver(pkg:"kpopup");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.9.5")<=0) {
    txt += 'Package kpopup version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
