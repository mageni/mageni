#
#VID 8d10038e-515c-11df-83fb-0015587e2cc1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 8d10038e-515c-11df-83fb-0015587e2cc1
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
tag_insight = "The following package is affected: joomla15";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://developer.joomla.org/security/news/308-20100423-core-password-reset-tokens.html
http://developer.joomla.org/security/news/309-20100423-core-sessation-fixation.html
http://developer.joomla.org/security/news/310-20100423-core-installer-migration-script.html
http://developer.joomla.org/security/news/311-20100423-core-negative-values-for-limit-and-offset.html
http://www.vuxml.org/freebsd/8d10038e-515c-11df-83fb-0015587e2cc1.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313601");
 script_version("$Revision: 8228 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
 script_tag(name:"cvss_base", value:"9.3"); 
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C"); 

 script_name("FreeBSD Ports: joomla15");



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
bver = portver(pkg:"joomla15");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.1")>=0 && revcomp(a:bver, b:"1.5.15")<=0) {
    txt += 'Package joomla15 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
