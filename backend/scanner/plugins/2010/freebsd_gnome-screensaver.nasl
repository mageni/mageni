#
#VID 0a82ac0c-1886-11df-b0d1-0015f2db7bde
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 0a82ac0c-1886-11df-b0d1-0015f2db7bde
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
tag_insight = "The following package is affected: gnome-screensaver

CVE-2010-0414
gnome-screensaver before 2.28.2 allows physically proximate attackers
to bypass screen locking and access an unattended workstation by
moving the mouse position to an external monitor and then
disconnecting that monitor.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://bugzilla.gnome.org/show_bug.cgi?id=609337
https://bugzilla.gnome.org/show_bug.cgi?id=609789
http://www.vuxml.org/freebsd/0a82ac0c-1886-11df-b0d1-0015f2db7bde.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.315046");
 script_version("$Revision: 8246 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-02-18 21:15:01 +0100 (Thu, 18 Feb 2010)");
 script_cve_id("CVE-2010-0414", "CVE-2010-0422");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: gnome-screensaver");



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
bver = portver(pkg:"gnome-screensaver");
if(!isnull(bver) && revcomp(a:bver, b:"2.28.3")<0) {
    txt += 'Package gnome-screensaver version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
