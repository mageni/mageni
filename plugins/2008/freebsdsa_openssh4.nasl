#
#ADV FreeBSD-SA-08:05.openssh.asc
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
#

tag_insight = "OpenSSH is an implementation of the SSH protocol suite, providing an
encrypted and authenticated transport for a variety of services,
including remote shell access.  The OpenSSH server daemon (sshd)
provides support for the X11 protocol by binding to a port on the
server and forwarding any connections which are made to that port.

When logging in via SSH with X11-forwarding enabled, sshd(8) fails to
correctly handle the case where it fails to bind to an IPv4 port but
successfully binds to an IPv6 port.  In this case, applications which
use X11 will connect to the IPv4 port, even though it had not been
bound by sshd(8) and is therefore not being securely forwarded.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:05.openssh.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-08:05.openssh.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301367");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-1483");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 name = "FreeBSD Security Advisory (FreeBSD-SA-08:05.openssh.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
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
vuln = 0;
if(patchlevelcmp(rel:"7.1", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.2", patchlevel:"12")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.1", patchlevel:"24")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"20")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
