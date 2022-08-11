#
#ADV FreeBSD-SA-03:14.arp.asc
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

tag_insight = "The Address Resolution Protocol (ARP) is fundamental to the operation
of IP with a variety of network technologies, such as Ethernet and
WLAN.  It is used to map IP addresses to MAC addresses, which enables
hosts on a local network segment to communicate with each other
directly.  These mappings are stored in the system's ARP cache.

FreeBSD's ARP cache is implemented within the kernel routing table as
a set of routes for the address family in use that have the LLINFO
flag set.  This is most commonly often AF_INET (for IPv4).  Normally,
when a FreeBSD system receives an ARP request for a network address
configured on one of its interfaces from a system on a local network,
it adds a reciprocal ARP entry to the cache for the system from where
the request originated.  Expiry timers are used to purge unused
entries from the ARP cache.  A reference count is maintained for each
ARP entry.  If the reciprocal ARP entry is not in use by an upper
layer protocol, the reference count will be zero.

Under certain circumstances, it is possible for an attacker to flood a
FreeBSD system with spoofed ARP requests, causing resource starvation
which eventually results in a system panic.  (The critical condition
is that a route exists for the apparent source of the ARP request.
This is always the case if the system has a default route configured
for that protocol family.)

If a large number of ARP requests with different network protocol
addresses are sent in a small space of time, resource starvation can
result, as the arplookup() function does not delete unnecessary ARP
entries cached as the result of responding to an ARP request.

NOTE WELL: Other BSD-derived systems may also be affected, as the
affected code dates well back to the CSRG branches.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:14.arp.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-03:14.arp.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303126");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(8689);
 script_cve_id("CVE-2003-0804");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "FreeBSD Security Advisory (FreeBSD-SA-03:14.arp.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"5.1", patchlevel:"8")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"16")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"10")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"20")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.6", patchlevel:"23")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.5", patchlevel:"34")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.4", patchlevel:"44")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.3", patchlevel:"40")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
