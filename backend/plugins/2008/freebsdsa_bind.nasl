#
#ADV FreeBSD-SA-03:19.bind.asc
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

tag_insight = "BIND 8 is an implementation of the Domain Name System (DNS) protocols.
The named(8) daemon is the Internet domain name server.

A programming error in BIND 8 named can result in a DNS message being
incorrectly cached as a negative response.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:19.bind.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-03:19.bind.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301270");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(9114);
 script_cve_id("CVE-2003-0914");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 name = "FreeBSD Security Advisory (FreeBSD-SA-03:19.bind.asc)";
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
if(patchlevelcmp(rel:"5.1", patchlevel:"11")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"19")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.9", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"14")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"24")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.6.2", patchlevel:"27")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.5", patchlevel:"37")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.4", patchlevel:"47")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
