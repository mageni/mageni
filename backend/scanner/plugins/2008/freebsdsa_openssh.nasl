#
#ADV FreeBSD-SA-03:12.openssh.asc
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

tag_insight = "OpenSSH is a free version of the SSH protocol suite of network
connectivity tools.  OpenSSH encrypts all traffic (including
passwords) to effectively eliminate eavesdropping, connection
hijacking, and other network-level attacks. Additionally, OpenSSH
provides a myriad of secure tunneling capabilities, as well as a
variety of authentication methods. `ssh' is the client application,
while `sshd' is the server.

Several operations within OpenSSH require dynamic memory allocation
or reallocation.  Examples are: the receipt of a packet larger
than available space in a currently allocated buffer; creation of
additional channels beyond the currently allocated maximum; and
allocation of new sockets beyond the currently allocated maximum.
Many of these operations can fail either due to `out of memory' or
due to explicit checks for ridiculously sized requests.  However, the
failure occurs after the allocation size has already been updated, so
that the bookkeeping data structures are in an inconsistent state (the
recorded size is larger than the actual allocation).  Furthermore,
the detection of these failures causes OpenSSH to invoke several
`fatal_cleanup' handlers, some of which may then attempt to use these
inconsistent data structures.  For example, a handler may zero and
free a buffer in this state, and as a result memory outside of the
allocated area will be overwritten with NUL bytes.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:12.openssh.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-03:12.openssh.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303586");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(8628);
 script_cve_id("CVE-2003-0693");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 name = "FreeBSD Security Advisory (FreeBSD-SA-03:12.openssh.asc)";
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
if(patchlevelcmp(rel:"5.1", patchlevel:"4")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"13")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"16")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.6", patchlevel:"19")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.5", patchlevel:"31")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.4", patchlevel:"41")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.3", patchlevel:"37")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
