#
#ADV FreeBSD-SA-09:09.pipe.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-09:09.pipe.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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

tag_insight = "One of the most commonly used forms of interprocess communication on
FreeBSD and other UNIX-like systems is the (anonymous) pipe.  In this
mechanism, a pair of file descriptors is created, and data written to
one descriptor can be read from the other.

FreeBSD's pipe implementation contains an optimization known as direct
writes.  In this optimization, rather than copying data into kernel
memory when the write(2) system call is invoked and then copying the
data again when the read(2) system call is invoked, the FreeBSD kernel
takes advantage of virtual memory mapping to allow the data to be copied
directly between processes.

An integer overflow in computing the set of pages containing data to be
copied can result in virtual-to-physical address lookups not being
performed.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:09.pipe.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-09:09.pipe.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311423");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-15 19:20:43 +0200 (Mon, 15 Jun 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "FreeBSD Security Advisory (FreeBSD-SA-09:09.pipe.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"7.2", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"11")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
