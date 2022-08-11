#
#ADV FreeBSD-SA-10:07.mbuf.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-10:07.mbuf.asc
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

tag_insight = "An mbuf is a basic unit of memory management in the FreeBSD kernel
inter-process communication and networking subsystem.  Network packets
and socket buffers are dependent on mbufs for their storage.

Data can be embedded directly in mbufs, or mbufs can instead reference
external buffers.  The sendfile(2) system call uses external mbuf storage
to directly map the contents of a file into a chain of mbufs for
transmission purposes.  The mbuf object supports a read-only flag that
must be honored to prevent modification or writes to buffer data in
cases like these.

The read-only flag is not correctly copied when a mbuf buffer reference
is duplicated.  When the sendfile(2) system call is used to transmit
data over the loopback interface, this can result in the backing pages
for the transmitted file being modified, causing data corruption.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:07.mbuf.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-10:07.mbuf.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314435");
 script_version("$Revision: 8266 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-22 17:43:43 +0200 (Thu, 22 Jul 2010)");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2693");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-10:07.mbuf.asc)");


 script_tag(name:"qod_type", value:"package");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
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
if(patchlevelcmp(rel:"8.0", patchlevel:"4")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"13")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
