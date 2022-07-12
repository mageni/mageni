#
#ADV FreeBSD-SA-08:07.amd64.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-08:07.amd64.asc
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

tag_insight = "FreeBSD/amd64 is commonly used on 64bit systems with AMD and Intel
CPU's.  For Intel CPU's this architecture is known as EM64T or Intel
64.

The gs segment CPU register is used by both user processes and the
kernel to convieniently access state data.  User processes use it to
manage per-thread data, and the kernel uses it to manage per-processor
data.  As the processor enters and leaves the kernel it uses the
'swapgs' instruction to toggle between the kernel and user values for
the gs register.

The kernel stores critical information in its per-processor data
block.  This includes the currently executing process and its
credentials.

As the processor switches between user and kernel level, a number of
checks are performed in order to implement the privilege protection
system.  If the processor detects a problem while attempting to switch
privilege levels it generates a trap - typically general protection
fault (GPF).  In that case, the processor aborts the return to the
user level process and re-enters the kernel.  The FreeBSD kernel
allows the user process to be notified of such an event by a signal
(SIGSEGV or SIGBUS).

If a General Protection Fault happens on a FreeBSD/amd64 system while
it is returning from an interrupt, trap or system call, the swapgs CPU
instruction may be called one extra time when it should not resulting
in userland and kernel state being mixed.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:07.amd64.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-08:07.amd64.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303316");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-3890");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 name = "FreeBSD Security Advisory (FreeBSD-SA-08:07.amd64.asc)";
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
if(patchlevelcmp(rel:"7.0", patchlevel:"4")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"4")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
