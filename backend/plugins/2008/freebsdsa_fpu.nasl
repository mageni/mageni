#
#ADV FreeBSD-SA-06:14.fpu.asc
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

tag_insight = "The floating-point unit (FPU) of i386 and amd64 processors is derived from
the original 8087 floating-point co-processor.  As a result, the FPU
contains the same debugging registers FOP, FIP, and FDP which store the
opcode, instruction address, and data address of the instruction most
recently executed by the FPU.

On processors implementing the SSE instruction set, a new pair of
instructions fxsave/fxrstor replaces the earlier fsave/frstor pair used
for saving and restoring the FPU state.  These new instructions also
save and restore the contents of the additional registers used by SSE
instructions.

On 7th generation and 8th generation processors manufactured by AMD,
including the AMD Athlon, Duron, Athlon MP, Athlon XP, Athlon64, Athlon64
FX, Opteron, Turion, and Sempron, the fxsave and fxrstor instructions do
not save and restore the FOP, FIP, and FDP registers unless the exception
summary bit (ES) in the x87 status word is set to 1, indicating that an
unmasked x87 exception has occurred.

This behaviour is consistent with documentation provided by AMD, but is
different from processors from other vendors, which save and restore the
FOP, FIP, and FDP registers regardless of the value of the ES bit.  As a
result of this discrepancy remaining unnoticed until now, the FreeBSD
kernel does not restore the contents of the FOP, FIP, and FDP registers
between context switches.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:14.fpu.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-06:14.fpu.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300935");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(17600);
 script_cve_id("CVE-2006-1056");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 name = "FreeBSD Security Advisory (FreeBSD-SA-06:14.fpu.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"6.0", patchlevel:"7")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"14")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"29")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"17")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"23")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
