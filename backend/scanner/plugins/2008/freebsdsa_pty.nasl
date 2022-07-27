#
#ADV FreeBSD-SA-08:01.pty.asc
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

tag_insight = "pt_chown is a setuid root support utility used by grantpt(3) to change
ownership of a tty.

openpty(3) is a support function in libutil which is used to obtain a
pseudo-terminal.

script(1) is a utility which makes a typescript of everything printed
on a terminal.

Two issues exist in the FreeBSD pty handling.

If openpty(3) is called as non-root user the newly created
pseudo-terminal is world readable and writeable.  While this is
documented to be the case, script(1) still uses openpty(3) and
script(1) may be used by non-root users [CVE-2008-0217].

The ptsname(3) function incorrectly extracts two characters from the
name of a device node in /dev without verifying that it's actually
operating on a valid pty which the calling user owns.  pt_chown uses
the bad result from ptsname(3) to change ownership of a pty to the
user calling pt_chown [CVE-2008-0216].";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:01.pty.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-08:01.pty.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302861");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-0216");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 name = "FreeBSD Security Advisory (FreeBSD-SA-08:01.pty.asc)";
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
if(patchlevelcmp(rel:"6.2", patchlevel:"10")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.1", patchlevel:"22")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"18")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
