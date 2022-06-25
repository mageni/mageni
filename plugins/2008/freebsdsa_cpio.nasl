#
#ADV FreeBSD-SA-06:03.cpio.asc
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

tag_insight = "The cpio utility copies files into or out of a cpio or tar archive.

A number of issues has been discovered in cpio:

  . When creating a new file, cpio closes the file before setting its
    permissions. (CVE-2005-1111)

  . When extracting files cpio does not properly sanitize file names
    to filter out .. components, even if the --no-absolute-filenames
    option is used. (CVE-2005-1229)

  . When adding large files (larger than 4 GB) to a cpio archive on
    64-bit platforms an internal buffer might overflow. (CVE-2005-4268)";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:03.cpio.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-06:03.cpio.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303283");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(13159);
 script_cve_id("CVE-2005-1111");
 script_tag(name:"cvss_base", value:"3.7");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
 name = "FreeBSD Security Advisory (FreeBSD-SA-06:03.cpio.asc)";
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
if(patchlevelcmp(rel:"6.0", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"9")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"24")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"14")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"20")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
