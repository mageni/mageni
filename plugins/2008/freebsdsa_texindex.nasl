#
#ADV FreeBSD-SA-06:01.texindex.asc
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

tag_insight = "TeX is a document typesetting system which is popular in the mathematics,
physics, and computer science realms because of its ability to typeset
complex mathematical formulas.  texindex(1) is a utility which is often
used to generate a sorted index of a TeX file.

The sort_offline function used by texindex(1) employs the maketempname
function, which produces predictable file names and fails to validate that
the paths do not exist.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:01.texindex.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-06:01.texindex.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303427");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(14854);
 script_cve_id("CVE-2005-3011");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
 name = "FreeBSD Security Advisory (FreeBSD-SA-06:01.texindex.asc)";
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
}
