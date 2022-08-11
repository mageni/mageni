#
#ADV FreeBSD-SA-09:17.freebsd.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-09:17.freebsd.asc
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

tag_insight = "The freebsd-update(8) utility is used to fetch, install, and rollback
updates to the FreeBSD base system, and also to upgrade from one FreeBSD
release to another.

When downloading updates to FreeBSD via 'freebsd-update fetch' or
'freebsd-update upgrade', the freebsd-update(8) utility copies currently
installed files into its working directory (/var/db/freebsd-update by
default) both for the purpose of merging changes to configuration files
and in order to be able to roll back installed updates.

The default working directory used by freebsd-update(8) is normally
created during the installation of FreeBSD with permissions which allow
all local users to see its contents, and freebsd-update(8) does not take
any steps to restrict access to files stored in said directory.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:17.freebsd.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-09:17.freebsd.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311858");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-09:17.freebsd.asc)");



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"8.0", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.2", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"9")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"8")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"14")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
