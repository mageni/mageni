#
#VID e480ccb2-6bc8-11d9-8dbe-000a95bc6fae
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

include("revisions-lib.inc");
tag_insight = "The following package is affected: fcron

CVE-2004-1030
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to gain sensitive information by calling
fcronsighup with an arbitrary file, which reveals the contents of the
file that can not be parsed in an error message.

CVE-2004-1031
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to bypass access restrictions and load an arbitrary
configuration file by starting an suid process and pointing the
fcronsighup configuration file to a /proc entry that is owned by root
but modifiable by the user, such as /proc/self/cmdline or
/proc/self/environ.

CVE-2004-1032
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to delete arbitrary files or create arbitrary empty
files via a target filename with a large number of leading slash (/)
characters such that fcronsighup does not properly append the intended
fcrontab.sig to the resulting string.

CVE-2004-1033
Fcron 2.0.1, 2.9.4, and possibly earlier versions leak file
descriptors of open files, which allows local users to bypass access
restrictions and read fcron.allow and fcron.deny via the EDITOR
environment variable.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.idefense.com/application/poi/display?id=157&type=vulnerabilities&flashstatus=false
http://www.vuxml.org/freebsd/e480ccb2-6bc8-11d9-8dbe-000a95bc6fae.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301731");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1030", "CVE-2004-1031", "CVE-2004-1032", "CVE-2004-1033");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: fcron");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

txt = "";
vuln = 0;
bver = portver(pkg:"fcron");
if(!isnull(bver) && revcomp(a:bver, b:"2.9.5.1")<0) {
    txt += 'Package fcron version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
