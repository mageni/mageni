# OpenVAS Vulnerability Test
# $Id: ubuntu_781_2.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_781_2.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-781-2 (gaim)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  gaim                            1:1.5.0+1.5.1cvs20051015-1ubuntu10.2

After a standard system upgrade you need to restart Gaim to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-781-2";

tag_insight = "It was discovered that Gaim did not properly handle certain malformed
messages when sending a file using the XMPP protocol handler. If a user
were tricked into sending a file, a remote attacker could send a specially
crafted response and cause Gaim to crash, or possibly execute arbitrary
code with user privileges. (CVE-2009-1373)

It was discovered that Gaim did not properly handle certain malformed
messages in the MSN protocol handler. A remote attacker could send a
specially crafted message and possibly execute arbitrary code with user
privileges. (CVE-2009-1376)";
tag_summary = "The remote host is missing an update to gaim
announced via advisory USN-781-2.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306519");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-1373", "CVE-2009-1376");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-781-2 (gaim)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-781-2/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"gaim-data", ver:"1.5.0+1.5.1cvs20051015-1ubuntu10.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim-dev", ver:"1.5.0+1.5.1cvs20051015-1ubuntu10.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim", ver:"1.5.0+1.5.1cvs20051015-1ubuntu10.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
