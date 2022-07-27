# OpenVAS Vulnerability Test
# $Id: ubuntu_717_2.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_717_2.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-717-2 (firefox-3.0)
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

Ubuntu 7.10:
  firefox                         2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1

After a standard system upgrade you need to restart Firefox to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-717-2";

tag_insight = "A flaw was discovered in the browser engine when restoring closed tabs. If a
user were tricked into restoring a tab to a malicious website with form input
controls, an attacker could steal local files on the user's system.
(CVE-2009-0355)

Wladimir Palant discovered that Firefox did not restrict access to cookies in
HTTP response headers. If a user were tricked into opening a malicious web
page, a remote attacker could view sensitive information. (CVE-2009-0357)";
tag_summary = "The remote host is missing an update to firefox-3.0
announced via advisory USN-717-2.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308223");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2009-0355", "CVE-2009-0357");
 script_tag(name:"cvss_base", value:"5.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
 script_name("Ubuntu USN-717-2 (firefox-3.0)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-717-2/");

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
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.21~20090209t122238+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
