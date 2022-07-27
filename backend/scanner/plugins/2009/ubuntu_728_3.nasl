# OpenVAS Vulnerability Test
# $Id: ubuntu_728_3.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_728_3.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-728-3 (firefox)
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
  firefox                         1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1

After a standard system upgrade you need to restart Firefox to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-728-3";

tag_insight = "Jesse Ruderman and Gary Kwong discovered flaws in the browser engine.
If a user were tricked into viewing a malicious website, a remote
attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2009-0772, CVE-2009-0774)

Georgi Guninski discovered a flaw when Firefox performed a
cross-domain redirect. An attacker could bypass the same-origin policy
in Firefox by utilizing nsIRDFService and steal private data from
users authenticated to the redirected website. (CVE-2009-0776)";
tag_summary = "The remote host is missing an update to firefox
announced via advisory USN-728-3.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305396");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-728-3 (firefox)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-728-3/");

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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.15~prepatch080614k-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
