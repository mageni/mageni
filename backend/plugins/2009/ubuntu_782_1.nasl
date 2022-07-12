# OpenVAS Vulnerability Test
# $Id: ubuntu_782_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_782_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-782-1 (thunderbird)
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

Ubuntu 8.04 LTS:
  thunderbird                     2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1

Ubuntu 8.10:
  thunderbird                     2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1

Ubuntu 9.04:
  thunderbird                     2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1

After a standard system upgrade you need to restart Thunderbird to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-782-1";

tag_insight = "Several flaws were discovered in the JavaScript engine of Thunderbird. If a
user had JavaScript enabled and were tricked into viewing malicious web
content, a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1303, CVE-2009-1305, CVE-2009-1392, CVE-2009-1833,
CVE-2009-1838)

Several flaws were discovered in the way Thunderbird processed malformed
URI schemes. If a user were tricked into viewing a malicious website and
had JavaScript and plugins enabled, a remote attacker could execute
arbitrary JavaScript or steal private data. (CVE-2009-1306, CVE-2009-1307,
CVE-2009-1309)

Cefn Hoile discovered Thunderbird did not adequately protect against
embedded third-party stylesheets. If JavaScript were enabled, an attacker
could exploit this to perform script injection attacks using XBL bindings.
(CVE-2009-1308)

Shuo Chen, Ziqing Mao, Yi-Min Wang, and Ming Zhang discovered that
Thunderbird did not properly handle error responses when connecting to a
proxy server. If a user had JavaScript enabled while using Thunderbird to
view websites and a remote attacker were able to perform a
man-in-the-middle attack, this flaw could be exploited to view sensitive
information. (CVE-2009-1836)

It was discovered that Thunderbird could be made to run scripts with
elevated privileges. If a user had JavaScript enabled while having
certain non-default add-ons installed and were tricked into viewing a
malicious website, an attacker could cause a chrome privileged object, such
as the browser sidebar, to run arbitrary code via interactions with the
attacker controlled website. (CVE-2009-1841)";
tag_summary = "The remote host is missing an update to thunderbird
announced via advisory USN-782-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309203");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-782-1 (thunderbird)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-782-1/");

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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
