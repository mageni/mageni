# OpenVAS Vulnerability Test
# $Id: ubuntu_757_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_757_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-757-1 (gs-gpl)
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
  gs-esp                          8.15.2.dfsg.0ubuntu1-0ubuntu1.2
  gs-gpl                          8.15-4ubuntu3.3

Ubuntu 8.04 LTS:
  libgs8                          8.61.dfsg.1-1ubuntu3.2

Ubuntu 8.10:
  libgs8                          8.63.dfsg.1-0ubuntu6.4

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-757-1";

tag_insight = "It was discovered that Ghostscript contained a buffer underflow in its
CCITTFax decoding filter. If a user or automated system were tricked into
opening a crafted PDF file, an attacker could cause a denial of service or
execute arbitrary code with privileges of the user invoking the program.
(CVE-2007-6725)

It was discovered that Ghostscript contained a buffer overflow in the
BaseFont writer module. If a user or automated system were tricked into
opening a crafted Postscript file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking the
program. (CVE-2008-6679)

It was discovered that Ghostscript contained additional integer overflows
in its ICC color management library. If a user or automated system were
tricked into opening a crafted Postscript or PDF file, an attacker could
cause a denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2009-0792)

Alin Rad Pop discovered that Ghostscript contained a buffer overflow in the
jbig2dec library. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service or execute
arbitrary code with privileges of the user invoking the program.
(CVE-2009-0196)

USN-743-1 provided updated ghostscript and gs-gpl packages to fix two
security vulnerabilities. This update corrects the same vulnerabilities in
the gs-esp package.

Original advisory details:
 It was discovered that Ghostscript contained multiple integer overflows in
 its ICC color management library. If a user or automated system were
 tricked into opening a crafted Postscript file, an attacker could cause a
 denial of service or execute arbitrary code with privileges of the user
 invoking the program. (CVE-2009-0583)

 It was discovered that Ghostscript did not properly perform bounds
 checking in its ICC color management library. If a user or automated
 system were tricked into opening a crafted Postscript file, an attacker
 could cause a denial of service or execute arbitrary code with privileges
 of the user invoking the program. (CVE-2009-0584)";
tag_summary = "The remote host is missing an update to gs-gpl
announced via advisory USN-757-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311632");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
 script_cve_id("CVE-2008-5259", "CVE-2009-0584", "CVE-2009-0583", "CVE-2009-1012", "CVE-2007-6725", "CVE-2009-1016", "CVE-2009-1185", "CVE-2009-0796", "CVE-2009-0792", "CVE-2009-0196", "CVE-2008-6679", "CVE-2009-1186");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-757-1 (gs-gpl)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-757-1/");

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
if ((res = isdpkgvuln(pkg:"gs", ver:"8.15-4ubuntu3.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.15.2.dfsg.0ubuntu1-0ubuntu1.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.15-4ubuntu3.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-esp-dev", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-common", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp-x", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-dev", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs8", ver:"8.61.dfsg.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-common", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-esp-dev", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp-x", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-dev", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs8", ver:"8.63.dfsg.1-0ubuntu6.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udev", ver:"079-0ubuntu35.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id-dev", ver:"113-0ubuntu17.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id0", ver:"113-0ubuntu17.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udev", ver:"113-0ubuntu17.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"volumeid", ver:"113-0ubuntu17.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id-dev", ver:"117-8ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id0", ver:"117-8ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udev", ver:"117-8ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id-dev", ver:"124-9ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvolume-id0", ver:"124-9ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udev", ver:"124-9ubuntu0.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
