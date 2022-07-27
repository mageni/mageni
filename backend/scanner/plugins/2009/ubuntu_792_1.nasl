# OpenVAS Vulnerability Test
# $Id: ubuntu_792_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_792_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-792-1 (openssl)
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
  libssl0.9.8                     0.9.8a-7ubuntu0.9

Ubuntu 8.04 LTS:
  libssl0.9.8                     0.9.8g-4ubuntu3.7

Ubuntu 8.10:
  libssl0.9.8                     0.9.8g-10.1ubuntu2.4

Ubuntu 9.04:
  libssl0.9.8                     0.9.8g-15ubuntu3.2

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-792-1";

tag_insight = "It was discovered that OpenSSL did not limit the number of DTLS records it
would buffer when they arrived with a future epoch. A remote attacker could
cause a denial of service via memory resource consumption by sending a
large number of crafted requests. (CVE-2009-1377)

It was discovered that OpenSSL did not properly free memory when processing
DTLS fragments. A remote attacker could cause a denial of service via
memory resource consumption by sending a large number of crafted requests.
(CVE-2009-1378)

It was discovered that OpenSSL did not properly handle certain server
certificates when processing DTLS packets. A remote DTLS server could cause
a denial of service by sending a message containing a specially crafted
server certificate. (CVE-2009-1379)

It was discovered that OpenSSL did not properly handle a DTLS
ChangeCipherSpec packet when it occurred before ClientHello. A remote
attacker could cause a denial of service by sending a specially crafted
request. (CVE-2009-1386)

It was discovered that OpenSSL did not properly handle out of sequence
DTLS handshake messages. A remote attacker could cause a denial of service
by sending a specially crafted request. (CVE-2009-1387)";
tag_summary = "The remote host is missing an update to openssl
announced via advisory USN-792-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307468");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-1628", "CVE-2009-1886", "CVE-2009-1888", "CVE-2009-1394", "CVE-2009-1150", "CVE-2009-1151", "CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-792-1 (openssl)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-792-1/");

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
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8a-7ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8a-7ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8a-7ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8a-7ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-4ubuntu3.7", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-4ubuntu3.7", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-4ubuntu3.7", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-4ubuntu3.7", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-4ubuntu3.7", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-10.1ubuntu2.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-10.1ubuntu2.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-10.1ubuntu2.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-10.1ubuntu2.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-10.1ubuntu2.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-15ubuntu3.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-15ubuntu3.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-15ubuntu3.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-15ubuntu3.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-15ubuntu3.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbfs", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.2.5-4lenny6", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.11.8.1-5+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
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
