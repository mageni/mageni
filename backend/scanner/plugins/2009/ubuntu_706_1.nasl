# OpenVAS Vulnerability Test
# $Id: ubuntu_706_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_706_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-706-1 (bind9)
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
  libdns21                        1:9.3.2-2ubuntu1.6

Ubuntu 7.10:
  libdns32                        1:9.4.1-P1-3ubuntu2.1

Ubuntu 8.04 LTS:
  libdns35                        1:9.4.2.dfsg.P2-2ubuntu0.1

Ubuntu 8.10:
  libdns43                        1:9.5.0.dfsg.P2-1ubuntu3.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-706-1";

tag_summary = "The remote host is missing an update to bind9
announced via advisory USN-706-1.

It was discovered that Bind did not properly perform certificate verification.
When DNSSEC with DSA certificates are in use, a remote attacker could exploit
this to bypass certificate validation to spoof DNS entries and poison DNS
caches. Among other things, this could lead to misdirected email and web
traffic.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305511");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2009-0025");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-706-1 (bind9)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-706-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
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
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-0", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns21", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc11", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc0", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg1", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres9", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.3.2-2ubuntu1.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-30", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns32", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc32", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc30", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg30", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres30", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.4.1-P1-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-30", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns35", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc35", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc30", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg30", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres30", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.4.2.dfsg.P2-2ubuntu0.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-40", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns43", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc44", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc40", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg40", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres40", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.5.0.dfsg.P2-1ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
