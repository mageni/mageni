# OpenVAS Vulnerability Test
# $Id: ubuntu_777_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_777_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-777-1 (ntp)
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
  ntp                             1:4.2.0a+stable-8.1ubuntu6.2
  ntp-server                      1:4.2.0a+stable-8.1ubuntu6.2

Ubuntu 8.04 LTS:
  ntp                             1:4.2.4p4+dfsg-3ubuntu2.2

Ubuntu 8.10:
  ntp                             1:4.2.4p4+dfsg-6ubuntu2.3

Ubuntu 9.04:
  ntp                             1:4.2.4p4+dfsg-7ubuntu5.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-777-1";

tag_insight = "A stack-based buffer overflow was discovered in ntpq. If a user were
tricked into connecting to a malicious ntp server, a remote attacker could
cause a denial of service in ntpq, or possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2009-0159)

Chris Ries discovered a stack-based overflow in ntp. If ntp was configured
to use autokey, a remote attacker could send a crafted packet to cause a
denial of service, or possible execute arbitrary code. (CVE-2009-1252)";
tag_summary = "The remote host is missing an update to ntp
announced via advisory USN-777-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308858");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-0159", "CVE-2009-1252");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-777-1 (ntp)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-777-1/");

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
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-server", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
