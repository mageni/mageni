# OpenVAS Vulnerability Test
# $Id: ubuntu_838_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_838_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-838-1 (dovecot)
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
  dovecot-common                  1:1.0.10-1ubuntu5.2

Ubuntu 8.10:
  dovecot-common                  1:1.1.4-0ubuntu1.3

Ubuntu 9.04:
  dovecot-common                  1:1.1.11-0ubuntu4.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-838-1";

tag_insight = "It was discovered that the ACL plugin in Dovecot would incorrectly handle
negative access rights. An attacker could exploit this flaw to access the
Dovecot server, bypassing the indended access restrictions. This only
affected Ubuntu 8.04 LTS. (CVE-2008-4577)

It was discovered that the ManageSieve service in Dovecot incorrectly
handled .. in script names. A remote attacker could exploit this to read
and modify arbitrary sieve files on the server. This only affected Ubuntu
8.10. (CVE-2008-5301)

It was discovered that the Sieve plugin in Dovecot incorrectly handled
certain sieve scripts. An authenticated user could exploit this with a
crafted sieve script to cause a denial of service or possibly execute
arbitrary code. (CVE-2009-2632, CVE-2009-3235)";
tag_summary = "The remote host is missing an update to dovecot
announced via advisory USN-838-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309740");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2008-4577", "CVE-2008-5301", "CVE-2009-2632", "CVE-2009-3235");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-838-1 (dovecot)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-838-1/");

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
if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.0.10-1ubuntu5.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1.0.10-1ubuntu5.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.0.10-1ubuntu5.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.0.10-1ubuntu5.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.1.4-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1.1.4-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.1.4-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.1.4-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-postfix", ver:"1.1.11-0ubuntu4.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.1.11-0ubuntu4.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1.1.11-0ubuntu4.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.1.11-0ubuntu4.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.1.11-0ubuntu4.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
