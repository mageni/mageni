# OpenVAS Vulnerability Test
# $Id: ubuntu_856_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_856_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-856-1 (cupsys)
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
  cupsys                          1.2.2-0ubuntu0.6.06.15

Ubuntu 8.04 LTS:
  cupsys                          1.3.7-1ubuntu3.6

Ubuntu 8.10:
  cups                            1.3.9-2ubuntu9.3

Ubuntu 9.04:
  cups                            1.3.9-17ubuntu3.4

Ubuntu 9.10:
  cups                            1.4.1-5ubuntu2.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-856-1";

tag_insight = "Aaron Sigel discovered that the CUPS web interface incorrectly protected
against cross-site scripting (XSS) and cross-site request forgery (CSRF)
attacks. If an authenticated user were tricked into visiting a malicious
website while logged into CUPS, a remote attacker could modify the CUPS
configuration and possibly steal confidential data.";
tag_summary = "The remote host is missing an update to cupsys
announced via advisory USN-856-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304766");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-2820");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Ubuntu USN-856-1 (cupsys)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-856-1/");

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
if ((res = isdpkgvuln(pkg:"libcupsys2-gnutls10", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.2.2-0ubuntu0.6.06.15", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.3.7-1ubuntu3.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-common", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-client", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.3.9-2ubuntu9.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-common", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-client", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.3.9-17ubuntu3.4", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-common", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsddk", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-client", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcups2", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupscgi1-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupscgi1", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsdriver1-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsdriver1", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsmime1-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsmime1", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsppdc1-dev", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsppdc1", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cups-ppdc", ver:"1.4.1-5ubuntu2.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
