# OpenVAS Vulnerability Test
# $Id: ubuntu_826_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_826_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-826-1 (mono)
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
  libmono-security1.0-cil         1.2.6+dfsg-6ubuntu3.1
  libmono-security2.0-cil         1.2.6+dfsg-6ubuntu3.1
  libmono-system-web1.0-cil       1.2.6+dfsg-6ubuntu3.1
  libmono-system-web2.0-cil       1.2.6+dfsg-6ubuntu3.1

Ubuntu 8.10:
  libmono-security1.0-cil         1.9.1+dfsg-4ubuntu2.1
  libmono-security2.0-cil         1.9.1+dfsg-4ubuntu2.1
  libmono-system-web1.0-cil       1.9.1+dfsg-4ubuntu2.1
  libmono-system-web2.0-cil       1.9.1+dfsg-4ubuntu2.1

Ubuntu 9.04:
  libmono-security1.0-cil         2.0.1-4ubuntu0.1
  libmono-security2.0-cil         2.0.1-4ubuntu0.1
  libmono-system-web1.0-cil       2.0.1-4ubuntu0.1
  libmono-system-web2.0-cil       2.0.1-4ubuntu0.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-826-1";

tag_insight = "It was discovered that the XML HMAC signature system did not correctly
check certain lengths. If an attacker sent a truncated HMAC, it could
bypass authentication, leading to potential privilege escalation.
(CVE-2009-0217)

It was discovered that Mono did not properly escape certain attributes in
the ASP.net class libraries which could result in browsers becoming
vulnerable to cross-site scripting attacks when processing the output. With
cross-site scripting vulnerabilities, if a user were tricked into viewing
server output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain. This issue only affected Ubuntu 8.04
LTS. (CVE-2008-3422)

It was discovered that Mono did not properly filter CRLF injections in the
query string. If a user were tricked into viewing server output during a
crafted server request, a remote attacker could exploit this to modify the
contents, steal confidential data (such as passwords), or perform
cross-site request forgeries. This issue only affected Ubuntu 8.04 LTS.
(CVE-2008-3906)";
tag_summary = "The remote host is missing an update to mono
announced via advisory USN-826-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304448");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2008-3422", "CVE-2008-3906", "CVE-2009-0217");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Ubuntu USN-826-1 (mono)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-826-1/");

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
if ((res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-mozilla0.1-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-dbg", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gac", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gmcs", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mcs", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-c5-1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.1-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.1-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-service", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-service", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mjs", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-smcs", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-xbuild", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"prj2make-sharp", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-dev", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0-dbg", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-common", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jay", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit-dbg", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-runtime", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-utils", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-mozilla0.2-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-nunit2.2-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-dbg", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gac", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gmcs", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mcs", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-c5-1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.1-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.1-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-service", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-service", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mjs", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-smcs", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-xbuild", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"prj2make-sharp", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-dev", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0-dbg", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-common", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jay", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit-dbg", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-runtime", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-utils", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-getoptions1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-getoptions2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-nunit2.2-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-posix1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-webbrowser0.5-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-gac", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-devel", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gac", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mcs", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-c5-1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.1-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.1-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-service", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-dbg", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mjs", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-smcs", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"prj2make-sharp", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-dev", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0-dbg", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-2.0-runtime", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-common", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jay", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit-dbg", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-runtime", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-utils", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-1.0-runtime", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
