# OpenVAS Vulnerability Test
# $Id: ubuntu_788_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_788_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-788-1 (tomcat6)
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

Ubuntu 8.10:
  libtomcat6-java                 6.0.18-0ubuntu3.2
  tomcat6-examples                6.0.18-0ubuntu3.2

Ubuntu 9.04:
  libtomcat6-java                 6.0.18-0ubuntu6.1
  tomcat6-examples                6.0.18-0ubuntu6.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-788-1";

tag_insight = "Iida Minehiko discovered that Tomcat did not properly normalise paths. A
remote attacker could send specially crafted requests to the server and
bypass security restrictions, gaining access to sensitive content.
(CVE-2008-5515)

Yoshihito Fukuyama discovered that Tomcat did not properly handle errors
when the Java AJP connector and mod_jk load balancing are used. A remote
attacker could send specially crafted requests containing invalid headers
to the server and cause a temporary denial of service. (CVE-2009-0033)

D. Matscheko and T. Hackner discovered that Tomcat did not properly handle
malformed URL encoding of passwords when FORM authentication is used. A
remote attacker could exploit this in order to enumerate valid usernames.
(CVE-2009-0580)

Deniz Cevik discovered that Tomcat did not properly escape certain
parameters in the example calendar application which could result in
browsers becoming vulnerable to cross-site scripting attacks when
processing the output. With cross-site scripting vulnerabilities, if a user
were tricked into viewing server output during a crafted server request, a
remote attacker could exploit this to modify the contents, or steal
confidential data (such as passwords), within the same domain.
(CVE-2009-0781)

Philippe Prados discovered that Tomcat allowed web applications to replace
the XML parser used by other web applications. Local users could exploit
this to bypass security restrictions and gain access to certain sensitive
files. (CVE-2009-0783)";
tag_summary = "The remote host is missing an update to tomcat6
announced via advisory USN-788-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309938");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Ubuntu USN-788-1 (tomcat6)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-788-1/");

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
if ((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
