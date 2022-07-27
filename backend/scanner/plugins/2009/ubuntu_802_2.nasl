# OpenVAS Vulnerability Test
# $Id: ubuntu_802_2.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_802_2.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-802-2 (apache2)
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
  apache2-common                  2.0.55-4ubuntu2.8
  apache2-mpm-perchild            2.0.55-4ubuntu2.8
  apache2-mpm-prefork             2.0.55-4ubuntu2.8
  apache2-mpm-worker              2.0.55-4ubuntu2.8
  libapr0                         2.0.55-4ubuntu2.8

Ubuntu 8.04 LTS:
  apache2-mpm-event               2.2.8-1ubuntu0.11
  apache2-mpm-perchild            2.2.8-1ubuntu0.11
  apache2-mpm-prefork             2.2.8-1ubuntu0.11
  apache2-mpm-worker              2.2.8-1ubuntu0.11
  apache2.2-common                2.2.8-1ubuntu0.11

Ubuntu 8.10:
  apache2-mpm-event               2.2.9-7ubuntu3.3
  apache2-mpm-prefork             2.2.9-7ubuntu3.3
  apache2-mpm-worker              2.2.9-7ubuntu3.3
  apache2.2-common                2.2.9-7ubuntu3.3

Ubuntu 9.04:
  apache2-mpm-event               2.2.11-2ubuntu2.3
  apache2-mpm-prefork             2.2.11-2ubuntu2.3
  apache2-mpm-worker              2.2.11-2ubuntu2.3
  apache2.2-common                2.2.11-2ubuntu2.3

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-802-2";

tag_insight = "USN-802-1 fixed vulnerabilities in Apache. The upstream fix for
CVE-2009-1891 introduced a regression that would cause Apache children to
occasionally segfault when mod_deflate is used. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that mod_proxy_http did not properly handle a large
 amount of streamed data when used as a reverse proxy. A remote attacker
 could exploit this and cause a denial of service via memory resource
 consumption. This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04.
 (CVE-2009-1890)
 
 It was discovered that mod_deflate did not abort compressing large files
 when the connection was closed. A remote attacker could exploit this and
 cause a denial of service via CPU resource consumption. (CVE-2009-1891)";
tag_summary = "The remote host is missing an update to apache2
announced via advisory USN-802-2.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305104");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1891", "CVE-2009-1890");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("Ubuntu USN-802-2 (apache2)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-802-2/");

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
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0", ver:"2.0.55-4ubuntu2.8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.11", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-7ubuntu3.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.11-2ubuntu2.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
