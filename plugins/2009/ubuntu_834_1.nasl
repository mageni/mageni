# OpenVAS Vulnerability Test
# $Id: ubuntu_834_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_834_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-834-1 (postgresql-8.3)
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
tag_summary = "The remote host is missing an update to postgresql-8.3
announced via advisory USN-834-1.
";

tag_insight = "It was discovered that PostgreSQL could be made to unload and reload an
already loaded module by using the LOAD command. A remote authenticated
attacker could exploit this to cause a denial of service. This issue did
not affect Ubuntu 6.06 LTS. (CVE-2009-3229)

Due to an incomplete fix for CVE-2007-6600, RESET ROLE and RESET SESSION
AUTHORIZATION operations were allowed inside security-definer functions. A
remote authenticated attacker could exploit this to escalate privileges
within PostgreSQL. (CVE-2009-3230)

It was discovered that PostgreSQL did not properly perform LDAP
authentication under certain circumstances. When configured to use LDAP
with anonymous binds, a remote attacker could bypass authentication by
supplying an empty password. This issue did not affect Ubuntu 6.06 LTS.
(CVE-2009-3231)";

tag_solution = "The problem can be corrected by upgrading your system to the
following package versions:

Ubuntu 6.06 LTS:
  postgresql-8.1                  8.1.18-0ubuntu0.6.06

Ubuntu 8.04 LTS:
  postgresql-8.3                  8.3.8-0ubuntu8.04

Ubuntu 8.10:
  postgresql-8.3                  8.3.8-0ubuntu8.10

Ubuntu 9.04:
  postgresql-8.3                  8.3.8-0ubuntu9.04

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-834-1";
                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307377");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
 script_cve_id("CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231", "CVE-2007-6600");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-834-1 (postgresql-8.3)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-834-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
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
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg5", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq4", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.1", ver:"8.1.18-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.3", ver:"8.3.8-0ubuntu8.04", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.3", ver:"8.3.8-0ubuntu8.10", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.3", ver:"8.3.8-0ubuntu9.04", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
