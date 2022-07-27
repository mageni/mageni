# OpenVAS Vulnerability Test
# $Id: ubuntu_723_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_723_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-723-1 (git-core)
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
  git-core                        1.1.3-1ubuntu1.1

Ubuntu 7.10:
  git-core                        1:1.5.2.5-2ubuntu0.1
  gitweb                          1:1.5.2.5-2ubuntu0.1

Ubuntu 8.04 LTS:
  git-core                        1:1.5.4.3-1ubuntu2.1
  gitweb                          1:1.5.4.3-1ubuntu2.1

Ubuntu 8.10:
  git-core                        1:1.5.6.3-1.1ubuntu2.1
  gitweb                          1:1.5.6.3-1.1ubuntu2.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-723-1";

tag_insight = "It was discovered that Git did not properly handle long file paths. If a user
were tricked into performing commands on a specially crafted Git repository, an
attacker could possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-3546)

It was discovered that the Git web interface (gitweb) did not correctly handle
shell metacharacters when processing certain commands. A remote attacker could
send specially crafted commands to the Git server and execute arbitrary code
with the privileges of the Git web server. This issue only applied to Ubuntu
7.10 and 8.04 LTS. (CVE-2008-5516, CVE-2008-5517)

It was discovered that the Git web interface (gitweb) did not properly restrict
the diff.external configuration parameter. A local attacker could exploit this
issue and execute arbitrary code with the privileges of the Git web server.
This issue only applied to Ubuntu 8.04 LTS and 8.10. (CVE-2008-5916)";
tag_summary = "The remote host is missing an update to git-core
announced via advisory USN-723-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305247");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2008-3546", "CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916", "CVE-2008-3974", "CVE-2009-0318", "CVE-2008-5984", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358", "CVE-2009-0316", "CVE-2008-5557", "CVE-2008-5658", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5985", "CVE-2009-0544", "CVE-2008-3964", "CVE-2008-5907", "CVE-2009-0040", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2009-0520", "CVE-2008-4810", "CVE-2008-3663", "CVE-2007-5624", "CVE-2008-1360", "CVE-2007-5803", "CVE-2009-0187", "CVE-2007-3698", "CVE-2007-3922", "CVE-2008-5263", "CVE-2009-0615", "CVE-2009-0616", "CVE-2009-0617", "CVE-2009-0618", "CVE-2009-0620", "CVE-2009-0621", "CVE-2009-0622", "CVE-2009-0623", "CVE-2009-0624", "CVE-2009-0625", "CVE-2009-0490", "CVE-2009-0614", "CVE-2009-0542", "CVE-2009-0543", "CVE-2009-0478");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-723-1 (git-core)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-723-1/");

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
if ((res = isdpkgvuln(pkg:"git-doc", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-email", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitk", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-arch", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-cvs", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-svn", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-core", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-doc", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitk", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-arch", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-cvs", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-daemon-run", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-email", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-gui", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-p4", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-svn", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitweb", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-core", ver:"1.5.2.5-2ubuntu0.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-doc", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitk", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-arch", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-cvs", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-daemon-run", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-email", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-gui", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-svn", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitweb", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-core", ver:"1.5.4.3-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-doc", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitk", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-arch", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-cvs", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-daemon-run", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-email", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-gui", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-svn", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gitweb", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"git-core", ver:"1.5.6.3-1.1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-crypto-dbg", ver:"2.0.1+dfsg1-2.3+lenny0", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-crypto", ver:"2.0.1+dfsg1-2.3+lenny0", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.1-17lenny1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid-common", ver:"2.7.STABLE3-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid", ver:"2.7.STABLE3-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid-cgi", ver:"2.7.STABLE3-1ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
