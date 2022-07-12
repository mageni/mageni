# OpenVAS Vulnerability Test
# $Id: ubuntu_716_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# $Id: ubuntu_716_1.nasl 8616 2018-02-01 08:24:13Z cfischer $
# Description: Auto-generated from advisory USN-716-1 (moin)
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
  python2.4-moinmoin              1.5.2-1ubuntu2.4

Ubuntu 7.10:
  python-moinmoin                 1.5.7-3ubuntu2.1

Ubuntu 8.04 LTS:
  python-moinmoin                 1.5.8-5.1ubuntu2.2

Ubuntu 8.10:
  python-moinmoin                 1.7.1-1ubuntu1.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-716-1";

tag_insight = "Fernando Quintero discovered than MoinMoin did not properly sanitize its
input when processing login requests, resulting in cross-site scripting (XSS)
vulnerabilities. With cross-site scripting vulnerabilities, if a user were
tricked into viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal confidential data,
within the same domain. This issue affected Ubuntu 7.10 and 8.04 LTS.
(CVE-2008-0780)

Fernando Quintero discovered that MoinMoin did not properly sanitize its input
when attaching files, resulting in cross-site scripting vulnerabilities. This
issue affected Ubuntu 6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0781)

It was discovered that MoinMoin did not properly sanitize its input when
processing user forms. A remote attacker could submit crafted cookie values and
overwrite arbitrary files via directory traversal. This issue affected Ubuntu
6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0782)

It was discovered that MoinMoin did not properly sanitize its input when
editing pages, resulting in cross-site scripting vulnerabilities. This issue
only affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1098)

It was discovered that MoinMoin did not properly enforce access controls,
which could allow a remoter attacker to view private pages. This issue only
affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1099)

It was discovered that MoinMoin did not properly sanitize its input when
attaching files and using the rename parameter, resulting in cross-site
scripting vulnerabilities. (CVE-2009-0260)

It was discovered that MoinMoin did not properly sanitize its input when
displaying error messages after processing spam, resulting in cross-site
scripting vulnerabilities. (CVE-2009-0312)";
tag_summary = "The remote host is missing an update to moin
announced via advisory USN-716-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309049");
 script_version("$Revision: 8616 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 09:24:13 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099", "CVE-2009-0260", "CVE-2009-0312");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Ubuntu USN-716-1 (moin)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-716-1/");

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
if ((res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.2-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.2-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-moinmoin", ver:"1.5.2-1ubuntu2.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.7-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.7-3ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.8-5.1ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.8-5.1ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.7.1-1ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(port:0, data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
