# OpenVAS Vulnerability Test
# $Id: deb_1986_1.nasl 8269 2018-01-02 07:28:22Z teissa $
# Description: Auto-generated from advisory DSA 1986-1 (moodle)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in Moodle, an online
course management system. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-4297

Multiple cross-site request forgery (CSRF) vulnerabilities have been
discovered.

CVE-2009-4298

It has been discovered that the LAMS module is prone to the disclosure
of user account information.

CVE-2009-4299

The Glossary module has an insufficient access control mechanism.

CVE-2009-4301

Moodle does not properly check permissions when the MNET service is
enabled, which allows remote authenticated servers to execute arbitrary
MNET functions.

CVE-2009-4302

The login/index_form.html page links to an HTTP page instead of using an
SSL secured connection.

CVE-2009-4303

Moodle stores sensitive data in backup files, which might make it
possible for attackers to obtain them.

CVE-2009-4305

It has been discovered that the SCORM module is prone to an SQL
injection.

Additionally, an SQL injection in the update_record function, a problem
with symbolic links and a verification problem with Glossary, database
and forum ratings have been fixed.


For the stable distribution (lenny), these problems have been fixed in
version 1.8.2.dfsg-3+lenny3.

For the oldstable distribution (etch), there are no fixed packages
available and it is too hard to backport many of the fixes. Therefore,
we recommend to upgrade to the lenny version.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 1.8.2.dfsg-6.


We recommend that you upgrade your moodle packages.";
tag_summary = "The remote host is missing an update to moodle
announced via advisory DSA 1986-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201986-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313613");
 script_version("$Revision: 8269 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2009-4297", "CVE-2009-4298", "CVE-2009-4299", "CVE-2009-4301", "CVE-2009-4302", "CVE-2009-4303", "CVE-2009-4305");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1986-1 (moodle)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
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
if ((res = isdpkgvuln(pkg:"moodle", ver:"1.8.2.dfsg-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
