# OpenVAS Vulnerability Test
# $Id: deb_1930_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1930-1 (drupal6)
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
tag_insight = "Several vulnerabilities have been found in drupal6, a fully-featured
content management framework. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-2372

Gerhard Killesreiter discovered a flaw in the way user signatures are
handled. It is possible for a user to inject arbitrary code via a
crafted user signature. (SA-CORE-2009-007)

CVE-2009-2373

Mark Piper, Sven Herrmann and Brandon Knight discovered a cross-site
scripting issue in the forum module, which could be exploited via the
tid parameter. (SA-CORE-2009-007)

CVE-2009-2374

Sumit Datta discovered that certain drupal6 pages leak sensible
information such as user credentials. (SA-CORE-2009-007)


Several design flaws in the OpenID module have been fixed, which could
lead to cross-site request forgeries or privilege escalations. Also, the
file upload function does not process all extensions properly leading
to the possible execution of arbitrary code.
(SA-CORE-2009-008)


For the stable distribution (lenny), these problems have been fixed in
version 6.6-3lenny3.

The oldstable distribution (etch) does not contain drupal6.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 6.14-1.


We recommend that you upgrade your drupal6 packages.";
tag_summary = "The remote host is missing an update to drupal6
announced via advisory DSA 1930-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201930-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308795");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-2372", "CVE-2009-2373", "CVE-2009-2374");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1930-1 (drupal6)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"drupal6", ver:"6.6-3lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
