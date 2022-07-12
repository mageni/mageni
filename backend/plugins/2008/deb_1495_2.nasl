# OpenVAS Vulnerability Test
# $Id: deb_1495_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1495-2 (nagios-plugins)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "A problem with the build system of the nagios-plugins package from old
stable (Sarge) lead to check_procs not being included for the i386
architecture. This update fixes this regression. For reference the
original advisory text below:

Several local/remote vulnerabilities have been discovered in two of
the plugins for the Nagios network monitoring and management system.
The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-5198

A buffer overflow has been discovered in the parser for HTTP
Location headers (present in the check_http module).

CVE-2007-5623

A buffer overflow has been discovered in the check_snmp module.

For the stable distribution (etch), these problems have been fixed in
version 1.4.5-1etch1.

For the old stable distribution (sarge), these problems have been
fixed in version 1.4-6sarge2.

We recommend that you upgrade your nagios-plugins package.";
tag_summary = "The remote host is missing an update to nagios-plugins
announced via advisory DSA 1495-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201495-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302987");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-5198", "CVE-2007-5623");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1495-2 (nagios-plugins)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"nagios-plugins", ver:"1.4-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
