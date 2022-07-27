# OpenVAS Vulnerability Test
# $Id: deb_568_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 568-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "A vulnerability has been discovered in the Cyrus implementation of the
SASL library, the Simple Authentication and Security Layer, a method
for adding authentication support to connection-based protocols.  The
library honors the environment variable SASL_PATH blindly, which
allows a local user to link against a malicious library to run
arbitrary code with the privileges of a setuid or setgid application.

The MIT version of the Cyrus implementation of the SASL library
provides bindings against MIT GSSAPI and MIT Kerberos4.

For the stable distribution (woody) this problem has been fixed in
version 1.5.24-15woody3.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your libsasl packages.";
tag_summary = "The remote host is missing an update to cyrus-sasl-mit
announced via advisory DSA 568-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20568-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300595");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(11347);
 script_cve_id("CVE-2004-0884");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 568-1 (cyrus-sasl-mit)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libsasl-gssapi-mit", ver:"1.5.24-15woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl-krb4-mit", ver:"1.5.24-15woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
