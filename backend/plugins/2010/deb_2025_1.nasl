# OpenVAS Vulnerability Test
# $Id: deb_2025_1.nasl 8495 2018-01-23 07:57:49Z teissa $
# Description: Auto-generated from advisory DSA 2025-1 (icedove)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird mail client. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2009-2408

Dan Kaminsky and Moxie Marlinspike discovered that icedove does not
properly handle a '\0' character in a domain name in the subject's
Common Name (CN) field of an X.509 certificate (MFSA 2009-42).

CVE-2009-2404

Moxie Marlinspike reported a heap overflow vulnerability in the code
that handles regular expressions in certificate names (MFSA 2009-43).

CVE-2009-2463

monarch2020 discovered an integer overflow n a base64 decoding function
(MFSA 2010-07).

CVE-2009-3072

Josh Soref discovered a crash in the BinHex decoder (MFSA 2010-07).

CVE-2009-3075

Carsten Book reported a crash in the JavaScript engine (MFSA 2010-07).

CVE-2010-0163

Ludovic Hirlimann reported a crash indexing some messages with
attachments, which could lead to the execution of arbitrary code
(MFSA 2010-07).


For the stable distribution (lenny), these problems have been fixed in
version 2.0.0.24-0lenny1.

Due to a problem with the archive system it is not possible to release
all architectures. The missing architectures will be installed into the
archive once they become available.

For the testing distribution squeeze and the unstable distribution (sid),
these problems will be fixed soon.


We recommend that you upgrade your icedove packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 2025-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202025-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312860");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-06 21:31:38 +0200 (Tue, 06 Apr 2010)");
 script_cve_id("CVE-2009-2408", "CVE-2009-2404", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2010-0163");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 2025-1 (icedove)");



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
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"2.0.0.24-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"2.0.0.24-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"2.0.0.24-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"2.0.0.24-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
