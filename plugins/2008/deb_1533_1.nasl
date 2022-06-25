# OpenVAS Vulnerability Test
# $Id: deb_1533_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1533-1 (exiftags)
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
tag_insight = "Christian Schmid and Meder Kydyraliev (Google Security) discovered a
number of vulnerabilities in exiftags, a utility for extracting EXIF
metadata from JPEG images. The Common Vulnerabilities and Exposures
project identified the following three problems:

CVE-2007-6354

Inadequate EXIF property validation could lead to invalid memory
accesses if executed on a maliciously crafted image, potentially
including heap corruption and the execution of arbitrary code.

CVE-2007-6355

Flawed data validation could lead to integer overflows, causing
other invalid memory accesses, also with the potential for memory
corruption or arbitrary code execution.

CVE-2007-6356

Cyclical EXIF image file directory (IFD) references could cause
a denial of service (infinite loop).

For the stable distribution (etch), these problems have been fixed in
version 0.98-1.1+etch1.

The old stable distribution (sarge) cannot be fixed synchronously
with the Etch version due to a technical limitation in the Debian
archive management scripts.

For the unstable distribution (sid), these problems have been fixed in
version 1.01-0.1.

We recommend that you upgrade your exiftags package.";
tag_summary = "The remote host is missing an update to exiftags
announced via advisory DSA 1533-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201533-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304267");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-07 20:38:54 +0200 (Mon, 07 Apr 2008)");
 script_cve_id("CVE-2007-6354", "CVE-2007-6355", "CVE-2007-6356");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1533-1 (exiftags)");



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
if ((res = isdpkgvuln(pkg:"exiftags", ver:"0.98-1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
