# OpenVAS Vulnerability Test
# $Id: deb_1171_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1171-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge8.

For the unstable distribution (sid) these problems have been fixed in
version 0.99.2-5.1 of wireshark, the network sniffer formerly known as
ethereal.

We recommend that you upgrade your ethereal packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201171-1";
tag_summary = "The remote host is missing an update to ethereal
announced via advisory DSA 1171-1.

Several remote vulnerabilities have been discovered in the Ethereal network
scanner, which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4333

It was discovered that the Q.2391 dissector is vulnerable to denial
of service caused by memory exhaustion.

CVE-2005-3241

It was discovered that the FC-FCS, RSVP and ISIS-LSP dissectors are
vulnerable to denial of service caused by memory exhaustion.

CVE-2005-3242

It was discovered that the IrDA and SMB dissectors are vulnerable to
denial of service caused by memory corruption.

CVE-2005-3243

It was discovered that the SLIMP3 and AgentX dissectors are vulnerable
to code injection caused by buffer overflows.

CVE-2005-3244

It was discovered that the BER dissector is vulnerable to denial of
service caused by an infinite loop.

CVE-2005-3246

It was discovered that the NCP and RTnet dissectors are vulnerable to
denial of service caused by a null pointer dereference.

CVE-2005-3248

It was discovered that the X11 dissector is vulnerable denial of service
caused by a division through zero.

This update also fixes a 64 bit-specific regression in the ASN.1 decoder, which
has been introduced in a previous DSA.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301464");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-4333", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3246", "CVE-2005-3248");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1171-1 (ethereal)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge8", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge8", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
