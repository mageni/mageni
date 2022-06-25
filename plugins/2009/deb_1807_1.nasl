# OpenVAS Vulnerability Test
# $Id: deb_1807_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1807-1 (cyrus-sasl2, cyrus-sasl2-heimdal)
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
tag_insight = "James Ralston discovered that the sasl_encode64() function of cyrus-sasl2,
a free library implementing the Simple Authentication and Security Layer,
suffers from a missing null termination in certain situations.  This causes
several buffer overflows in situations where cyrus-sasl2 itself requires
the string to be null terminated which can lead to denial of service or
arbitrary code execution.

Important notice (Quoting from US-CERT):
While this patch will fix currently vulnerable code, it can cause
non-vulnerable existing code to break. Here's a function prototype from
include/saslutil.h to clarify my explanation:

/* base64 encode
* in -- input data
* inlen -- input data length
* out -- output buffer (will be NUL terminated)
* outmax -- max size of output buffer
* result:
* outlen -- gets actual length of output buffer (optional)
*
* Returns SASL_OK on success, SASL_BUFOVER if result won't fit
*/
LIBSASL_API int sasl_encode64(const char *in, unsigned inlen,
char *out, unsigned outmax,
unsigned *outlen);

Assume a scenario where calling code has been written in such a way that it
calculates the exact size required for base64 encoding in advance, then
allocates a buffer of that exact size, passing a pointer to the buffer into
sasl_encode64() as *out. As long as this code does not anticipate that the
buffer is NUL-terminated (does not call any string-handling functions like
strlen(), for example) the code will work and it will not be vulnerable.

Once this patch is applied, that same code will break because sasl_encode64()
will begin to return SASL_BUFOVER.


For the oldstable distribution (etch), this problem will be fixed soon.

For the stable distribution (lenny), this problem has been fixed in
version 2.1.22.dfsg1-23+lenny1 of cyrus-sasl2 and cyrus-sasl2-heimdal.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.23.dfsg1-1 of cyrus-sasl2 and cyrus-sasl2-heimdal.


We recommend that you upgrade your cyrus-sasl2/cyrus-sasl2-heimdal packages.";
tag_summary = "The remote host is missing an update to cyrus-sasl2, cyrus-sasl2-heimdal
announced via advisory DSA 1807-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201807-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304920");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1807-1 (cyrus-sasl2, cyrus-sasl2-heimdal)");



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
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-heimdal-dbg", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
