# OpenVAS Vulnerability Test
# $Id: deb_1651_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1651-1 (ruby1.8)
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
tag_insight = "Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service and other
security problems. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-3655

Keita Yamaguchi discovered that several safe level restrictions
are insufficiently enforced.

CVE-2008-3656

Christian Neukirchen discovered that the WebRick module uses
inefficient algorithms for HTTP header splitting, resulting in
denial of service through resource exhaustion.

CVE-2008-3657

It was discovered that the dl module doesn't perform taintness
checks.

CVE-2008-3790

Luka Treiber and Mitja Kolsek discovered that recursively nested
XML entities can lead to denial of service through resource
exhaustion in rexml.

CVE-2008-3905

Tanaka Akira discovered that the resolv module uses sequential
transaction IDs and a fixed source port for DNS queries, which
makes it more vulnerable to DNS spoofing attacks.

For the stable distribution (etch), these problems have been fixed in
version 1.8.5-4etch3. Packages for arm will be provided later.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.7.72-1.

We recommend that you upgrade your ruby1.8 packages.";
tag_summary = "The remote host is missing an update to ruby1.8
announced via advisory DSA 1651-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201651-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302734");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
 script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1651-1 (ruby1.8)");



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
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.5-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
