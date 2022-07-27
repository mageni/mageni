# OpenVAS Vulnerability Test
# $Id: deb_2054_2.nasl 8274 2018-01-03 07:28:17Z teissa $
# Description: Auto-generated from advisory DSA 2054-2 (bind9)
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
tag_insight = "This update restores the PID file location for bind to the location
before the last security update.  For reference, here is the original
advisory text that explains the security problems fixed:

Several cache-poisoning vulnerabilities have been discovered in BIND.
These vulnerabilities are apply only if DNSSEC validation is enabled and
trust anchors have been installed, which is not the default.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2010-0097
BIND does not properly validate DNSSEC NSEC records, which allows
remote attackers to add the Authenticated Data (AD) flag to a forged
NXDOMAIN response for an existing domain.

CVE-2010-0290
When processing crafted responses containing CNAME or DNAME records,
BIND is subject to a DNS cache poisoning vulnerability, provided that
DNSSEC validation is enabled and trust anchors have been installed.

CVE-2010-0382
When processing certain responses containing out-of-bailiwick data,
BIND is subject to a DNS cache poisoning vulnerability, provided that
DNSSEC validation is enabled and trust anchors have been installed.

In addition, this update introduce a more conservative query behavior
in the presence of repeated DNSSEC validation failures, addressing the
roll over and die phenomenon.  The new version also supports the
cryptographic algorithm used by the upcoming signed ICANN DNS root
(RSASHA256 from RFC 5702), and the NSEC3 secure denial of existence
algorithm used by some signed top-level domains.

This update is based on a new upstream version of BIND 9, 9.6-ESV-R1.
Because of the scope of changes, extra care is recommended when
installing the update.  Due to ABI changes, new Debian packages are
included, and the update has to be installed using apt-get
dist-upgrade (or an equivalent aptitude command).

For the stable distribution (lenny), these problems have been fixed in
version 1:9.6.ESV.R1+dfsg-0+lenny2.

The unstable distribution is not affected by the wrong PID file location.

We recommend that you upgrade your bind9 packages.";
tag_summary = "The remote host is missing an update to bind9
announced via advisory DSA 2054-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202054-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312816");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
 script_name("Debian Security Advisory DSA 2054-2 (bind9)");



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
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9utils", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-40", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-50", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns45", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns55", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc45", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc52", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc40", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc50", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg40", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg50", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres40", ver:"9.5.1.dfsg.P3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres50", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.6.ESV.R1+dfsg-0+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
