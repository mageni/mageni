# OpenVAS Vulnerability Test
# $Id: deb_2077_1.nasl 8457 2018-01-18 07:58:32Z teissa $
# Description: Auto-generated from advisory DSA 2077-1 (openldap)
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
tag_insight = "Two remote vulnerabilities have been discovered in OpenLDAP.  The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2010-0211

The slap_modrdn2mods function in modrdn.c in OpenLDAP 2.4.22 does
not check the return value of a call to the smr_normalize
function, which allows remote attackers to cause a denial of
service (segmentation fault) and possibly execute arbitrary code
via a modrdn call with an RDN string containing invalid UTF-8
sequences.

CVE-2010-0212

OpenLDAP 2.4.22 allows remote attackers to cause a denial of
service (crash) via a modrdn call with a zero-length RDN
destination string.

For the stable distribution (lenny), this problem has been fixed in
version 2.4.11-1+lenny2.  (The missing update for the mips
architecture will be provided soon.)

For the unstable distribution (sid), this problem has been fixed in
version 2.4.23-1.

We recommend that you upgrade your openldap packages.";
tag_summary = "The remote host is missing an update to openldap
announced via advisory DSA 2077-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202077-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314773");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-0211", "CVE-2010-0212");
 script_name("Debian Security Advisory DSA 2077-1 (openldap)");



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
if ((res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"slapd", ver:"2.4.11-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
