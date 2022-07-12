#
#VID 8a835235-ae84-11dc-a5f9-001a4d49522b
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following packages are affected:
   wireshark
   wireshark-lite
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2007-6438
Unspecified vulnerability in the SMB dissector in Wireshark (formerly
Ethereal) 0.99.6 allows remote attackers to cause a denial of service
via unknown vectors.  NOTE: this identifier originally included MP3
and NCP, but those issues are already covered by CVE-2007-6111.

CVE-2007-6439
Wireshark (formerly Ethereal) 0.99.6 allows remote attackers to cause
a denial of service (infinite or large loop) via the (1) IPv6 or (2)
USB dissector, which can trigger resource consumption or a crash.
NOTE: this identifier originally included Firebird/Interbase, but it
is already covered by CVE-2007-6116.  The DCP ETSI issue is already
covered by CVE-2007-6119.

CVE-2007-6441
The WiMAX dissector in Wireshark (formerly Ethereal) 0.99.6 allows
remote attackers to cause a denial of service (crash) via unknown
vectors related to 'unaligned access on some platforms.'

CVE-2007-6450
The RPL dissector in Wireshark (formerly Ethereal) 0.9.8 to 0.99.6
allows remote attackers to cause a denial of service (infinite loop)
via unknown vectors.

CVE-2007-6451
Unspecified vulnerability in the CIP dissector in Wireshark (formerly
Ethereal) 0.9.14 to 0.99.6 allows remote attackers to cause a denial
of service (crash) via unknown vectors that trigger allocation of
large amounts of memory.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.wireshark.org/security/wnpa-sec-2007-03.html
http://www.vuxml.org/freebsd/8a835235-ae84-11dc-a5f9-001a4d49522b.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301446");
 script_version("$Revision: 4203 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-04 07:30:30 +0200 (Tue, 04 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("wireshark -- multiple vulnerabilities");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
    txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
