#
#VID 21c223f2-d596-11da-8098-00123ffe8333
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
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2006-1932
Off-by-one error in the OID printing routine in Ethereal 0.10.x up to
0.10.14 has unknown impact and remote attack vectors.

CVE-2006-1933
Multiple unspecified vulnerabilities in Ethereal 0.10.x up to 0.10.14
allow remote attackers to cause a denial of service (large or infinite
loops) viarafted packets to the (1) UMA and (2) BER dissectors.

CVE-2006-1934
Multiple buffer overflows in Ethereal 0.10.x up to 0.10.14 allow
remote attackers to cause a denial of service (crash) and possibly
execute arbitrary code via the (1) ALCAP dissector, (2) Network
Instruments file code, or (3) NetXray/Windows Sniffer file code.

CVE-2006-1935
Buffer overflow in Ethereal 0.9.15 up to 0.10.14 allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via the COPS dissector.

CVE-2006-1936
Buffer overflow in Ethereal 0.8.5 up to 0.10.14 allows remote
attackers to execute arbitrary code via the telnet dissector.

CVE-2006-1937
Multiple unspecified vulnerabilities in Ethereal 0.10.x up to 0.10.14
allow remote attackers to cause a denial of service (crash from null
dereference) via the (1) H.248, (2) X.509if, (3) SRVLOC, (4) H.245,
(5) AIM, and (6) general packet dissectors; and (7) the statistics
counter.

CVE-2006-1938
Multiple unspecified vulnerabilities in Ethereal 0.8.x up to 0.10.14
allow remote attackers to cause a denial of service (crash from null
dereference) via the (1) Sniffer capture or (2) SMB PIPE dissector.

CVE-2006-1939
Multiple unspecified vulnerabilities in Ethereal 0.9.x up to 0.10.14
allow remote attackers to cause a denial of service (crash from null
dereference) via (1) an invalid display filter, or the (2) GSM SMS,
(3) ASN.1-based, (4) DCERPC NT, (5) PER, (6) RPC, (7) DCERPC, and (8)
ASN.1 dissectors.

CVE-2006-1940
Unspecified vulnerability in Ethereal 0.10.4 up to 0.10.14 allows
remote attackers to cause a denial of service (abort) via the SNDCP
dissector.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ethereal.com/appnotes/enpa-sa-00023.html
http://secunia.com/advisories/19769/
http://www.vuxml.org/freebsd/21c223f2-d596-11da-8098-00123ffe8333.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302917");
 script_version("$Revision: 4078 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-16 07:34:17 +0200 (Fri, 16 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: ethereal, ethereal-lite, tethereal, tethereal-lite");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.5")>=0 && revcomp(a:bver, b:"0.99.0")<0) {
    txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.5")>=0 && revcomp(a:bver, b:"0.99.0")<0) {
    txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.5")>=0 && revcomp(a:bver, b:"0.99.0")<0) {
    txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.5")>=0 && revcomp(a:bver, b:"0.99.0")<0) {
    txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
