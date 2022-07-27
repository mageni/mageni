#
#VID 0f37d765-c5d4-11db-9f82-000e0c2e438a
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
tag_insight = "The following package is affected: openssl

CVE-2006-2937
OpenSSL 0.9.7 before 0.9.7l and 0.9.8 before 0.9.8d allows remote
attackers to cause a denial of service (infinite loop and memory
consumption) via malformed ASN.1 structures that trigger an improperly
handled error condition.
CVE-2006-2938
** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided.
CVE-2006-2940
OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions
allows attackers to cause a denial of service (CPU consumption) via
parasitic public keys with large (1) 'public exponent' or (2) 'public
modulus' values in X.509 certificates that require extra time to
process when using RSA signature verification.
CVE-2006-3738
Buffer overflow in the SSL_get_shared_ciphers function in OpenSSL
0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions has
unspecified impact and remote attack vectors involving a long list of
ciphers.
CVE-2006-4343
The get_server_hello function in the SSLv2 client code in OpenSSL
0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions allows
remote servers to cause a denial of service (client crash) via unknown
vectors that trigger a null pointer dereference.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300784");
 script_version("$Revision: 4144 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-26 07:28:56 +0200 (Mon, 26 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-2937", "CVE-2006-2938", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: openssl");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"openssl");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.7l_0")<0) {
    txt += 'Package openssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.8")>0 && revcomp(a:bver, b:"0.9.8d_0")<0) {
    txt += 'Package openssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
