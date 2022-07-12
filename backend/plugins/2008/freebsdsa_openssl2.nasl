#
#ADV FreeBSD-SA-05:21.openssl.asc
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
#

tag_insight = "The OpenSSL library implements the Secure Sockets Layer and Transport
Layer Security protocols, as well as providing a large number of basic
cryptographic functions.

The Secure Sockets Layer protocol exists in two versions and includes a
mechanism for negotiating the protocol version to be used.  If the
protocol is executed correctly, it is impossible for a client and
server both capable of the newer version of the protocol (SSLv3) to end
up using the older version of the protocol (SSLv2).

In order to provide bug-for-bug compatibility with Microsoft Internet
Explorer 3.02, a verification step required by the Secure Sockets Layer
protocol can be disabled by using the SSL_OP_MSIE_SSLV2_RSA_PADDING
option in OpenSSL.  This option is implied by the frequently-used
SSL_OP_ALL option.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-05:21.openssl.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-05:21.openssl.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304186");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(15647, 15071);
 script_cve_id("CVE-2005-2969");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 name = "FreeBSD Security Advisory (FreeBSD-SA-05:21.openssl.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
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
vuln = 0;
if(patchlevelcmp(rel:"5.4", patchlevel:"8")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"23")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"13")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"19")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
