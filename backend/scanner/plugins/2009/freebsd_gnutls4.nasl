#
#VID b31a1088-460f-11de-a11a-0022156e8794
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID b31a1088-460f-11de-a11a-0022156e8794
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
   gnutls
   gnutls-devel

CVE-2009-1415
lib/pk-libgcrypt.c in libgnutls in GnuTLS before 2.6.6 does not
properly handle invalid DSA signatures, which allows remote attackers
to cause a denial of service (application crash) and possibly have
unspecified other impact via a malformed DSA key that triggers a (1)
free of an uninitialized pointer or (2) double free.

CVE-2009-1416
lib/gnutls_pk.c in libgnutls in GnuTLS 2.5.0 through 2.6.5 generates
RSA keys stored in DSA structures, instead of the intended DSA keys,
which might allow remote attackers to spoof signatures on certificates
or have unspecified other impact by leveraging an invalid DSA key.

CVE-2009-1417
gnutls-cli in GnuTLS before 2.6.6 does not verify the activation and
expiration times of X.509 certificates, which allows remote attackers
to successfully present a certificate that is (1) not yet valid or (2)
no longer valid, related to lack of time checks in the
_gnutls_x509_verify_certificate function in lib/x509/verify.c in
libgnutls_x509, as used by (a) Exim, (b) OpenLDAP, and (c) libsoup.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://article.gmane.org/gmane.comp.encryption.gpg.gnutls.devel/3515
http://article.gmane.org/gmane.comp.encryption.gpg.gnutls.devel/3516
http://article.gmane.org/gmane.comp.encryption.gpg.gnutls.devel/3517
http://www.vuxml.org/freebsd/b31a1088-460f-11de-a11a-0022156e8794.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304983");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1415", "CVE-2009-1416", "CVE-2009-1417");
 script_bugtraq_id(34783);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: gnutls");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"gnutls");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.6")<0) {
    txt += 'Package gnutls version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gnutls-devel");
if(!isnull(bver) && revcomp(a:bver, b:"2.7.8")<0) {
    txt += 'Package gnutls-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
