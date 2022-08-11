###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libreswan CESA-2015:1979 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882312");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-11-05 06:16:02 +0100 (Thu, 05 Nov 2015)");
  script_cve_id("CVE-2015-3240");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libreswan CESA-2015:1979 centos7");
  script_tag(name:"summary", value:"Check the version of libreswan");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Libreswan is an implementation of IPsec &amp  IKE for Linux. IPsec is the
Internet Protocol Security and uses strong cryptography to provide both
authentication and encryption services. These services allow you to build
secure tunnels through untrusted networks such as virtual private network
(VPN).

A flaw was discovered in the way Libreswan's IKE daemon processed IKE KE
payloads. A remote attacker could send specially crafted IKE payload with a
KE payload of g^x=0 that, when processed, would lead to a denial of service
(daemon crash). (CVE-2015-3240)

This issue was discovered by Paul Wouters of Red Hat.

Note: Please note that when upgrading from an earlier version of Libreswan,
the existing CA certificates in the /etc/ipsec.d/cacerts/ directory and the
existing certificate revocation list (CRL) files from the
/etc/ipsec.d/crls/ directory are automatically imported into the NSS
database. Once completed, these directories are no longer used by
Libreswan. To install new CA certificates or new CRLS, the certutil and
crlutil commands must be used to import these directly into the Network
Security Services (NSS) database.

This update also adds the following enhancements:

  * This update adds support for RFC 7383 IKEv2 Fragmentation, RFC 7619 Auth
Null and ID Null, INVALID_KE renegotiation, CRL and OCSP support via NSS,
AES_CTR and AES_GCM support for IKEv2, CAVS testing for FIPS compliance.

In addition, this update enforces FIPS algorithms restrictions in FIPS
mode, and runs Composite Application Validation System (CAVS) testing for
FIPS compliance during package build. A new Cryptographic Algorithm
Validation Program (CAVP) binary can be used to re-run the CAVS tests at
any time. Regardless of FIPS mode, the pluto daemon runs RFC test vectors
for various algorithms.

Furthermore, compiling on all architectures now enables the '-Werror' GCC
option, which enhances the security by making all warnings into errors.
(BZ#1263346)

  * This update also fixes several memory leaks and introduces a sub-second
packet retransmit option. (BZ#1268773)

  * This update improves migration support from Openswan to Libreswan.
Specifically, all Openswan options that can take a time value without a
suffix are now supported, and several new keywords for use in the
/etc/ipsec.conf file have been introduced. See the relevant man pages for
details. (BZ#1268775)

  * With this update, loopback support via the 'loopback=' option has been
deprecated. (BZ#1270673)

All Libreswan users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"affected", value:"libreswan on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-November/021462.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.15~5.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
