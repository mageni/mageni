###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2009:1335 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016149.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880738");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0590", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379",
                "CVE-2009-1386", "CVE-2009-1387");
  script_name("CentOS Update for openssl CESA-2009:1335 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"openssl on CentOS 5");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a full-strength
  general purpose cryptography library. Datagram TLS (DTLS) is a protocol
  based on TLS that is capable of securing datagram transport (for example,
  UDP).

  Multiple denial of service flaws were discovered in OpenSSL's DTLS
  implementation. A remote attacker could use these flaws to cause a DTLS
  server to use excessive amounts of memory, or crash on an invalid memory
  access or NULL pointer dereference. (CVE-2009-1377, CVE-2009-1378,
  CVE-2009-1379, CVE-2009-1386, CVE-2009-1387)

  Note: These flaws only affect applications that use DTLS. Red Hat does not
  ship any DTLS client or server applications in Red Hat Enterprise Linux.

  An input validation flaw was found in the handling of the BMPString and
  UniversalString ASN1 string types in OpenSSL's ASN1_STRING_print_ex()
  function. An attacker could use this flaw to create a specially-crafted
  X.509 certificate that could cause applications using the affected function
  to crash when printing certificate contents. (CVE-2009-0590)

  Note: The affected function is rarely used. No application shipped with Red
  Hat Enterprise Linux calls this function, for example.

  These updated packages also fix the following bugs:

  * 'openssl smime -verify -in' verifies the signature of the input file and
  the '-verify' switch expects a signed or encrypted input file. Previously,
  running openssl on an S/MIME file that was not encrypted or signed caused
  openssl to segfault. With this update, the input file is now checked for a
  signature or encryption. Consequently, openssl now returns an error and
  quits when attempting to verify an unencrypted or unsigned S/MIME file.
  (BZ#472440)

  * when generating RSA keys, pairwise tests were called even in non-FIPS
  mode. This prevented small keys from being generated. With this update,
  generating keys in non-FIPS mode no longer calls the pairwise tests and
  keys as small as 32-bits can be generated in this mode. Note: In FIPS mode,
  pairwise tests are still called and keys generated in this mode must still
  be 1024-bits or larger. (BZ#479817)

  As well, these updated packages add the following enhancements:

  * both the libcrypto and libssl shared libraries, which are part of the
  OpenSSL FIPS module, are now checked for integrity on initialization of
  FIPS mode. (BZ#475798)

  * an issuing Certificate Authority (CA) allows multiple certificate
  templates to inherit the CA's Common Name (CN). Be ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~12.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~12.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~12.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
