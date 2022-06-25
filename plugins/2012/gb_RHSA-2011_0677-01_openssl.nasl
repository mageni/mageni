###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssl RHSA-2011:0677-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870609");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:33:54 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-0014");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for openssl RHSA-2011:0677-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"openssl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  A buffer over-read flaw was discovered in the way OpenSSL parsed the
  Certificate Status Request TLS extensions in ClientHello TLS handshake
  messages. A remote attacker could possibly use this flaw to crash an SSL
  server using the affected OpenSSL functionality. (CVE-2011-0014)

  This update fixes the following bugs:

  * The 'openssl speed' command (which provides algorithm speed measurement)
  failed when openssl was running in FIPS (Federal Information Processing
  Standards) mode, even if testing of FIPS approved algorithms was requested.
  FIPS mode disables ciphers and cryptographic hash algorithms that are not
  approved by the NIST (National Institute of Standards and Technology)
  standards. With this update, the 'openssl speed' command no longer fails.
  (BZ#619762)

  * The 'openssl pkcs12 -export' command failed to export a PKCS#12 file in
  FIPS mode. The default algorithm for encrypting a certificate in the
  PKCS#12 file was not FIPS approved and thus did not work. The command now
  uses a FIPS approved algorithm by default in FIPS mode. (BZ#673453)

  This update also adds the following enhancements:

  * The 'openssl s_server' command, which previously accepted connections
  only over IPv4, now accepts connections over IPv6. (BZ#601612)

  * For the purpose of allowing certain maintenance commands to be run (such
  as 'rsync'), an 'OPENSSL_FIPS_NON_APPROVED_MD5_ALLOW' environment variable
  has been added. When a system is configured for FIPS mode and is in a
  maintenance state, this newly added environment variable can be set to
  allow software that requires the use of an MD5 cryptographic hash algorithm
  to be run, even though the hash algorithm is not approved by the FIPS-140-2
  standard. (BZ#673071)

  Users of OpenSSL are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues and add these
  enhancements. For the update to take effect, all services linked to the
  OpenSSL library must be restarted, or the system rebooted.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.0~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.0~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
