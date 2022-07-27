###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2015:1197 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.882215");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-03 06:11:00 +0200 (Fri, 03 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openssl CESA-2015:1197 centos5");
  script_tag(name:"summary", value:"Check the version of openssl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the
  Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An out-of-bounds read flaw was found in the X509_cmp_time() function of
OpenSSL. A specially crafted X.509 certificate or a Certificate Revocation
List (CRL) could possibly cause a TLS/SSL server or client using OpenSSL
to crash. (CVE-2015-1789)

A NULL pointer dereference was found in the way OpenSSL handled certain
PKCS#7 inputs. A specially crafted PKCS#7 input with missing
EncryptedContent data could cause an application using OpenSSL to crash.
(CVE-2015-1790)

A flaw was found in the way the TLS protocol composes the Diffie-Hellman
(DH) key exchange. A man-in-the-middle attacker could use this flaw to
force the use of weak 512 bit export-grade keys during the key exchange,
allowing them to decrypt all traffic. (CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenSSL to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Future updates may raise this limit to
1024 bits.

Red Hat would like to thank the OpenSSL project for reporting CVE-2015-1789
and CVE-2015-1790. Upstream acknowledges Robert Swiecki and Hanno Bock as
the original reporters of CVE-2015-1789, and Michal Zalewski as the
original reporter of CVE-2015-1790.

All openssl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library must be restarted, or
the system rebooted.");
  script_tag(name:"affected", value:"openssl on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-July/021230.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~36.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~36.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~36.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
