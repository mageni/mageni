###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssl RHSA-2015:0716-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871339");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-24 07:08:39 +0100 (Tue, 24 Mar 2015)");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288",
                "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssl RHSA-2015:0716-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An invalid pointer use flaw was found in OpenSSL's ASN1_TYPE_cmp()
function. A remote attacker could crash a TLS/SSL client or server using
OpenSSL via a specially crafted X.509 certificate when the
attacker-supplied certificate was verified by the application.
(CVE-2015-0286)

An integer underflow flaw, leading to a buffer overflow, was found in the
way OpenSSL decoded malformed Base64-encoded inputs. An attacker able to
make an application using OpenSSL decode a specially crafted Base64-encoded
input (such as a PEM file) could use this flaw to cause the application to
crash. Note: this flaw is not exploitable via the TLS/SSL protocol because
the data being transferred is not Base64-encoded. (CVE-2015-0292)

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had both
the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

A use-after-free flaw was found in the way OpenSSL imported malformed
Elliptic Curve private keys. A specially crafted key file could cause an
application using OpenSSL to crash when imported. (CVE-2015-0209)

An out-of-bounds write flaw was found in the way OpenSSL reused certain
ASN.1 structures. A remote attacker could possibly use a specially crafted
ASN.1 structure that, when parsed by an application, would cause that
application to crash. (CVE-2015-0287)

A NULL pointer dereference flaw was found in OpenSSL's X.509 certificate
handling implementation. A specially crafted X.509 certificate could cause
an application using OpenSSL to crash if the application attempted to
convert the certificate to a certificate request. (CVE-2015-0288)

A NULL pointer dereference was found in the way OpenSSL handled certain
PKCS#7 inputs. An attacker able to make an application using OpenSSL
verify, decrypt, or parse a specially crafted PKCS#7 input could cause that
application to crash. TLS/SSL clients and servers using OpenSSL were not
affected by this flaw. (CVE-2015-0289)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2015-0286, CVE-2015-0287, CVE-2015-0288, CVE-2015-0289, CVE-2015-0292,
and CVE-2015-0293. Upstream acknowledges Stephen Henson of the OpenSSL
development team as the original reporter of CVE-2015-0286, Emilia Kasper
of the OpenSSL development team as the original repor ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openssl on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00046.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~42.el7_1.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1e~42.el7_1.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~42.el7_1.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~42.el7_1.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
