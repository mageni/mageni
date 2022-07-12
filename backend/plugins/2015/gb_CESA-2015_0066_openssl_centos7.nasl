###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2015:0066 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882095");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:56:36 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for openssl CESA-2015:0066 centos7");
  script_tag(name:"summary", value:"Check the version of openssl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose cryptography
library.

A NULL pointer dereference flaw was found in the DTLS implementation of
OpenSSL. A remote attacker could send a specially crafted DTLS message,
which would cause an OpenSSL server to crash. (CVE-2014-3571)

A memory leak flaw was found in the way the dtls1_buffer_record() function
of OpenSSL parsed certain DTLS messages. A remote attacker could send
multiple specially crafted DTLS messages to exhaust all available memory of
a DTLS server. (CVE-2015-0206)

It was found that OpenSSL's BigNumber Squaring implementation could produce
incorrect results under certain special conditions. This flaw could
possibly affect certain OpenSSL library functionality, such as RSA
blinding. Note that this issue occurred rarely and with a low probability,
and there is currently no known way of exploiting it. (CVE-2014-3570)

It was discovered that OpenSSL would perform an ECDH key exchange with a
non-ephemeral key even when the ephemeral ECDH cipher suite was selected.
A malicious server could make a TLS/SSL client using OpenSSL use a weaker
key exchange method than the one requested by the user. (CVE-2014-3572)

It was discovered that OpenSSL would accept ephemeral RSA keys when using
non-export RSA cipher suites. A malicious server could make a TLS/SSL
client using OpenSSL use a weaker key exchange method. (CVE-2015-0204)

Multiple flaws were found in the way OpenSSL parsed X.509 certificates.
An attacker could use these flaws to modify an X.509 certificate to produce
a certificate with a different fingerprint without invalidating its
signature, and possibly bypass fingerprint-based blacklisting in
applications. (CVE-2014-8275)

It was found that an OpenSSL server would, under certain conditions, accept
Diffie-Hellman client certificates without the use of a private key.
An attacker could use a user's client certificate to authenticate as that
user, without needing the private key. (CVE-2015-0205)

All OpenSSL users are advised to upgrade to these updated packages, which
contain a backported patch to mitigate the above issues. For the update to
take effect, all services linked to the OpenSSL library (such as httpd and
other SSL-enabled services) must be restarted or the system rebooted.");
  script_tag(name:"affected", value:"openssl on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020885.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~34.el7_0.7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~34.el7_0.7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~34.el7_0.7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~34.el7_0.7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~34.el7_0.7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}