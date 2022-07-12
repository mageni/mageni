###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2014:1052 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881988");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-08-14 05:54:57 +0200 (Thu, 14 Aug 2014)");
  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508",
                "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for openssl CESA-2014:1052 centos6");

  script_tag(name:"affected", value:"openssl on CentOS 6");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer
(SSL), Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose cryptography
library.

A race condition was found in the way OpenSSL handled ServerHello messages
with an included Supported EC Point Format extension. A malicious server
could possibly use this flaw to cause a multi-threaded TLS/SSL client using
OpenSSL to write into freed memory, causing the client to crash or execute
arbitrary code. (CVE-2014-3509)

It was discovered that the OBJ_obj2txt() function could fail to properly
NUL-terminate its output. This could possibly cause an application using
OpenSSL functions to format fields of X.509 certificates to disclose
portions of its memory. (CVE-2014-3508)

A flaw was found in the way OpenSSL handled fragmented handshake packets.
A man-in-the-middle attacker could use this flaw to force a TLS/SSL server
using OpenSSL to use TLS 1.0, even if both the client and the server
supported newer protocol versions. (CVE-2014-3511)

Multiple flaws were discovered in the way OpenSSL handled DTLS packets.
A remote attacker could use these flaws to cause a DTLS server or client
using OpenSSL to crash or use excessive amounts of memory. (CVE-2014-3505,
CVE-2014-3506, CVE-2014-3507)

A NULL pointer dereference flaw was found in the way OpenSSL performed a
handshake when using the anonymous Diffie-Hellman (DH) key exchange. A
malicious server could cause a DTLS client using OpenSSL to crash if that
client had anonymous DH cipher suites enabled. (CVE-2014-3510)

All OpenSSL users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library (such as httpd and other
SSL-enabled services) must be restarted or the system rebooted.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020488.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~16.el6_5.15", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~16.el6_5.15", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~16.el6_5.15", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~16.el6_5.15", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
