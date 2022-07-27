###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl098e CESA-2016:0372 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882414");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-10 06:15:53 +0100 (Thu, 10 Mar 2016)");
  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704",
                "CVE-2016-0800");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openssl098e CESA-2016:0372 centos6");
  script_tag(name:"summary", value:"Check the version of openssl098e");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1)
protocols, as well as a full-strength, general purpose cryptography library.

A padding oracle flaw was found in the Secure Sockets Layer version 2.0
(SSLv2) protocol. An attacker can potentially use this flaw to decrypt
RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol
version, allowing them to decrypt such connections. This cross-protocol
attack is publicly referred to as DROWN. (CVE-2016-0800)

Note: This issue was addressed by disabling the SSLv2 protocol by default
when using the 'SSLv23' connection methods, and removing support for weak
SSLv2 cipher suites. For more information, refer to the knowledge base
article linked to in the References section.

It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2
connection handshakes that indicated non-zero clear key length for
non-export cipher suites. An attacker could use this flaw to decrypt
recorded SSLv2 sessions with the server by using it as a decryption
oracle.(CVE-2016-0703)

It was discovered that the SSLv2 protocol implementation in OpenSSL did
not properly implement the Bleichenbacher protection for export cipher
suites. An attacker could use a SSLv2 server using OpenSSL as a
Bleichenbacher oracle. (CVE-2016-0704)

Note: The CVE-2016-0703 and CVE-2016-0704 issues could allow for more
efficient exploitation of the CVE-2016-0800 issue via the DROWN attack.

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had both
the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2
ciphers that have been disabled on the server. This could result in weak
SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to
man-in-the-middle attacks. (CVE-2015-3197)

Red Hat would like to thank the OpenSSL project for reporting these issues.
Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as the original
reporters of CVE-2016-0800 and CVE-2015-3197  David Adrian (University of
Michigan) and J. Alex Halderman (University of Michigan) as the original
reporters of CVE-2016-0703 and CVE-2016-0704  and Sean Burford (Google) and
Emilia Kasper (OpenSSL development team) as the original reporters of
CVE-2015-0293.

All openssl098e users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the update
to take effect, all services linked to the openssl098e library must be
restarted, or the system rebooted.");
  script_tag(name:"affected", value:"openssl098e on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021720.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~20.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
