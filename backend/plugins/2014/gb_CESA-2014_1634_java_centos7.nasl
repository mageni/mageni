###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2014:1634 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882057");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-16 05:59:29 +0200 (Thu, 16 Oct 2014)");
  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506",
                "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519",
                "CVE-2014-6531", "CVE-2014-6558");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for java CESA-2014:1634 centos7");

  script_tag(name:"summary", value:"Check the version of java");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The java-1.6.0-openjdk packages provide the
OpenJDK 6 Java Runtime Environment and the OpenJDK 6 Java Software Development Kit.

Multiple flaws were discovered in the Libraries, 2D, and Hotspot components
in OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2014-6506, CVE-2014-6531,
CVE-2014-6502, CVE-2014-6511, CVE-2014-6504, CVE-2014-6519)

It was discovered that the StAX XML parser in the JAXP component in OpenJDK
performed expansion of external parameter entities even when external
entity substitution was disabled. A remote attacker could use this flaw to
perform XML eXternal Entity (XXE) attack against applications using the
StAX parser to parse untrusted XML documents. (CVE-2014-6517)

It was discovered that the DatagramSocket implementation in OpenJDK failed
to perform source address checks for packets received on a connected
socket. A remote attacker could use this flaw to have their packets
processed as if they were received from the expected source.
(CVE-2014-6512)

It was discovered that the TLS/SSL implementation in the JSSE component in
OpenJDK failed to properly verify the server identity during the
renegotiation following session resumption, making it possible for
malicious TLS/SSL servers to perform a Triple Handshake attack against
clients using JSSE and client certificate authentication. (CVE-2014-6457)

It was discovered that the CipherInputStream class implementation in
OpenJDK did not properly handle certain exceptions. This could possibly
allow an attacker to affect the integrity of an encrypted stream handled by
this class. (CVE-2014-6558)

The CVE-2014-6512 was discovered by Florian Weimer of Red Hat Product
Security.

This update also fixes the following bug:

  * The TLS/SSL implementation in OpenJDK previously failed to handle
Diffie-Hellman (DH) keys with more than 1024 bits. This caused client
applications using JSSE to fail to establish TLS/SSL connections to servers
using larger DH keys during the connection handshake. This update adds
support for DH keys with size up to 2048 bits. (BZ#1148309)

All users of java-1.6.0-openjdk are advised to upgrade to these updated
packages, which resolve these issues. All running instances of OpenJDK Java
must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"java on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-October/020689.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.33~1.13.5.0.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.33~1.13.5.0.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.33~1.13.5.0.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.33~1.13.5.0.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.33~1.13.5.0.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
