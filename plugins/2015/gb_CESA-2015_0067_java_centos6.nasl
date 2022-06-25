###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2015:0067 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882089");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:56:12 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for java CESA-2015:0067 centos6");
  script_tag(name:"summary", value:"Check the version of java");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

A flaw was found in the way the Hotspot component in OpenJDK verified
bytecode from the class files. An untrusted Java application or applet
could possibly use this flaw to bypass Java sandbox restrictions.
(CVE-2014-6601)

Multiple improper permission check issues were discovered in the JAX-WS,
and RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions. (CVE-2015-0412,
CVE-2015-0408)

A flaw was found in the way the Hotspot garbage collector handled phantom
references. An untrusted Java application or applet could use this flaw to
corrupt the Java Virtual Machine memory and, possibly, execute arbitrary
code, bypassing Java sandbox restrictions. (CVE-2015-0395)

A flaw was found in the way the DER (Distinguished Encoding Rules) decoder
in the Security component in OpenJDK handled negative length values. A
specially crafted, DER-encoded input could cause a Java application to
enter an infinite loop when decoded. (CVE-2015-0410)

A flaw was found in the way the SSL 3.0 protocol handled padding bytes when
decrypting messages that were encrypted using block ciphers in cipher block
chaining (CBC) mode. This flaw could possibly allow a man-in-the-middle
(MITM) attacker to decrypt portions of the cipher text using a padding
oracle attack. (CVE-2014-3566)

Note: This update disables SSL 3.0 by default to address this issue.
The jdk.tls.disabledAlgorithms security property can be used to re-enable
SSL 3.0 support if needed. For additional information, refer to the Red Hat
Bugzilla bug linked to in the References section.

It was discovered that the SSL/TLS implementation in the JSSE component in
OpenJDK failed to properly check whether the ChangeCipherSpec was received
during the SSL/TLS connection handshake. An MITM attacker could possibly
use this flaw to force a connection to be established without encryption
being enabled. (CVE-2014-6593)

An information leak flaw was found in the Swing component in OpenJDK. An
untrusted Java application or applet could use this flaw to bypass certain
Java sandbox restrictions. (CVE-2015-0407)

A NULL pointer dereference flaw was found in the MulticastSocket
implementation in the Libraries component of OpenJDK. An untrusted Java
application or applet could possibly use this flaw to bypass certain Java
sandbox restrictions. (CVE-2014-6587)

Multiple boundary check flaws were found in the font parsing code in the 2D
component in OpenJDK. A specially crafted font file could allo ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020889.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.75~2.5.4.0.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.75~2.5.4.0.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.75~2.5.4.0.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.75~2.5.4.0.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.75~2.5.4.0.el6_6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
