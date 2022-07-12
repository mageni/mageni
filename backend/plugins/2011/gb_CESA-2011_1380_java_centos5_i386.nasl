###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2011:1380 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-October/018121.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881023");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547",
                "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553",
                "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558",
                "CVE-2011-3560");
  script_name("CentOS Update for java CESA-2011:1380 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  A flaw was found in the Java RMI (Remote Method Invocation) registry
  implementation. A remote RMI client could use this flaw to execute
  arbitrary code on the RMI server running the registry. (CVE-2011-3556)

  A flaw was found in the Java RMI registry implementation. A remote RMI
  client could use this flaw to execute code on the RMI server with
  unrestricted privileges. (CVE-2011-3557)

  A flaw was found in the IIOP (Internet Inter-Orb Protocol) deserialization
  code. An untrusted Java application or applet running in a sandbox could
  use this flaw to bypass sandbox restrictions by deserializing
  specially-crafted input. (CVE-2011-3521)

  It was found that the Java ScriptingEngine did not properly restrict the
  privileges of sandboxed applications. An untrusted Java application or
  applet running in a sandbox could use this flaw to bypass sandbox
  restrictions. (CVE-2011-3544)

  A flaw was found in the AWTKeyStroke implementation. An untrusted Java
  application or applet running in a sandbox could use this flaw to bypass
  sandbox restrictions. (CVE-2011-3548)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the Java2D code used to perform transformations of graphic shapes
  and images. An untrusted Java application or applet running in a sandbox
  could use this flaw to bypass sandbox restrictions. (CVE-2011-3551)

  An insufficient error checking flaw was found in the unpacker for JAR files
  in pack200 format. A specially-crafted JAR file could use this flaw to
  crash the Java Virtual Machine (JVM) or, possibly, execute arbitrary code
  with JVM privileges. (CVE-2011-3554)

  It was found that HttpsURLConnection did not perform SecurityManager checks
  in the setSSLSocketFactory method. An untrusted Java application or applet
  running in a sandbox could use this flaw to bypass connection restrictions
  defined in the policy. (CVE-2011-3560)

  A flaw was found in the way the SSL 3 and TLS 1.0 protocols used block
  ciphers in cipher-block chaining (CBC) mode. An attacker able to perform a
  chosen plain text attack against a connection mixing trusted and untrusted
  data could use this flaw to recover portions of the trusted data sent over
  the connection. (CVE-2011-3389)

  Note: This update mitigates the CVE-2011-3389 issue by splitting the first
  application data record byte to a separate SSL/TLS protocol record. This
  mitigation may cause compatibility issues with some SSL/TLS implementations
  and can be ...

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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.23.1.9.10.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.23.1.9.10.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.23.1.9.10.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.23.1.9.10.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.23.1.9.10.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
