###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2013:0770 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_tag(name:"affected", value:"java on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  Multiple flaws were discovered in the font layout engine in the 2D
  component. An untrusted Java application or applet could possibly use these
  flaws to trigger Java Virtual Machine memory corruption. (CVE-2013-1569,
  CVE-2013-2383, CVE-2013-2384)

  Multiple improper permission check issues were discovered in the Beans,
  Libraries, JAXP, and RMI components in OpenJDK. An untrusted Java
  application or applet could use these flaws to bypass Java sandbox
  restrictions. (CVE-2013-1558, CVE-2013-2422, CVE-2013-1518, CVE-2013-1557)

  The previous default value of the java.rmi.server.useCodebaseOnly property
  permitted the RMI implementation to automatically load classes from
  remotely specified locations. An attacker able to connect to an application
  using RMI could use this flaw to make the application execute arbitrary
  code. (CVE-2013-1537)

  Note: The fix for CVE-2013-1537 changes the default value of the property
  to true, restricting class loading to the local CLASSPATH and locations
  specified in the java.rmi.server.codebase property. Refer to Red Hat
  Bugzilla bug 952387 for additional details.

  The 2D component did not properly process certain images. An untrusted Java
  application or applet could possibly use this flaw to trigger Java Virtual
  Machine memory corruption. (CVE-2013-2420)

  It was discovered that the Hotspot component did not properly handle
  certain intrinsic frames, and did not correctly perform MethodHandle
  lookups. An untrusted Java application or applet could use these flaws to
  bypass Java sandbox restrictions. (CVE-2013-2431, CVE-2013-2421)

  It was discovered that JPEGImageReader and JPEGImageWriter in the ImageIO
  component did not protect against modification of their state while
  performing certain native code operations. An untrusted Java application or
  applet could possibly use these flaws to trigger Java Virtual Machine
  memory corruption. (CVE-2013-2429, CVE-2013-2430)

  The JDBC driver manager could incorrectly call the toString() method in
  JDBC drivers, and the ConcurrentHashMap class could incorrectly call the
  defaultReadObject() method. An untrusted Java application or applet could
  possibly use these flaws to bypass Java sandbox restrictions.
  (CVE-2013-1488, CVE-2013-2426)

  The sun.awt.datatransfer.ClassLoaderObjectInputStream class may incorrectly
  invoke the system class loader. An untrusted Java application or applet
  could possibly use this flaw to bypass certain Java sandbox restrict ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_oid("1.3.6.1.4.1.25623.1.0.881719");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:21:12 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537",
                "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383",
                "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419",
                "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424",
                "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("CentOS Update for java CESA-2013:0770 centos6");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-April/019703.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.61.1.11.11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.61.1.11.11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.61.1.11.11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.61.1.11.11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.61.1.11.11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
