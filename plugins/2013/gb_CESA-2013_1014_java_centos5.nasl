###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2013:1014 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.881761");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-07-05 13:01:03 +0530 (Fri, 05 Jul 2013)");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412",
                "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446",
                "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2450", "CVE-2013-2452",
                "CVE-2013-2453", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457",
                "CVE-2013-2459", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465",
                "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472",
                "CVE-2013-2473");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for java CESA-2013:1014 centos5");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-July/019834.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  Multiple flaws were discovered in the ImagingLib and the image attribute,
  channel, layout and raster processing in the 2D component. An untrusted
  Java application or applet could possibly use these flaws to trigger Java
  Virtual Machine memory corruption. (CVE-2013-2470, CVE-2013-2471,
  CVE-2013-2472, CVE-2013-2473, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469)

  Integer overflow flaws were found in the way AWT processed certain input.
  An attacker could use these flaws to execute arbitrary code with the
  privileges of the user running an untrusted Java applet or application.
  (CVE-2013-2459)

  Multiple improper permission check issues were discovered in the Sound and
  JMX components in OpenJDK. An untrusted Java application or applet could
  use these flaws to bypass Java sandbox restrictions. (CVE-2013-2448,
  CVE-2013-2457, CVE-2013-2453)

  Multiple flaws in the Serialization, Networking, Libraries and CORBA
  components can be exploited by an untrusted Java application or applet to
  gain access to potentially sensitive information. (CVE-2013-2456,
  CVE-2013-2447, CVE-2013-2455, CVE-2013-2452, CVE-2013-2443, CVE-2013-2446)

  It was discovered that the Hotspot component did not properly handle
  out-of-memory errors. An untrusted Java application or applet could
  possibly use these flaws to terminate the Java Virtual Machine.
  (CVE-2013-2445)

  It was discovered that the AWT component did not properly manage certain
  resources and that the ObjectStreamClass of the Serialization component
  did not properly handle circular references. An untrusted Java application
  or applet could possibly use these flaws to cause a denial of service.
  (CVE-2013-2444, CVE-2013-2450)

  It was discovered that the Libraries component contained certain errors
  related to XML security and the class loader. A remote attacker could
  possibly exploit these flaws to bypass intended security mechanisms or
  disclose potentially sensitive information and cause a denial of service.
  (CVE-2013-2407, CVE-2013-2461)

  It was discovered that JConsole did not properly inform the user when
  establishing an SSL connection failed. An attacker could exploit this flaw
  to gain access to potentially sensitive information. (CVE-2013-2412)

  It was found that documentation generated by Javadoc was vulnerable to a
  frame injection attack. If such documentation was accessible over a
  network, and a remote attacker could trick a user into visiting a
  specially-crafted URL, it would  ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.41.1.11.11.90.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.41.1.11.11.90.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.41.1.11.11.90.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.41.1.11.11.90.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.41.1.11.11.90.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
