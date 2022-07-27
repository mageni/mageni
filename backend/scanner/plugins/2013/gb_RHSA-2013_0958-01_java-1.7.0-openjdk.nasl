###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for java-1.7.0-openjdk RHSA-2013:0958-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871009");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-06-24 14:52:46 +0530 (Mon, 24 Jun 2013)");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412",
                "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446",
                "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450",
                "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455",
                "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459",
                "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465",
                "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472",
                "CVE-2013-2473");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for java-1.7.0-openjdk RHSA-2013:0958-01");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-June/msg00018.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"java-1.7.0-openjdk on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  Multiple flaws were discovered in the ImagingLib and the image attribute,
  channel, layout and raster processing in the 2D component. An untrusted
  Java application or applet could possibly use these flaws to trigger Java
  Virtual Machine memory corruption. (CVE-2013-2470, CVE-2013-2471,
  CVE-2013-2472, CVE-2013-2473, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469)

  Integer overflow flaws were found in the way AWT processed certain input.
  An attacker could use these flaws to execute arbitrary code with the
  privileges of the user running an untrusted Java applet or application.
  (CVE-2013-2459)

  Multiple improper permission check issues were discovered in the Sound,
  JDBC, Libraries, JMX, and Serviceability components in OpenJDK. An
  untrusted Java application or applet could use these flaws to bypass Java
  sandbox restrictions. (CVE-2013-2448, CVE-2013-2454, CVE-2013-2458,
  CVE-2013-2457, CVE-2013-2453, CVE-2013-2460)

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

  It was discovered that GnomeFileTypeDetector did not check for read
  permissions when accessing files. An untrusted Jav ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.25~2.3.10.4.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
