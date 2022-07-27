###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2011:0857 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-June/017617.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880554");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_name("CentOS Update for java CESA-2011:0857 centos5 i386");

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

  Integer overflow flaws were found in the way Java2D parsed JPEG images and
  user-supplied fonts. An attacker could use these flaws to execute arbitrary
  code with the privileges of the user running an untrusted applet or
  application. (CVE-2011-0862)

  It was found that the MediaTracker implementation created Component
  instances with unnecessary access privileges. A remote attacker could use
  this flaw to elevate their privileges by utilizing an untrusted applet or
  application that uses Swing. (CVE-2011-0871)

  A flaw was found in the HotSpot component in OpenJDK. Certain bytecode
  instructions confused the memory management within the Java Virtual Machine
  (JVM), resulting in an applet or application crashing. (CVE-2011-0864)

  An information leak flaw was found in the NetworkInterface class. An
  untrusted applet or application could use this flaw to access information
  about available network interfaces that should only be available to
  privileged code. (CVE-2011-0867)

  An incorrect float-to-long conversion, leading to an overflow, was found
  in the way certain objects (such as images and text) were transformed in
  Java2D. A remote attacker could use this flaw to crash an untrusted applet
  or application that uses Java2D. (CVE-2011-0868)

  It was found that untrusted applets and applications could misuse a SOAP
  connection to incorrectly set global HTTP proxy settings instead of
  setting them in a local scope. This flaw could be used to intercept HTTP
  requests. (CVE-2011-0869)

  A flaw was found in the way signed objects were deserialized. If trusted
  and untrusted code were running in the same Java Virtual Machine (JVM), and
  both were deserializing the same signed object, the untrusted code could
  modify said object by using this flaw to bypass the validation checks on
  signed objects. (CVE-2011-0865)

  Note: All of the above flaws can only be remotely triggered in OpenJDK by
  calling the 'appletviewer' application.

  All users of java-1.6.0-openjdk are advised to upgrade to these updated
  packages, which provide OpenJDK 6 b20 / IcedTea 1.9.8 and resolve these
  issues. All running instances of OpenJDK Java must be restarted for the
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-1.6.0.0", rpm:"java-1.6.0-openjdk-1.6.0.0~1.22.1.9.8.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo-1.6.0.0", rpm:"java-1.6.0-openjdk-demo-1.6.0.0~1.22.1.9.8.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel-1.6.0.0", rpm:"java-1.6.0-openjdk-devel-1.6.0.0~1.22.1.9.8.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc-1.6.0.0", rpm:"java-1.6.0-openjdk-javadoc-1.6.0.0~1.22.1.9.8.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src-1.6.0.0", rpm:"java-1.6.0-openjdk-src-1.6.0.0~1.22.1.9.8.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
