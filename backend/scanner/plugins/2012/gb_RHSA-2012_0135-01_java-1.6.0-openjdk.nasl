###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for java-1.6.0-openjdk RHSA-2012:0135-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00031.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870649");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:41:06 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497",
                "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505",
                "CVE-2012-0506");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for java-1.6.0-openjdk RHSA-2012:0135-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  It was discovered that Java2D did not properly check graphics rendering
  objects before passing them to the native renderer. Malicious input, or an
  untrusted Java application or applet could use this flaw to crash the Java
  Virtual Machine (JVM), or bypass Java sandbox restrictions. (CVE-2012-0497)

  It was discovered that the exception thrown on deserialization failure did
  not always contain a proper identification of the cause of the failure. An
  untrusted Java application or applet could use this flaw to bypass Java
  sandbox restrictions. (CVE-2012-0505)

  The AtomicReferenceArray class implementation did not properly check if
  the array was of the expected Object[] type. A malicious Java application
  or applet could use this flaw to bypass Java sandbox restrictions.
  (CVE-2011-3571)

  It was discovered that the use of TimeZone.setDefault() was not restricted
  by the SecurityManager, allowing an untrusted Java application or applet to
  set a new default time zone, and hence bypass Java sandbox restrictions.
  (CVE-2012-0503)

  The HttpServer class did not limit the number of headers read from HTTP
  requests. A remote attacker could use this flaw to make an application
  using HttpServer use an excessive amount of CPU time via a
  specially-crafted request. This update introduces a header count limit
  controlled using the sun.net.httpserver.maxReqHeaders property. The default
  value is 200. (CVE-2011-5035)

  The Java Sound component did not properly check buffer boundaries.
  Malicious input, or an untrusted Java application or applet could use this
  flaw to cause the Java Virtual Machine (JVM) to crash or disclose a portion
  of its memory. (CVE-2011-3563)

  A flaw was found in the AWT KeyboardFocusManager that could allow an
  untrusted Java application or applet to acquire keyboard focus and possibly
  steal sensitive information. (CVE-2012-0502)

  It was discovered that the CORBA (Common Object Request Broker
  Architecture) implementation in Java did not properly protect repository
  identifiers on certain CORBA objects. This could have been used to modify
  immutable object data. (CVE-2012-0506)

  An off-by-one flaw, causing a stack overflow, was found in the unpacker for
  ZIP files. A specially-crafted ZIP archive could cause the Java Virtual
  Machine (JVM) to crash when opened. (CVE-2012-0501)

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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.43.1.10.6.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~1.43.1.10.6.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.43.1.10.6.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.43.1.10.6.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
