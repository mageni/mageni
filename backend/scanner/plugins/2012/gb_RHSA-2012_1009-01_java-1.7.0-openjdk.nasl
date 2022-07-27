###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for java-1.7.0-openjdk RHSA-2012:1009-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00041.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870777");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:33 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717",
                "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724",
                "CVE-2012-1725", "CVE-2012-1726");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for java-1.7.0-openjdk RHSA-2012:1009-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"java-1.7.0-openjdk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  Multiple flaws were discovered in the CORBA (Common Object Request Broker
  Architecture) implementation in Java. A malicious Java application or
  applet could use these flaws to bypass Java sandbox restrictions or modify
  immutable object data. (CVE-2012-1711, CVE-2012-1719)

  It was discovered that the SynthLookAndFeel class from Swing did not
  properly prevent access to certain UI elements from outside the current
  application context. A malicious Java application or applet could use this
  flaw to crash the Java Virtual Machine, or bypass Java sandbox
  restrictions. (CVE-2012-1716)

  Multiple flaws were discovered in the font manager's layout lookup
  implementation. A specially-crafted font file could cause the Java Virtual
  Machine to crash or, possibly, execute arbitrary code with the privileges
  of the user running the virtual machine. (CVE-2012-1713)

  Multiple flaws were found in the way the Java HotSpot Virtual Machine
  verified the bytecode of the class file to be executed. A specially-crafted
  Java application or applet could use these flaws to crash the Java Virtual
  Machine, or bypass Java sandbox restrictions. (CVE-2012-1723,
  CVE-2012-1725)

  It was discovered that java.lang.invoke.MethodHandles.Lookup did not
  properly honor access modes. An untrusted Java application or applet could
  use this flaw to bypass Java sandbox restrictions. (CVE-2012-1726)

  It was discovered that the Java XML parser did not properly handle certain
  XML documents. An attacker able to make a Java application parse a
  specially-crafted XML file could use this flaw to make the XML parser enter
  an infinite loop. (CVE-2012-1724)

  It was discovered that the Java security classes did not properly handle
  Certificate Revocation Lists (CRL). CRL containing entries with duplicate
  certificate serial numbers could have been ignored. (CVE-2012-1718)

  It was discovered that various classes of the Java Runtime library could
  create temporary files with insecure permissions. A local attacker could
  use this flaw to gain access to the content of such temporary files.
  (CVE-2012-1717)

  This update also fixes the following bug:

  * Attempting to compile a SystemTap script using the jstack tapset could
  have failed with an error similar to the following:

  error: the frame size of 272 bytes is larger than 256 bytes

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

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.5~2.2.1.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.5~2.2.1.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
