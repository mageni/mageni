###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2009:0377 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015734.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880673");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733",
                "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095",
                "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101",
                "CVE-2009-1102");
  script_name("CentOS Update for java CESA-2009:0377 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
  contains the software and tools that users need to run applications written
  using the Java programming language.

  A flaw was found in the way that the Java Virtual Machine (JVM) handled
  temporary font files. A malicious applet could use this flaw to use large
  amounts of disk space, causing a denial of service. (CVE-2006-2426)

  A memory leak flaw was found in LittleCMS (embedded in OpenJDK). An
  application using color profiles could use excessive amounts of memory, and
  possibly crash after using all available memory, if used to open
  specially-crafted images. (CVE-2009-0581)

  Multiple integer overflow flaws which could lead to heap-based buffer
  overflows, as well as multiple insufficient input validation flaws, were
  found in the way LittleCMS handled color profiles. An attacker could use
  these flaws to create a specially-crafted image file which could cause a
  Java application to crash or, possibly, execute arbitrary code when opened.
  (CVE-2009-0723, CVE-2009-0733)

  A null pointer dereference flaw was found in LittleCMS. An application
  using color profiles could crash while converting a specially-crafted image
  file. (CVE-2009-0793)

  A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
  handling could allow a remote attacker to cause a denial of service on the
  server application hosting the JAX-WS service endpoint. (CVE-2009-1101)

  A flaw in the way the Java Runtime Environment initialized LDAP connections
  could allow a remote, authenticated user to cause a denial of service on
  the LDAP service. (CVE-2009-1093)

  A flaw in the Java Runtime Environment LDAP client could allow malicious
  data from an LDAP server to cause arbitrary code to be loaded and then run
  on an LDAP client. (CVE-2009-1094)

  Several buffer overflow flaws were found in the Java Runtime Environment
  unpack200 functionality. An untrusted applet could extend its privileges,
  allowing it to read and write local files, as well as to execute local
  applications with the privileges of the user running the applet.
  (CVE-2009-1095, CVE-2009-1096)

  A flaw in the Java Runtime Environment Virtual Machine code generation
  functionality could allow untrusted applets to extend their privileges. An
  untrusted applet could extend its privileges, allowing it to read and write
  local files, as well as execute local applications with the privileges
  of the user running the applet. (CVE-2009-1102)

  A buffer overf ...

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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~0.30.b09.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~0.30.b09.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~0.30.b09.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~0.30.b09.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~0.30.b09.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
