###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for java CESA-2010:0339 centos5 i386
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
  script_oid("1.3.6.1.4.1.25623.1.0.880601");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085",
                "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093",
                "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838",
                "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");
  script_name("CentOS Update for java CESA-2010:0339 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-June/016727.html");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20491");

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

  A flaw was found in the way the TLS/SSL (Transport Layer Security/Secure
  Sockets Layer) protocols handle session renegotiation. A man-in-the-middle
  attacker could use this flaw to prefix arbitrary plain text to a client's
  session (for example, an HTTPS connection to a website). This could force
  the server to process an attacker's request as if authenticated using the
  victim's credentials. (CVE-2009-3555)

  This update disables renegotiation in the Java Secure Socket Extension
  (JSSE) component. Unsafe renegotiation can be re-enabled using the
  sun.security.ssl.allowUnsafeRenegotiation property. Refer to the linked
  Knowledgebase article for details.

  A number of flaws have been fixed in the Java Virtual Machine (JVM) and in
  various Java class implementations. These flaws could allow an unsigned
  applet or application to bypass intended access restrictions.
  (CVE-2010-0082, CVE-2010-0084, CVE-2010-0085, CVE-2010-0088, CVE-2010-0094)

  An untrusted applet could access clipboard information if a drag operation
  was performed over that applet's canvas. This could lead to an information
  leak. (CVE-2010-0091)

  The rawIndex operation incorrectly handled large values, causing the
  corruption of internal memory structures, resulting in an untrusted applet
  or application crashing. (CVE-2010-0092)

  The System.arraycopy operation incorrectly handled large index values,
  potentially causing array corruption in an untrusted applet or application.
  (CVE-2010-0093)

  Subclasses of InetAddress may incorrectly interpret network addresses,
  allowing an untrusted applet or application to bypass network access
  restrictions. (CVE-2010-0095)

  In certain cases, type assignments could result in 'non-exact' interface
  types. This could be used to bypass type-safety restrictions.
  (CVE-2010-0845)

  A buffer overflow flaw in LittleCMS (embedded in OpenJDK) could cause an
  untrusted applet or application using color profiles from untrusted sources
  to crash. (CVE-2010-0838)

  An input validation flaw was found in the JRE unpack200 functionality. An
  untrusted applet or application could use this flaw to elevate its
  privileges. (CVE-2010-0837)

  Deferred  ...

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

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-1.6.0.0", rpm:"java-1.6.0-openjdk-1.6.0.0~1.11.b16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.11.b16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.11.b16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.11.b16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src-1.6.0.0", rpm:"java-1.6.0-openjdk-src-1.6.0.0~1.11.b16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
