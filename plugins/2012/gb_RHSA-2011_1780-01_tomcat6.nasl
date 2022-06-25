###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tomcat6 RHSA-2011:1780-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870651");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:41:29 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for tomcat6 RHSA-2011:1780-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"tomcat6 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  APR (Apache Portable Runtime) as mentioned in the CVE-2011-3190 and
  CVE-2011-2526 descriptions does not refer to APR provided by the apr
  packages. It refers to the implementation of APR provided by the Tomcat
  Native library, which provides support for using APR with Tomcat. This
  library is not shipped with Red Hat Enterprise Linux 6. This update
  includes fixes for users who have elected to use APR with Tomcat by taking
  the Tomcat Native library from a different product. Such a configuration is
  not supported by Red Hat, however.

  Multiple flaws were found in the way Tomcat handled HTTP DIGEST
  authentication. These flaws weakened the Tomcat HTTP DIGEST authentication
  implementation, subjecting it to some of the weaknesses of HTTP BASIC
  authentication, for example, allowing remote attackers to perform session
  replay attacks. (CVE-2011-1184)

  A flaw was found in the way the Coyote (org.apache.coyote.ajp.AjpProcessor)
  and APR (org.apache.coyote.ajp.AjpAprProcessor) Tomcat AJP (Apache JServ
  Protocol) connectors processed certain POST requests. An attacker could
  send a specially-crafted request that would cause the connector to treat
  the message body as a new request. This allows arbitrary AJP messages to be
  injected, possibly allowing an attacker to bypass a web application's
  authentication checks and gain access to information they would otherwise
  be unable to access. The JK (org.apache.jk.server.JkCoyoteHandler)
  connector is used by default when the APR libraries are not present. The JK
  connector is not affected by this flaw. (CVE-2011-3190)

  A flaw was found in the Tomcat MemoryUserDatabase. If a runtime exception
  occurred when creating a new user with a JMX client, that user's password
  was logged to Tomcat log files. Note: By default, only administrators have
  access to such log files. (CVE-2011-2204)

  A flaw was found in the way Tomcat handled sendfile request attributes when
  using the HTTP APR or NIO (Non-Blocking I/O) connector. A malicious web
  application running on a Tomcat instance could use this flaw to bypass
  security manager restrictions and gain access to files it would otherwise
  be unable to access, or possibly terminate the Java Virtual Machine (JVM).
  The HTTP blocking IO (BIO) connector, which is not vulnerable to this
  issue, is used by default in Red Hat Enterprise Linux 6. (CVE-2011-2526)

  Red Hat would like to thank the Apach ...

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

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~35.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~35.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~35.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~35.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~35.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
