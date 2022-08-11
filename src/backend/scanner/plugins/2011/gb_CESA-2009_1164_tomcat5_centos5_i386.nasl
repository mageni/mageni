###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for tomcat5 CESA-2009:1164 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-July/016048.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880716");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
  script_name("CentOS Update for tomcat5 CESA-2009:1164 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat5'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"tomcat5 on CentOS 5");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  It was discovered that the Red Hat Security Advisory RHSA-2007:0871 did not
  address all possible flaws in the way Tomcat handles certain characters and
  character sequences in cookie values. A remote attacker could use this flaw
  to obtain sensitive information, such as session IDs, and then use this
  information for session hijacking attacks. (CVE-2007-5333)

  Note: The fix for the CVE-2007-5333 flaw changes the default cookie
  processing behavior: with this update, version 0 cookies that contain
  values that must be quoted to be valid are automatically changed to version
  1 cookies. To reactivate the previous, but insecure behavior, add the
  following entry to the '/etc/tomcat5/catalina.properties' file:

  org.apache.tomcat.util.http.ServerCookie.VERSION_SWITCH=false

  It was discovered that request dispatchers did not properly normalize user
  requests that have trailing query strings, allowing remote attackers to
  send specially-crafted requests that would cause an information leak.
  (CVE-2008-5515)

  A flaw was found in the way the Tomcat AJP (Apache JServ Protocol)
  connector processes AJP connections. An attacker could use this flaw to
  send specially-crafted requests that would cause a temporary denial of
  service. (CVE-2009-0033)

  It was discovered that the error checking methods of certain authentication
  classes did not have sufficient error checking, allowing remote attackers
  to enumerate (via brute force methods) usernames registered with
  applications running on Tomcat when FORM-based authentication was used.
  (CVE-2009-0580)

  A cross-site scripting (XSS) flaw was found in the examples calendar
  application. With some web browsers, remote attackers could use this flaw
  to inject arbitrary web script or HTML via the 'time' parameter.
  (CVE-2009-0781)

  It was discovered that web applications containing their own XML parsers
  could replace the XML parser Tomcat uses to parse configuration files. A
  malicious web application running on a Tomcat instance could read or,
  potentially, modify the configuration and XML-based data of other web
  applications deployed on the same Tomcat instance. (CVE-2009-0783)

  Users of Tomcat should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Tomcat must be restarted for
  this update to take effect.");
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
  if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.23~0jpp.7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
