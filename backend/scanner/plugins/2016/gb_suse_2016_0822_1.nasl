###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0822_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for tomcat SUSE-SU-2016:0822-1 (tomcat)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851245");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-19 06:18:04 +0100 (Sat, 19 Mar 2016)");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351",
                "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for tomcat SUSE-SU-2016:0822-1 (tomcat)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for tomcat fixes the following security issues.

  Tomcat has been updated from 7.0.55 to 7.0.68.

  * CVE-2015-5174: Directory traversal vulnerability in RequestUtil.java in
  Apache Tomcat allowed remote authenticated users to bypass intended
  SecurityManager restrictions and list a parent directory via a /..
  (slash dot dot) in a pathname used by a web application in a
  getResource, getResourceAsStream, or getResourcePaths call, as
  demonstrated by the $CATALINA_BASE/webapps directory.  (bsc#967967)

  * CVE-2015-5346: Session fixation vulnerability in Apache Tomcat when
  different session settings are used for deployments of multiple versions
  of the same web application, might have allowed remote attackers to
  hijack web sessions by leveraging use of a requestedSessionSSL field
  for an unintended request, related to CoyoteAdapter.java and
  Request.java. (bsc#967814)

  * CVE-2015-5345: The Mapper component in Apache Tomcat processes redirects
  before considering security constraints and Filters, which allowed
  remote attackers to determine the existence of a directory via a URL
  that lacks a trailing / (slash) character. (bsc#967965)

  * CVE-2015-5351: The (1) Manager and (2) Host Manager applications in
  Apache Tomcat established sessions and send CSRF tokens for arbitrary
  new requests, which allowed remote attackers to bypass a CSRF protection
  mechanism by using a token. (bsc#967812)

  * CVE-2016-0706: Apache Tomcat did not place
  org.apache.catalina.manager.StatusManagerServlet on the
  org/apache/catalina/core/RestrictedServlets.properties list, which
  allowed remote authenticated users to bypass intended SecurityManager
  restrictions and read arbitrary HTTP requests, and consequently
  discover session ID values, via a crafted web application.  (bsc#967815)

  * CVE-2016-0714: The session-persistence implementation in Apache Tomcat
  mishandled session attributes, which allowed remote authenticated users
  to bypass intended SecurityManager restrictions and execute arbitrary
  code in a privileged context via a web application that places a crafted
  object in a session. (bsc#967964)

  * CVE-2016-0763: The setGlobalContext method in
  org/apache/naming/factory/ResourceLinkFactory.java in Apache Tomcat did
  not consider whether ResourceLinkFactory.setGlobalContext callers are
  authorized, which allowed remote authenticated users to bypass intended
  SecurityManager restrictions and read or write to arbitrary application
  data, or cause a denial of service (application disruption), via a web
  application that sets a crafted global  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"tomcat on SUSE Linux Enterprise Server 12");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-el-2_2-api", rpm:"tomcat-el-2_2-api~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-jsp-2_2-api", rpm:"tomcat-jsp-2_2-api~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-servlet-3_0-api", rpm:"tomcat-servlet-3_0-api~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.68~7.6.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
