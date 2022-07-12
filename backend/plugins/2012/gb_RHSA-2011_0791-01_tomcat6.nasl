###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tomcat6 RHSA-2011:0791-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870626");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:35:19 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3718", "CVE-2010-4172", "CVE-2011-0013");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for tomcat6 RHSA-2011:0791-01");

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

  It was found that web applications could modify the location of the Tomcat
  host's work directory. As web applications deployed on Tomcat have read and
  write access to this directory, a malicious web application could use this
  flaw to trick Tomcat into giving it read and write access to an arbitrary
  directory on the file system. (CVE-2010-3718)

  A cross-site scripting (XSS) flaw was found in the Manager application,
  used for managing web applications on Tomcat. If a remote attacker could
  trick a user who is logged into the Manager application into visiting a
  specially-crafted URL, the attacker could perform Manager application tasks
  with the privileges of the logged in user. (CVE-2010-4172)

  A second cross-site scripting (XSS) flaw was found in the Manager
  application. A malicious web application could use this flaw to conduct an
  XSS attack, leading to arbitrary web script execution with the privileges
  of victims who are logged into and viewing Manager application web pages.
  (CVE-2011-0013)

  This update also fixes the following bugs:

  * A bug in the 'tomcat6' init script prevented additional Tomcat instances
  from starting. As well, running 'service tomcat6 start' caused
  configuration options applied from '/etc/sysconfig/tomcat6' to be
  overwritten with those from '/etc/tomcat6/tomcat6.conf'. With this update,
  multiple instances of Tomcat run as expected. (BZ#636997)

  * The '/usr/share/java/' directory was missing a symbolic link to the
  '/usr/share/tomcat6/bin/tomcat-juli.jar' library. Because this library was
  mandatory for certain operations (such as running the Jasper JSP
  precompiler), the 'build-jar-repository' command was unable to compose a
  valid classpath. With this update, the missing symbolic link has been
  added. (BZ#661244)

  * Previously, the 'tomcat6' init script failed to start Tomcat with a 'This
  account is currently not available.' message when Tomcat was configured to
  run under a user that did not have a valid shell configured as a login
  shell. This update modifies the init script to work correctly regardless of
  the daemon user's login shell. Additionally, these new tomcat6 packages now
  set '/sbin/nologin' as the login shell for the 'tomcat' user upon
  installation, as recommended by deployment best practices. (BZ#678671 ...

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

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
