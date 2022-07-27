###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0208_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for tomcat6 openSUSE-SU-2012:0208-1 (tomcat6)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850210");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 20:47:11 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-1184", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SuSE Update for tomcat6 openSUSE-SU-2012:0208-1 (tomcat6)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");
  script_tag(name:"affected", value:"tomcat6 on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"This update fixes a regression in parameter passing (in
  urldecoding of parameters that contain spaces).

  In addition, multiple weaknesses in HTTP DIGESTS are fixed
  (CVE-2011-1184).


  CVE-2011-5062: The HTTP Digest Access Authentication
  implementation in Apache Tomcat 5.5.x before 5.5.34, 6.x
  before 6.0.33 and 7.x before 7.0.12 does not check qop
  values, which might allow remote attackers to bypass
  intended integrity-protection requirements via a qop=auth
  value, a different vulnerability than CVE-2011-1184.

  CVE-2011-5063: The HTTP Digest Access Authentication
  implementation in Apache Tomcat 5.5.x before 5.5.34, 6.x
  before 6.0.33, and 7.x before 7.0.12 does not check realm
  values, which might allow remote attackers to bypass
  intended access restrictions by leveraging the availability
  of a protection space with weaker authentication or
  authorization requirements, a different vulnerability than
  CVE-2011-1184.

  CVE-2011-5064: DigestAuthenticator.java in the HTTP Digest
  Access Authentication implementation in Apache Tomcat 5.5.x
  before 5.5.34, 6.x before 6.0.33, and 7.x before 7.0.12
  uses Catalina as the hard-coded server secret (aka private
  key), which makes it easier for remote attackers to bypass
  cryptographic protection mechanisms by leveraging knowledge
  of this string, a different vulnerability than
  CVE-2011-1184.


  Special Instructions and Notes:

  Please reboot the system after installing this update.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-1_0-api", rpm:"tomcat6-el-1_0-api~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2_1-api", rpm:"tomcat6-jsp-2_1-api~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2_5-api", rpm:"tomcat6-servlet-2_5-api~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.32~7.14.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
