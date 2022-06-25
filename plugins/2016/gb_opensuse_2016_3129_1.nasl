###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_3129_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for tomcat openSUSE-SU-2016:3129-1 (tomcat)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851455");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-14 05:55:01 +0100 (Wed, 14 Dec 2016)");
  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796",
                "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for tomcat openSUSE-SU-2016:3129-1 (tomcat)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for Tomcat provides the following fixes:

  Feature changes:

  The embedded Apache Commons DBCP component was updated to version 2.0.
  (bsc#1010893 fate#321029)

  Security fixes:

  - CVE-2016-0762: Realm Timing Attack (bsc#1007854)

  - CVE-2016-5018: Security Manager Bypass (bsc#1007855)

  - CVE-2016-6794: System Property Disclosure (bsc#1007857)

  - CVE-2016-6796: Manager Bypass (bsc#1007858)

  - CVE-2016-6797: Unrestricted Access to Global Resources (bsc#1007853)

  - CVE-2016-8735: Remote code execution vulnerability in
  JmxRemoteLifecycleListener (bsc#1011805)

  - CVE-2016-6816: HTTP Request smuggling vulnerability due to permitting
  invalid character in HTTP requests (bsc#1011812)

  Bugs fixed:

  - Fixed StringIndexOutOfBoundsException in WebAppClassLoaderBase.filter().
  (bsc#974407)

  - Fixed a deployment error in the examples webapp by changing the
  context.xml format to the new one introduced by Tomcat 8. (bsc#1004728)

  - Enabled optional setenv.sh script. See section '(3.4) Using the 'setenv'
  script' in the referenced documentation. (bsc#1002639)

  - Fixed regression caused by CVE-2016-6816.

  This update supplies the new packages apache-commons-pool2 and
  apache-commons-dbcp in version 2 to allow tomcat to use the DBCP 2.0
  interface.

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name:"affected", value:"tomcat on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");

  script_xref(name:"URL", value:"http://tomcat.apache.org/tomcat-8.0-doc/RUNNING.txt");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"apache-commons-dbcp", rpm:"apache-commons-dbcp~2.1.1~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-commons-dbcp-javadoc", rpm:"apache-commons-dbcp-javadoc~2.1.1~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-commons-pool2", rpm:"apache-commons-pool2~2.4.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-commons-pool2-javadoc", rpm:"apache-commons-pool2-javadoc~2.4.2~2.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-embed", rpm:"tomcat-embed~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-servlet-3_1-api", rpm:"tomcat-servlet-3_1-api~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~8.0.32~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
