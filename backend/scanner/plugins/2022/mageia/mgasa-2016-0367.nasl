# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0367");
  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-5425", "CVE-2016-6325", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 18:24:00 +0000 (Thu, 23 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0367");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0367.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19672");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/27/7");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/27/8");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/27/9");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/27/10");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/27/11");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-2046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2016-0367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Realm implementations did not process the supplied password if the
supplied user name did not exist. This made a timing attack possible to
determine valid user names. Note that the default configuration includes
the LockOutRealm which makes exploitation of this vulnerability harder
(CVE-2016-0762).

A malicious web application was able to bypass a configured
SecurityManager via a Tomcat utility method that was accessible to web
applications (CVE-2016-5018).

It was discovered that the Tomcat packages installed configuration file
/usr/lib/tmpfiles.d/tomcat.conf writeable to the tomcat group. A member
of the group or a malicious web application deployed on Tomcat could use
this flaw to escalate their privileges (CVE-2016-5425).

It was discovered that the Tomcat packages installed certain
configuration files read by the Tomcat initialization script as
writeable to the tomcat group. A member of the group or a malicious web
application deployed on Tomcat could use this flaw to escalate their
privileges (CVE-2016-6325).

When a SecurityManager is configured, a web application's ability to
read system properties should be controlled by the SecurityManager.
Tomcat's system property replacement feature for configuration files
could be used by a malicious web application to bypass the
SecurityManager and read system properties that should not be visible
(CVE-2016-6794).

A malicious web application was able to bypass a configured
SecurityManager via manipulation of the configuration parameters for the
JSP Servlet (CVE-2016-6796).

The ResourceLinkFactory did not limit web application access to global
JNDI resources to those resources explicitly linked to the web
application. Therefore, it was possible for a web application to access
any global JNDI resource whether an explicit ResourceLink had been
configured or not (CVE-2016-6797).");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.72~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
