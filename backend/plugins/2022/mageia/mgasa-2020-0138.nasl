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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0138");
  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0138)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0138");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0138.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26305");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2020-March/006581.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2020-0138 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

The refactoring present in Apache Tomcat 9.0.28 to 9.0.30, 8.5.48 to
8.5.50 and 7.0.98 to 7.0.99 introduced a regression. The result of the
regression was that invalid Transfer-Encoding headers were incorrectly
processed leading to a possibility of HTTP Request Smuggling if Tomcat
was located behind a reverse proxy that incorrectly handled the invalid
Transfer-Encoding header in a particular manner. Such a reverse proxy
is considered unlikely. (CVE-2019-17569)

In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99
the HTTP header parsing code used an approach to end-of-line parsing that
allowed some invalid HTTP headers to be parsed as valid. This led to a
possibility of HTTP Request Smuggling if Tomcat was located behind a
reverse proxy that incorrectly handled the invalid Transfer-Encoding header
in a particular manner. Such a reverse proxy is considered unlikely.
(CVE-2020-1935)

When using the Apache JServ Protocol (AJP), care must be taken when trusting
incoming connections to Apache Tomcat. Tomcat treats AJP connections as
having higher trust than, for example, a similar HTTP connection. If such
connections are available to an attacker, they can be exploited in ways that
may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50
and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default
that listened on all configured IP addresses. It was expected (and
recommended in the security guide) that this Connector would be disabled if
not required. This vulnerability report identified a mechanism that allowed:
- returning arbitrary files from anywhere in the web application
- processing any file in the web application as a JSP Further, if the web
 application allowed file upload and stored those files within the web
 application (or the attacker was able to control the content of the web
 application by some other means) then this, along with the ability to
 process a file as a JSP, made remote code execution possible.
It is important to note that mitigation is only required if an AJP port is
accessible to untrusted users. Users wishing to take a defence-in-depth
approach and block the vector that permits returning arbitrary files and
execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100
or later. A number of changes were made to the default AJP Connector
configuration in 9.0.31 to harden the default configuration. It is likely
that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to
make small changes to their configurations. (CVE-2020-1938)");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.31~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.31~1.mga7", rls:"MAGEIA7"))) {
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
