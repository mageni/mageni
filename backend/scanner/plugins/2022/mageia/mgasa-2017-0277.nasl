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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0277");
  script_cve_id("CVE-2017-9735");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2017-0277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0277");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0277.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21202");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QULQK5DU63QRYEWLVC6QZWASFQFSPFMD/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jetty, jetty-alpn, jetty-test-helper' package(s) announced via the MGASA-2017-0277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jetty is prone to a timing channel attack in util/security/Password.java, which
makes it easier for remote attackers to obtain access by observing elapsed times
before rejection of incorrect passwords (CVE-2017-9735).");

  script_tag(name:"affected", value:"'jetty, jetty-alpn, jetty-test-helper' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"jetty", rpm:"jetty~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-alpn", rpm:"jetty-alpn~8.1.11~3.v20170118.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-alpn-client", rpm:"jetty-alpn-client~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-alpn-javadoc", rpm:"jetty-alpn-javadoc~8.1.11~3.v20170118.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-alpn-server", rpm:"jetty-alpn-server~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-annotations", rpm:"jetty-annotations~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-ant", rpm:"jetty-ant~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-cdi", rpm:"jetty-cdi~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-client", rpm:"jetty-client~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-continuation", rpm:"jetty-continuation~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-deploy", rpm:"jetty-deploy~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-fcgi-client", rpm:"jetty-fcgi-client~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-fcgi-server", rpm:"jetty-fcgi-server~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http", rpm:"jetty-http~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http-spi", rpm:"jetty-http-spi~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http2-client", rpm:"jetty-http2-client~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http2-common", rpm:"jetty-http2-common~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http2-hpack", rpm:"jetty-http2-hpack~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http2-http-client-transport", rpm:"jetty-http2-http-client-transport~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http2-server", rpm:"jetty-http2-server~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-httpservice", rpm:"jetty-httpservice~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-infinispan", rpm:"jetty-infinispan~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-io", rpm:"jetty-io~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jaas", rpm:"jetty-jaas~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jaspi", rpm:"jetty-jaspi~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-javadoc", rpm:"jetty-javadoc~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-javax-websocket-client-impl", rpm:"jetty-javax-websocket-client-impl~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-javax-websocket-server-impl", rpm:"jetty-javax-websocket-server-impl~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jmx", rpm:"jetty-jmx~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jndi", rpm:"jetty-jndi~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jsp", rpm:"jetty-jsp~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jspc-maven-plugin", rpm:"jetty-jspc-maven-plugin~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jstl", rpm:"jetty-jstl~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-maven-plugin", rpm:"jetty-maven-plugin~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-nosql", rpm:"jetty-nosql~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-osgi-alpn", rpm:"jetty-osgi-alpn~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-osgi-boot", rpm:"jetty-osgi-boot~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-osgi-boot-jsp", rpm:"jetty-osgi-boot-jsp~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-osgi-boot-warurl", rpm:"jetty-osgi-boot-warurl~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-plus", rpm:"jetty-plus~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-project", rpm:"jetty-project~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-proxy", rpm:"jetty-proxy~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-quickstart", rpm:"jetty-quickstart~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-rewrite", rpm:"jetty-rewrite~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-security", rpm:"jetty-security~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-server", rpm:"jetty-server~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlet", rpm:"jetty-servlet~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlets", rpm:"jetty-servlets~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-spring", rpm:"jetty-spring~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-start", rpm:"jetty-start~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-test-helper", rpm:"jetty-test-helper~3.1~4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-test-helper-javadoc", rpm:"jetty-test-helper-javadoc~3.1~4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-unixsocket", rpm:"jetty-unixsocket~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util", rpm:"jetty-util~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util-ajax", rpm:"jetty-util-ajax~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-webapp", rpm:"jetty-webapp~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-websocket-api", rpm:"jetty-websocket-api~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-websocket-client", rpm:"jetty-websocket-client~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-websocket-common", rpm:"jetty-websocket-common~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-websocket-server", rpm:"jetty-websocket-server~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-websocket-servlet", rpm:"jetty-websocket-servlet~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-xml", rpm:"jetty-xml~9.4.6~1.v20170531.1.1.mga6", rls:"MAGEIA6"))) {
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
