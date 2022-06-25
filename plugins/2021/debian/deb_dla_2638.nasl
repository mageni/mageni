# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892638");
  script_version("2021-04-25T03:00:25+0000");
  script_cve_id("CVE-2020-24616", "CVE-2020-24750", "CVE-2020-25649", "CVE-2020-35490", "CVE-2020-35491", "CVE-2020-35728", "CVE-2020-36179", "CVE-2020-36180", "CVE-2020-36181", "CVE-2020-36182", "CVE-2020-36183", "CVE-2020-36184", "CVE-2020-36185", "CVE-2020-36186", "CVE-2020-36187", "CVE-2020-36188", "CVE-2020-36189", "CVE-2021-20190");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-04-26 10:09:32 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-25 03:00:25 +0000 (Sun, 25 Apr 2021)");
  script_name("Debian LTS: Security Advisory for jackson-databind (DLA-2638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2638-1");
  script_xref(name:"Advisory-ID", value:"DLA-2638-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DLA-2638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were found in Jackson Databind.

CVE-2020-24616

FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the
interaction between serialization gadgets and typing, related
to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).

CVE-2020-24750

FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the
interaction between serialization gadgets and typing, related
to com.pastdev.httpcomponents.configuration.JndiConfiguration.

CVE-2020-25649

A flaw was found in FasterXML Jackson Databind, where it did not
have entity expansion secured properly. This flaw allows
vulnerability to XML external entity (XXE) attacks. The highest
threat from this vulnerability is data integrity.

CVE-2020-35490

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.

CVE-2020-35491

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.

CVE-2020-35728

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool
(aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).

CVE-2020-36179

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36180

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36181

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36182

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS.

CVE-2020-36183

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related
to org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool.

CVE-2020-36184

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the
interaction between serialization gadgets and typing, related to
org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

CVE-2020-36185

FasterXML ja ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.8.6-1+deb9u9.

We recommend that you upgrade your jackson-databind packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java", ver:"2.8.6-1+deb9u9", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java-doc", ver:"2.8.6-1+deb9u9", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
