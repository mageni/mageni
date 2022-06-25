# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892179");
  script_version("2020-04-18T03:00:13+0000");
  script_cve_id("CVE-2020-10968", "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113", "CVE-2020-11619", "CVE-2020-11620");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-20 08:28:46 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-18 03:00:13 +0000 (Sat, 18 Apr 2020)");
  script_name("Debian LTS: Security Advisory for jackson-databind (DLA-2179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2179-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DLA-2179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Following CVEs were reported against the jackson-databind source package
:

CVE-2020-10968

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.aoju.bus.proxy.provider.remoting.RmiProvider
(aka bus-proxy).

CVE-2020-10969

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to javax.swing.JEditorPane.

CVE-2020-11111

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.activemq.* (aka activemq-jms, activemq-core,
activemq-pool, and activemq-pool-jms).

CVE-2020-11112

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.commons.proxy.provider.remoting.RmiProvider
(aka apache/commons-proxy).

CVE-2020-11113

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.openjpa.ee.WASRegistryManagedRuntime
(aka openjpa).

CVE-2020-11619

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.springframework.aop.config.MethodLocatingFactoryBean
(aka spring-aop).

CVE-2020-11620

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.commons.jelly.impl.Embedded (aka commons-jelly).");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.4.2-2+deb8u14.

We recommend that you upgrade your jackson-databind packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java", ver:"2.4.2-2+deb8u14", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java-doc", ver:"2.4.2-2+deb8u14", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
