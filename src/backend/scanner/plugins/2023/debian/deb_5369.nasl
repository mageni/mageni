# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5369");
  script_cve_id("CVE-2022-38725");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-03 16:52:00 +0000 (Fri, 03 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-5369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5369");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5369");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/syslog-ng");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'syslog-ng' package(s) announced via the DSA-5369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an integer overflow in the RFC3164 parser of syslog-ng, a system logging daemon, may result in denial of service via malformed syslog messages.

For the stable distribution (bullseye), this problem has been fixed in version 3.28.1-2+deb11u1.

We recommend that you upgrade your syslog-ng packages.

For the detailed security status of syslog-ng please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'syslog-ng' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-core", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-dbg", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-dev", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-add-contextual-data", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-amqp", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-examples", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-extra", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-geoip2", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-getent", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-graphite", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-http", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-map-value-pairs", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-mongodb", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-python", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-rdkafka", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-redis", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-riemann", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-slog", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-smtp", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-snmp", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-sql", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-stardate", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-stomp", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng-mod-xml-parser", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"syslog-ng", ver:"3.28.1-2+deb11u1", rls:"DEB11"))) {
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
