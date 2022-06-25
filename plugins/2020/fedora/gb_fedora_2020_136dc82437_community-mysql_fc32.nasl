# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877794");
  script_version("2020-05-15T04:25:55+0000");
  script_cve_id("CVE-2020-2759", "CVE-2020-2761", "CVE-2020-2762", "CVE-2020-2763", "CVE-2020-2765", "CVE-2020-2770", "CVE-2020-2774", "CVE-2020-2779", "CVE-2020-2780", "CVE-2020-2804", "CVE-2020-2812", "CVE-2020-2814", "CVE-2020-2853", "CVE-2020-2892", "CVE-2020-2893", "CVE-2020-2895", "CVE-2020-2896", "CVE-2020-2897", "CVE-2020-2898", "CVE-2020-2901", "CVE-2020-2903", "CVE-2020-2904", "CVE-2020-2921", "CVE-2020-2923", "CVE-2020-2924", "CVE-2020-2925", "CVE-2020-2926", "CVE-2020-2928", "CVE-2020-2930", "CVE-2020-2760");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-05-15 10:12:07 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-11 03:21:22 +0000 (Mon, 11 May 2020)");
  script_name("Fedora: Security Advisory for community-mysql (FEDORA-2020-136dc82437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SDGBQYS3A36S4CAZPV5YROHYXYZR6LAH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2020-136dc82437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~8.0.20~1.fc32", rls:"FC32"))) {
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