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
  script_oid("1.3.6.1.4.1.25623.1.0.827111");
  script_version("2023-02-21T10:09:30+0000");
  script_cve_id("CVE-2022-21594", "CVE-2022-21599", "CVE-2022-21604", "CVE-2022-21608", "CVE-2022-21611", "CVE-2022-21617", "CVE-2022-21625", "CVE-2022-21632", "CVE-2022-21633", "CVE-2022-21637", "CVE-2022-21640", "CVE-2022-39400", "CVE-2022-39408", "CVE-2022-39410", "CVE-2023-21836", "CVE-2023-21863", "CVE-2023-21867", "CVE-2023-21868", "CVE-2023-21869", "CVE-2023-21870", "CVE-2023-21871", "CVE-2023-21873", "CVE-2023-21875", "CVE-2023-21876", "CVE-2023-21877", "CVE-2023-21878", "CVE-2023-21879");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-17 02:02:31 +0000 (Fri, 17 Feb 2023)");
  script_name("Fedora: Security Advisory for community-mysql (FEDORA-2023-d332f0b6a3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-d332f0b6a3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EG3VBUHKCUXVWBSCD2FHCWIAMZO4X3PR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2023-d332f0b6a3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~8.0.32~1.fc37", rls:"FC37"))) {
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