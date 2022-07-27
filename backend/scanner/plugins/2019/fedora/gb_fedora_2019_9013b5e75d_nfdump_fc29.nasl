# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.876714");
  script_version("2019-08-28T11:48:42+0000");
  script_cve_id("CVE-2019-14459", "CVE-2019-1010057");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-28 11:48:42 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-25 02:18:33 +0000 (Sun, 25 Aug 2019)");
  script_name("Fedora Update for nfdump FEDORA-2019-9013b5e75d");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YTONOGJU5FSMFNRCT6OHXYUMDRKH4RPA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfdump'
  package(s) announced via the FEDORA-2019-9013b5e75d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nfdump is a set of tools to collect and process NetFlow data. It&#39, s fast and has
a powerful filter pcap like syntax. It supports NetFlow versions v1, v5, v7, v9
and IPFIX as well as a limited set of sflow. It includes support for CISCO ASA
(NSEL) and CISCO NAT (NEL) devices which export event logging records as v9
flows. Nfdump is fully IPv6 compatible.");

  script_tag(name:"affected", value:"'nfdump' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"nfdump", rpm:"nfdump~1.6.18~1.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);