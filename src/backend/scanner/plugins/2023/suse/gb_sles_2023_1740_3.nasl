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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1740.3");
  script_cve_id("CVE-2018-20573", "CVE-2018-20574", "CVE-2019-6285", "CVE-2019-6292");
  script_tag(name:"creation_date", value:"2023-04-04 04:19:12 +0000 (Tue, 04 Apr 2023)");
  script_version("2023-04-04T10:10:18+0000");
  script_tag(name:"last_modification", value:"2023-04-04 10:10:18 +0000 (Tue, 04 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1740-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1740-3");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231740-3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yaml-cpp' package(s) announced via the SUSE-SU-2023:1740-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yaml-cpp fixes the following issues:

CVE-2018-20573: Fixed remote DOS via a crafted YAML file in function Scanner:EnsureTokensInQueue (bsc#1121227).
CVE-2018-20574: Fixed remote DOS via a crafted YAML file in function SingleDocParser:HandleFlowMap (bsc#1121230).
CVE-2019-6285: Fixed remote DOS via a crafted YAML file in function SingleDocParser::HandleFlowSequence (bsc#1122004).
CVE-2019-6292: Fixed DOS by stack consumption in singledocparser.cpp (bsc#1122021).");

  script_tag(name:"affected", value:"'yaml-cpp' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libyaml-cpp0_6", rpm:"libyaml-cpp0_6~0.6.1~4.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyaml-cpp0_6-debuginfo", rpm:"libyaml-cpp0_6-debuginfo~0.6.1~4.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yaml-cpp-debugsource", rpm:"yaml-cpp-debugsource~0.6.1~4.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yaml-cpp-devel", rpm:"yaml-cpp-devel~0.6.1~4.5.1", rls:"SLES15.0SP2"))) {
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
