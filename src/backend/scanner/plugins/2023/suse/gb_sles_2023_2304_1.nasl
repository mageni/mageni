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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2304.1");
  script_cve_id("CVE-2023-27530", "CVE-2023-28120");
  script_tag(name:"creation_date", value:"2023-05-29 04:23:31 +0000 (Mon, 29 May 2023)");
  script_version("2023-05-30T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-30 09:08:51 +0000 (Tue, 30 May 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-16 16:18:00 +0000 (Thu, 16 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2304-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232304-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2023:2304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server fixes the following issues:
Updated to version 2.13:

CVE-2023-28120: Fixed a potential XSS issue in an embedded
 dependency (bsc#1209507).
CVE-2023-27530: Fixed a denial of service issue in multipart request
 parsing (bsc#1209096).

Non-security fixes:

Fixed transactional update on GCE (bsc#1211398).
Use HTTPS in rmt-client-setup-res (bsc#1209825).
Various build fixes (bsc#1207670, bsc#1203171, bsc#1206593,
 bsc#1202053).");

  script_tag(name:"affected", value:"'rmt-server' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~2.13~150100.3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-config", rpm:"rmt-server-config~2.13~150100.3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-debuginfo", rpm:"rmt-server-debuginfo~2.13~150100.3.45.1", rls:"SLES15.0SP1"))) {
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
