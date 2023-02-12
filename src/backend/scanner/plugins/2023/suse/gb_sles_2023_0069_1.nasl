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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0069.1");
  script_cve_id("CVE-2022-4743");
  script_tag(name:"creation_date", value:"2023-01-12 04:19:12 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 15:10:00 +0000 (Mon, 23 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0069-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230069-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2' package(s) announced via the SUSE-SU-2023:0069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2 fixes the following issues:

CVE-2022-4743: Fixed a potential memory leak when creating a texture for
 an OpenGL ES image (bsc#1206727).");

  script_tag(name:"affected", value:"'SDL2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Realtime Extension 15-SP3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit", rpm:"libSDL2-2_0-0-32bit~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit-debuginfo", rpm:"libSDL2-2_0-0-32bit-debuginfo~2.0.8~150200.11.9.1", rls:"SLES15.0SP4"))) {
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
