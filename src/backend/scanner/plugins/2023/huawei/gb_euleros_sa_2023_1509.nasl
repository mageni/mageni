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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1509");
  script_cve_id("CVE-2022-2867", "CVE-2022-2868", "CVE-2022-2869", "CVE-2022-2953", "CVE-2022-3570", "CVE-2022-3597", "CVE-2022-3598", "CVE-2022-3599", "CVE-2022-3626", "CVE-2022-3627");
  script_tag(name:"creation_date", value:"2023-03-09 04:15:24 +0000 (Thu, 09 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-21 20:58:00 +0000 (Fri, 21 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2023-1509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1509");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1509");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2023-1509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibTIFF 4.4.0 has an out-of-bounds write in extractContigSamplesShifted24bits in tools/tiffcrop.c:3604, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit cfbb883b.(CVE-2022-3598)

LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemcpy in libtiff/tif_unix.c:346 when called from extractImageSection, tools/tiffcrop.c:6826, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.(CVE-2022-3597)

LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemset in libtiff/tif_unix.c:340 when called from processCropSelections, tools/tiffcrop.c:7619, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.(CVE-2022-3626)

LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemcpy in libtiff/tif_unix.c:346 when called from extractImageSection, tools/tiffcrop.c:6860, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.(CVE-2022-3627)

LibTIFF 4.4.0 has an out-of-bounds read in writeSingleSection in tools/tiffcrop.c:7345, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit e8131125.(CVE-2022-3599)

Multiple heap buffer overflows in tiffcrop.c utility in libtiff library Version 4.4.0 allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into application crash, potential information disclosure or any other context-dependent impact(CVE-2022-3570)

libtiff's tiffcrop utility has a improper input validation flaw that can lead to out of bounds read and ultimately cause a crash if an attacker is able to supply a crafted file to tiffcrop.(CVE-2022-2868)

libtiff's tiffcrop utility has a uint32_t underflow that can lead to out of bounds read and write. An attacker who supplies a crafted file to tiffcrop (likely via tricking a user to run tiffcrop on it with certain parameters) could cause a crash or in some cases, further exploitation.(CVE-2022-2867)

libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw could cause a crash or potentially further exploitation.(CVE-2022-2869)

LibTIFF 4.4.0 has an out-of-bounds read in extractImageSection in tools/tiffcrop.c:6905, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 48d6ece8.(CVE-2022-2953)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~27.h39.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.3~27.h39.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
