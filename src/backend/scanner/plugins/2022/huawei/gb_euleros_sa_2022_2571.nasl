# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2571");
  script_cve_id("CVE-2022-0561", "CVE-2022-0562", "CVE-2022-0865", "CVE-2022-0891", "CVE-2022-0907", "CVE-2022-0908", "CVE-2022-0909", "CVE-2022-0924", "CVE-2022-1355", "CVE-2022-22844");
  script_tag(name:"creation_date", value:"2022-10-12 04:41:33 +0000 (Wed, 12 Oct 2022)");
  script_version("2022-10-12T10:13:47+0000");
  script_tag(name:"last_modification", value:"2022-10-12 10:13:47 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 18:46:00 +0000 (Tue, 15 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2022-2571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2571");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2022-2571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-buffer-overflow flaw was found in tiffcp.c in main().(CVE-2022-1355)

Unchecked Return Value to NULL Pointer Dereference in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file.For users that compile libtiff from sources, the fix is available with commit f2b656e2.(CVE-2022-0907)

Reachable Assertion in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file.For users that compile libtiff from sources, the fix is available with commit 5e180045.(CVE-2022-0865)

Out-of-bounds Read error in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file.For users that compile libtiff from sources, the fix is available with commit 408976c4.(CVE-2022-0924)

Divide By Zero error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file.For users that compile libtiff from sources, the fix is available with commit f8d0f9aa.(CVE-2022-0909)

Null source pointer passed as an argument to memcpy() function within TIFFFetchNormalTag () in tif_dirread.c in libtiff versions up to 4.3.0 could lead to Denial of Service via crafted TIFF file.(CVE-2022-0908)

LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a custom tag and 0x0200 as the second word of the DE field.(CVE-2022-22844)

Null source pointer passed as an argument to memcpy() function within TIFFReadDirectory() in tif_dirread.c in libtiff versions from 4.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users that compile libtiff from sources, a fix is available with commit 561599c.(CVE-2022-0562)

Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing() in tif_dirread.c in libtiff versions from 3.9.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users that compile libtiff from sources, the fix is available with commit eecb0712.(CVE-2022-0561)

A heap buffer overflow in ExtractImageSection function in tiffcrop.c in libtiff library Version 4.3.0 allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into application crash, potential information disclosure or any other context-dependent impact(CVE-2022-0891)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.9~11.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~11.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
