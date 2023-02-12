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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1150");
  script_cve_id("CVE-2020-12321", "CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 16:23:00 +0000 (Tue, 24 Nov 2020)");

  script_name("Huawei EulerOS: Security Advisory for linux-firmware (EulerOS-SA-2023-1150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1150");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1150");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'linux-firmware' package(s) announced via the EulerOS-SA-2023-1150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * before version 26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable an escalation of privilege via local access.(CVE-2020-12362)

Null pointer reference in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and before version Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via local access.(CVE-2020-12364)

Improper input validation in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via local access.(CVE-2020-12363)

Improper buffer restriction in some Intel(R) Wireless Bluetooth(R) products before version 21.110 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.(CVE-2020-12321)");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20200817~2.h5.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
