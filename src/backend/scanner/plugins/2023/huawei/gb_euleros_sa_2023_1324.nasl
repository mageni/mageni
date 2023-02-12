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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1324");
  script_cve_id("CVE-2021-33640", "CVE-2021-33643", "CVE-2021-33644", "CVE-2021-33645", "CVE-2021-33646");
  script_tag(name:"creation_date", value:"2023-02-09 04:29:52 +0000 (Thu, 09 Feb 2023)");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-29 18:54:00 +0000 (Thu, 29 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for libtar (EulerOS-SA-2023-1324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1324");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1324");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtar' package(s) announced via the EulerOS-SA-2023-1324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longname, causing an out-of-bounds read.(CVE-2021-33644)

An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longlink, causing an out-of-bounds read.(CVE-2021-33643)

After tar_close(), libtar.c releases the memory pointed to by pointer t. After tar_close() is called in the list() function, it continues to use pointer t: free_longlink_longname(t->th_buf) . As a result, the released memory is used (use-after-free).(CVE-2021-33640)

The th_read() function doesn't free a variable t->th_buf.gnu_longlink after allocating memory, which may cause a memory leak.(CVE-2021-33645)

The th_read() function doesn't free a variable t->th_buf.gnu_longname after allocating memory, which may cause a memory leak.(CVE-2021-33646)");

  script_tag(name:"affected", value:"'libtar' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"libtar", rpm:"libtar~1.2.20~15.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
