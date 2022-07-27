# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2807");
  script_cve_id("CVE-2021-33285", "CVE-2021-33287", "CVE-2021-33289", "CVE-2021-35266", "CVE-2021-35267", "CVE-2021-35268", "CVE-2021-35269", "CVE-2021-39251", "CVE-2021-39252", "CVE-2021-39253", "CVE-2021-39254");
  script_tag(name:"creation_date", value:"2021-12-26 03:23:15 +0000 (Sun, 26 Dec 2021)");
  script_version("2022-01-03T09:39:10+0000");
  script_tag(name:"last_modification", value:"2022-01-03 09:39:10 +0000 (Mon, 03 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-20 17:04:00 +0000 (Mon, 20 Sep 2021)");

  script_name("Huawei EulerOS: Security Advisory for ntfs-3g (EulerOS-SA-2021-2807)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2807");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2807");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntfs-3g' package(s) announced via the EulerOS-SA-2021-2807 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode pathname is supplied in an NTFS image a heap buffer overflow can occur resulting in memory disclosure, denial of service and even code execution(CVE-2021-35266)

NTFS-3G versions < 2021.8.22, a stack buffer overflow can occur when correcting differences in the MFT and MFTMirror allowing for code execution or escalation of privileges when setuid-root.(CVE-2021-35267)

In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute is supplied to the function ntfs_get_attribute_value, a heap buffer overflow can occur allowing for memory disclosure or denial of service. The vulnerability is caused by an out-of-bound buffer access which can be triggered by mounting a crafted ntfs partition. The root cause is a missing consistency check after reading an MFT record : the 'bytes_in_use' field should be less than the 'bytes_allocated' field. When it is not, the parsing of the records proceeds into the wild.(CVE-2021-33285)

In NTFS-3G versions < 2021.8.22, when specially crafted NTFS attributes are read in the function ntfs_attr_pread_i, a heap buffer overflow can occur and allow for writing to arbitrary memory or denial of service of the application.(CVE-2021-33287)

In NTFS-3G versions < 2021.8.22, when a specially crafted MFT section is supplied in an NTFS image a heap buffer overflow can occur and allow for code execution.(CVE-2021-33289)

In NTFS-3G versions < 2021.8.22, when a specially crafted NTFS inode is loaded in the function ntfs_inode_real_open, a heap buffer overflow can occur allowing for code execution and escalation of privileges.(CVE-2021-35268)

NTFS-3G versions < 2021.8.22, when a specially crafted NTFS attribute from the MFT is setup in the function ntfs_attr_setup_flag, a heap buffer overflow can occur allowing for code execution and escalation of privileges.(CVE-2021-35269)

A crafted NTFS image can cause a NULL pointer dereference in ntfs_extent_inode_open in NTFS-3G < 2021.8.22(CVE-2021-39251)

A crafted NTFS image can cause an out-of-bounds read in ntfs_ie_lookup in NTFS-3G < 2021.8.22.(CVE-2021-39252)

A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G < 2021.8.22.(CVE-2021-39253)

A crafted NTFS image can cause an integer overflow in memmove, leading to a heap-based buffer overflow in the function ntfs_attr_record_resize, in NTFS-3G < 2021.8.22.(CVE-2021-39254)");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2017.3.23~8.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2017.3.23~8.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
