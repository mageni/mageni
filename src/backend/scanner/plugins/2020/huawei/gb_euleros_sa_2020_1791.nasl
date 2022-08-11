# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1791");
  script_version("2020-07-03T06:29:09+0000");
  script_cve_id("CVE-2019-13224", "CVE-2019-13225", "CVE-2019-14553", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-03 10:14:24 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 06:29:09 +0000 (Fri, 03 Jul 2020)");
  script_name("Huawei EulerOS: Security Advisory for edk (EulerOS-SA-2020-1791)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.6\.0");

  script_xref(name:"EulerOS-SA", value:"2020-1791");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1791");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'edk' package(s) announced via the EulerOS-SA-2020-1791 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL Pointer Dereference in match_at() in regexec.c in Oniguruma 6.9.2 allows attackers to potentially cause denial of service by providing a crafted regular expression. Oniguruma issues often affect Ruby, as well as common optional libraries for PHP and Rust.(CVE-2019-13225)

A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2 allows attackers to potentially cause information disclosure, denial of service, or possibly code execution by providing a crafted regular expression. The attacker provides a pair of a regex pattern and a string, with a multi-byte encoding that gets handled by onig_new_deluxe(). Oniguruma issues often affect Ruby, as well as common optional libraries for PHP and Rust.(CVE-2019-13224)

EDK2 is a set of cross-platform firmware development environment based on UEFI and PI specifications in the TianoCore community.There is a security vulnerability in EDK2. The vulnerability stems from the fact that the'DxeImageVerificationHandler()' function does not correctly check whether unsigned EFI files are allowed to be loaded. Attackers can use this vulnerability to bypass verification.(CVE-2019-14575)

EDK2 is a set of cross-platform firmware development environment based on UEFI and PI specifications in the TianoCore community.The'ArpOnFrameRcvdDpc' function in EDK2 has a resource management error vulnerability. The vulnerability stems from the improper management of system resources (such as memory, disk space, files, etc.) by network systems or products.(CVE-2019-14559)

EDK2 is a set of cross-platform firmware development environment based on UEFI and PI specifications in the TianoCore community.An input verification error vulnerability exists in EDK2. The vulnerability stems from the fact that the network system or product did not correctly verify the input data.(CVE-2019-14563)

EDK2 is a set of cross-platform firmware development environment based on UEFI and PI specifications in the TianoCore community.There is a security vulnerability in EDK2. The source of the vulnerability will receive an invalid certificate when HTTPS-over-IPv6 is started. Attackers can use this vulnerability to implement man-in-the-middle attacks.(CVE-2019-14553)");

  script_tag(name:"affected", value:"'edk' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"edk", rpm:"edk~2.0~30.107", rls:"EULEROSVIRT-3.0.6.0"))) {
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