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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1041.1");
  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2019-19481", "CVE-2019-20792", "CVE-2019-6502", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572", "CVE-2021-42779", "CVE-2021-42780", "CVE-2021-42781", "CVE-2021-42782");
  script_tag(name:"creation_date", value:"2022-03-31 04:11:26 +0000 (Thu, 31 Mar 2022)");
  script_version("2022-03-31T04:11:26+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1041-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221041-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the SUSE-SU-2022:1041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

Security issues fixed:

CVE-2021-42780: Fixed use after return in insert_pin() (bsc#1192005).

CVE-2021-42779: Fixed use after free in sc_file_valid() (bsc#1191992).

CVE-2021-42781: Fixed multiple heap buffer overflows in
 pkcs15-oberthur.c (bsc#1192000).

CVE-2021-42782: Stack buffer overflow issues in various places
 (bsc#1191957).

CVE-2019-6502: Fixed a memory leak in sc_context_create() (bsc#1122756).

CVE-2020-26570: Fixed a heap based buffer overflow in
 sc_oberthur_read_file (bsc#1177364).

CVE-2020-26572: Prevent out of bounds write (bsc#1177378)

CVE-2020-26571: gemsafe GPK smart card software driver stack-based
 buffer overflow (bsc#1177380)

CVE-2019-15946: out-of-bounds access of an ASN.1 Octet string in
 asn1_decode_entry (bsc#1149747)

CVE-2019-19479: incorrect read operation during parsing of a SETCOS file
 attribute (bsc#1158256)

CVE-2019-15945: Fixed an out-of-bounds access of an ASN.1 Bitstring in
 decode_bit_string (bsc#1149746).

CVE-2019-19481: Fixed an improper handling of buffer limits for CAC
 certificates (bsc#1158305).

CVE-2019-20792: Fixed a double free in coolkey_free_private_data
 (bsc#1170809).

Non-security issues fixed:

Fixes segmentation fault in 'pkcs11-tool.c'. (bsc#1114649)");

  script_tag(name:"affected", value:"'opensc' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.18.0~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.18.0~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.18.0~150000.3.23.1", rls:"SLES15.0"))) {
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
