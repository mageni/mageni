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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3797.1");
  script_cve_id("CVE-2017-6891", "CVE-2018-1000654", "CVE-2021-46848");
  script_tag(name:"creation_date", value:"2022-10-28 04:36:32 +0000 (Fri, 28 Oct 2022)");
  script_version("2022-10-28T04:36:32+0000");
  script_tag(name:"last_modification", value:"2022-10-28 04:36:32 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 17:00:00 +0000 (Mon, 24 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3797-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223797-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1' package(s) announced via the SUSE-SU-2022:3797-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libtasn1 fixes the following issues:

Security issue fixed:

CVE-2018-1000654: Fixed a denial of service in the asn1 parser
 (bsc#1105435).

CVE-2017-6891: Added safety check to fix a stack overflow issue
 (bsc#1040621).

CVE-2021-46848: Fixed off-by-one array size check that affects
 asn1_encode_simple_der (bsc#1204690)");

  script_tag(name:"affected", value:"'libtasn1' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-6", rpm:"libtasn1-6~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-6-32bit", rpm:"libtasn1-6-32bit~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-6-debuginfo", rpm:"libtasn1-6-debuginfo~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-6-debuginfo-32bit", rpm:"libtasn1-6-debuginfo-32bit~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-debuginfo", rpm:"libtasn1-debuginfo~3.7~13.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-debugsource", rpm:"libtasn1-debugsource~3.7~13.7.1", rls:"SLES12.0SP2"))) {
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
