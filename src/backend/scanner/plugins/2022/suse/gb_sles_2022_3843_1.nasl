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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3843.1");
  script_cve_id("CVE-2022-3358", "CVE-2022-3602", "CVE-2022-3786");
  script_tag(name:"creation_date", value:"2022-11-02 04:46:04 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-04T04:36:43+0000");
  script_tag(name:"last_modification", value:"2022-11-04 04:36:43 +0000 (Fri, 04 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 01:15:00 +0000 (Thu, 03 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3843-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223843-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3' package(s) announced via the SUSE-SU-2022:3843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

CVE-2022-3358: Fixed vulnerability where a custom cipher passed to
 EVP_CipherInit() could lead into NULL encryption being unexpectedly used
 (bsc#1204226).

CVE-2022-3602: Fixed a buffer overflow in the X.509 email address.
 (bsc#1204714)

CVE-2022-3786: Fixed another buffer overflow related to X.509 email
 address. (bsc#1204714)");

  script_tag(name:"affected", value:"'openssl-3' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-debuginfo", rpm:"libopenssl3-debuginfo~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debuginfo", rpm:"openssl-3-debuginfo~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debugsource", rpm:"openssl-3-debugsource~3.0.1~150400.4.11.1", rls:"SLES15.0SP4"))) {
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
