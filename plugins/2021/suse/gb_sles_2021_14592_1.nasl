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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14592.1");
  script_cve_id("CVE-2020-3123", "CVE-2020-3327", "CVE-2020-3341", "CVE-2020-3350", "CVE-2020-3481");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:08+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-19 23:15:00 +0000 (Thu, 19 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14592-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114592-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2021:14592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

Update to 0.103.0 to implement jsc#ECO-3010 and bsc#1118459

This update incorporates incompatible changes that were introduced in
 version 0.101.0.

Accumulated security fixes:
 * CVE-2020-3350: Fix a vulnerability wherein a malicious user could
 replace a scan target's directory with a symlink to another path to
 trick clamscan, clamdscan, or clamonacc into removing or moving a
 different file (eg. a critical system file). The issue would affect
 users that use the --move or --remove options for clamscan, clamdscan,
 and clamonacc. (bsc#1174255)
 * CVE-2020-3327: Fix a vulnerability in the ARJ archive parsing module
 in ClamAV 0.102.3 that could cause a Denial-of-Service (DoS)
 condition. Improper bounds checking results in an
 out-of-bounds read which could cause a crash. The previous fix for
 this CVE in 0.102.3 was incomplete. This fix correctly resolves the
 issue.
 * CVE-2020-3481: Fix a vulnerability in the EGG archive module in ClamAV
 0.102.0 - 0.102.3 could cause a Denial-of-Service (DoS) condition.
 Improper error handling may result in a crash due to a NULL pointer
 dereference. This vulnerability is mitigated for those using the
 official ClamAV signature databases because the file type signatures
 in daily.cvd will not enable the EGG archive parser in versions
 affected by the vulnerability. (bsc#1174250)
 * CVE-2020-3341: Fix a vulnerability in the PDF parsing module in ClamAV
 0.101 - 0.102.2 that could cause a Denial-of-Service (DoS) condition.
 Improper size checking of a buffer used to initialize AES decryption
 routines results in an out-of-bounds read which may cause a crash.
 (bsc#1171981)
 * CVE-2020-3123: A denial-of-service (DoS) condition may occur when
 using the optional credit card data-loss-prevention (DLP) feature.
 Improper bounds checking of an unsigned variable resulted in an
 out-of-bounds read, which causes a crash.");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP3");

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

if(release == "SLES11.0SP4") {
  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.0~0.20.32.1", rls:"SLES11.0SP4"))){
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
