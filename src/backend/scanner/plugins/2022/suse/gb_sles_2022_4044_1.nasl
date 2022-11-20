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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4044.1");
  script_cve_id("CVE-2018-10903");
  script_tag(name:"creation_date", value:"2022-11-17 14:01:30 +0000 (Thu, 17 Nov 2022)");
  script_version("2022-11-17T14:01:30+0000");
  script_tag(name:"last_modification", value:"2022-11-17 14:01:30 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4044-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224044-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cryptography, python-cryptography-vectors' package(s) announced via the SUSE-SU-2022:4044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-cryptography, python-cryptography-vectors fixes the following issues:

Update in SLE-15 (bsc#1177083, jsc#PM-2730, jsc#SLE-18312)

Refresh patches for new version

Update in SLE-15 (bsc#1176785, jsc#ECO-3105, jsc#PM-2352)

update to 2.9.2
 * 2.9.2 - 2020-04-22
 - Updated the macOS wheel to fix an issue where it would not run on
 macOS versions older than 10.15.
 * 2.9.1 - 2020-04-21
 - Updated Windows, macOS, and manylinux wheels to be compiled with
 OpenSSL 1.1.1g.
 * 2.9 - 2020-04-02
 - BACKWARDS INCOMPATIBLE: Support for Python 3.4 has been removed due
 to low usage and maintenance burden.
 - BACKWARDS INCOMPATIBLE: Support for OpenSSL 1.0.1 has been removed.
 Users on older version of OpenSSL will need to upgrade.
 - BACKWARDS INCOMPATIBLE: Support for LibreSSL 2.6.x has been removed.
 - Removed support for calling public_bytes() with no arguments, as per
 our deprecation policy. You must now pass encoding and format.
 - BACKWARDS INCOMPATIBLE: Reversed the order in which rfc4514_string()
 returns the RDNs as required by RFC 4514.
 - Updated Windows, macOS, and manylinux wheels to be compiled with
 OpenSSL 1.1.1f.
 - Added support for parsing single_extensions in an OCSP response.
 - NameAttribute values can now be empty strings.

Add openSSL_111d.patch to make this version of the package compatible
 with OpenSSL 1.1.1d, thus fixing bsc#1149792.

bsc#1101820 CVE-2018-10903 GCM tag forgery via truncated tag in
 finalize_with_tag API

Update in SLE-15 (bsc#1177083, jsc#PM-2730, jsc#SLE-18312)

Include in SLE-15 (bsc#1176785, jsc#ECO-3105, jsc#PM-2352)

update to 2.9.2:
 * updated vectors for the cryptography 2.9.2 testing");

  script_tag(name:"affected", value:"'python-cryptography, python-cryptography-vectors' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Python2 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debuginfo", rpm:"python-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography", rpm:"python2-cryptography~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography-debuginfo", rpm:"python2-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debuginfo", rpm:"python-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography", rpm:"python2-cryptography~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography-debuginfo", rpm:"python2-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~2.9.2~150200.13.1", rls:"SLES15.0SP2"))) {
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
