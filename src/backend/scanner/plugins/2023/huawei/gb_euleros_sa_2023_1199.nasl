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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1199");
  script_cve_id("CVE-2020-10735", "CVE-2021-28861");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-15 17:20:00 +0000 (Thu, 15 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2023-1199)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1199");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1199");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2023-1199 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in python. In algorithms with quadratic time complexity using non-binary bases, when using int('text'), a system could take 50ms to parse an int string with 100,000 digits and 5s for 1,000,000 digits (float, decimal, int.from_bytes(), and int() for binary bases 2, 4, 8, 16, and 32 are not affected). The highest threat from this vulnerability is to system availability.(CVE-2020-10735)

** DISPUTED ** Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to no protection against multiple (/) at the beginning of URI path which may leads to information disclosure. NOTE: this is disputed by a third party because the http.server.html documentation page states 'Warning: http.server is not recommended for production. It only implements basic security checks.'(CVE-2021-28861)");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.7.4~7.h48.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.7.4~7.h48.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
