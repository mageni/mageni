# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1118");
  script_version("2020-01-23T11:13:16+0000");
  script_cve_id("CVE-2018-5125", "CVE-2018-5127", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5144", "CVE-2018-5145", "CVE-2018-5146", "CVE-2018-5148");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:13:16 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:13:16 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for firefox (EulerOS-SA-2018-1118)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1118");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'firefox' package(s) announced via the EulerOS-SA-2018-1118 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of bounds write flaw was found in the processing of vorbis audio data. A maliciously crafted file or audio stream could cause the application to crash or, potentially, execute arbitrary code.(CVE-2018-5146)

Memory safety bugs fixed in Firefox 59 and Firefox ESR 52.7 (MFSA 2018-07) (CVE-2018-5125)

Buffer overflow manipulating SVG animatedPathSegList (MFSA 2018-07) (CVE-2018-5127)

Out-of-bounds write with malformed IPC messages (MFSA 2018-07) (CVE-2018-5129)

Mismatched RTP payload type can trigger memory corruption (MFSA 2018-07) (CVE-2018-5130)

Fetch API improperly returns cached copies of no-store/no-cache resources (MFSA 2018-07) (CVE-2018-5131)

Integer overflow during Unicode conversion (MFSA 2018-07) (CVE-2018-5144)

Memory safety bugs fixed in Firefox ESR 52.7 (MFSA 2018-07) (CVE-2018-5145)

Use-after-free in compositor potentially allows code execution (CVE-2018-5148)");

  script_tag(name:"affected", value:"'firefox' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~52.7.3~1.h2", rls:"EULEROS-2.0SP2"))) {
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