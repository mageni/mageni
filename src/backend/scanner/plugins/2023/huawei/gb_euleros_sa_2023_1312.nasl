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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1312");
  script_cve_id("CVE-2022-41860", "CVE-2022-41861");
  script_tag(name:"creation_date", value:"2023-02-09 04:29:52 +0000 (Thu, 09 Feb 2023)");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 19:53:00 +0000 (Tue, 24 Jan 2023)");

  script_name("Huawei EulerOS: Security Advisory for freeradius (EulerOS-SA-2023-1312)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1312");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1312");
  script_xref(name:"URL", value:"https://freeradius.org/security/Upstream");
  script_xref(name:"URL", value:"https://github.com/FreeRADIUS/freeradius-server/commit/f1cdbb33ec61c4a64a");
  script_xref(name:"URL", value:"https://freeradius.org/security/Upstream");
  script_xref(name:"URL", value:"https://github.com/FreeRADIUS/freeradius-server/commit/0ec2b39d260e");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freeradius' package(s) announced via the EulerOS-SA-2023-1312 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When an EAP-SIM supplicant sends an unknown SIM option, the server will try to look that option up in the internal dictionaries. This lookup will fail, but the SIM code will not check for that failure. Instead, it will dereference a NULL pointer, and cause the server to crash.References:[link moved to references] fix:[link moved to references](CVE-2022-41860)

A malicious RADIUS client or home server can send a malformed abinary attribute which can cause the server to crash.References:[link moved to references] fix:[link moved to references](CVE-2022-41861)");

  script_tag(name:"affected", value:"'freeradius' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.15~14.h7.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
