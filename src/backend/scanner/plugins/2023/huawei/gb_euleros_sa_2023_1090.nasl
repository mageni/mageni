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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1090");
  script_cve_id("CVE-2019-8921", "CVE-2019-8922", "CVE-2021-43400");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-08 17:32:00 +0000 (Mon, 08 Nov 2021)");

  script_name("Huawei EulerOS: Security Advisory for bluez (EulerOS-SA-2023-1090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1090");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1090");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bluez' package(s) announced via the EulerOS-SA-2023-1090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow was discovered in bluetoothd in BlueZ through 5.48. There isn't any check on whether there is enough space in the destination buffer. The function simply appends all data passed to it. The values of all attributes that are requested are appended to the output buffer. There are no size checks whatsoever, resulting in a simple heap overflow if one can craft a request where the response is large enough to overflow the preallocated buffer. This issue exists in service_attr_req gets called by process_request (in sdpd-request.c), which also allocates the response buffer.(CVE-2019-8922)

An issue was discovered in gatt-database.c in BlueZ 5.61. A use-after-free can occur when a client disconnects during D-Bus processing of a WriteValue call.(CVE-2021-43400)

An issue was discovered in bluetoothd in BlueZ through 5.48. The vulnerability lies in the handling of a SVC_ATTR_REQ by the SDP implementation. By crafting a malicious CSTATE, it is possible to trick the server into returning more bytes than the buffer actually holds, resulting in leaking arbitrary heap data. The root cause can be found in the function service_attr_req of sdpd-request.c. The server does not check whether the CSTATE data is the same in consecutive requests, and instead simply trusts that it is the same.(CVE-2019-8921)");

  script_tag(name:"affected", value:"'bluez' package(s) on Huawei EulerOS Virtualization 3.0.2.6.");

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

if(release == "EULEROSVIRT-3.0.2.6") {

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~5.44~4.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.6"))) {
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
