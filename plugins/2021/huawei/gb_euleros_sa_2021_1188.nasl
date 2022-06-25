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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1188");
  script_version("2021-02-05T15:25:36+0000");
  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839", "CVE-2020-11045", "CVE-2020-11096", "CVE-2020-11523");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-05 17:59:24 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-05 15:01:59 +0000 (Fri, 05 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2021-1188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1188");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1188");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'freerdp' package(s) announced via the EulerOS-SA-2021-1188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bound read in update_read_bitmap_data that allows client memory to be read to an image buffer. The result is displayed on screen as colour.(CVE-2020-11045)

libfreerdp/gdi/region.c in FreeRDP versions  1.0 through 2.0.0-rc4 has an Integer Overflow.(CVE-2020-11523)

In FreeRDP before version 2.1.2, there is a global OOB read in update_read_cache_bitmap_v3_order. As a workaround, one can disable bitmap cache with -bitmap-cache (default). This is fixed in version 2.1.2.(CVE-2020-11096)

An exploitable code execution vulnerability exists in the authentication functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server response can cause an out-of-bounds write resulting in an exploitable condition. An attacker can compromise the server or use a man in the middle attack to trigger this vulnerability.(CVE-2017-2834)

An exploitable code execution vulnerability exists in the RDP receive functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server response can cause an out-of-bounds write resulting in an exploitable condition. An attacker can compromise the server or use a man in the middle to trigger this vulnerability.(CVE-2017-2835)

An exploitable denial of service vulnerability exists within the reading of proprietary server certificates in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2836)

An exploitable denial of service vulnerability exists within the handling of security data in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2837)

An exploitable denial of service vulnerability exists within the handling of challenge packets in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2838)

An exploitable denial of service vulnerability exists within the handling of challenge packets in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2839)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.2~15.h11.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~1.0.2~15.h11.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-plugins", rpm:"freerdp-plugins~1.0.2~15.h11.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
