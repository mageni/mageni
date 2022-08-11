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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2455");
  script_version("2020-01-23T12:59:10+0000");
  script_cve_id("CVE-2013-4118", "CVE-2013-4119", "CVE-2014-0250", "CVE-2014-0791", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839", "CVE-2018-1000852");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:59:10 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:59:10 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2019-2455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2455");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'freerdp' package(s) announced via the EulerOS-SA-2019-2455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP before 1.1.0-beta+2013071101 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) by disconnecting before authentication has finished.(CVE-2013-4119)

FreeRDP FreeRDP 2.0.0-rc3 released version before commit 205c612820dac644d665b5bb1cdf437dc5ca01e3 contains a Other/Unknown vulnerability in channels/drdynvc/client/drdynvc_main.c, drdynvc_process_capability_request that can result in The RDP server can read the client's memory.. This attack appear to be exploitable via RDPClient must connect the rdp server with echo option. This vulnerability appears to have been fixed in after commit 205c612820dac644d665b5bb1cdf437dc5ca01e3.(CVE-2018-1000852)

FreeRDP before 1.1.0-beta1 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via unspecified vectors.(CVE-2013-4118)

Multiple integer overflows in client/X11/xf_graphics.c in FreeRDP allow remote attackers to have an unspecified impact via the width and height to the (1) xf_Pointer_New or (2) xf_Bitmap_Decompress function, which causes an incorrect amount of memory to be allocated.(CVE-2014-0250)

Integer overflow in the license_read_scope_list function in libfreerdp/core/license.c in FreeRDP through 1.0.2 allows remote RDP servers to cause a denial of service (application crash) or possibly have unspecified other impact via a large ScopeCount value in a Scope List in a Server License Request packet.(CVE-2014-0791)

An exploitable code execution vulnerability exists in the RDP receive functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server response can cause an out-of-bounds write resulting in an exploitable condition. An attacker can compromise the server or use a man in the middle to trigger this vulnerability.(CVE-2017-2835)

An exploitable denial of service vulnerability exists within the reading of proprietary server certificates in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2836)

An exploitable denial of service vulnerability exists within the handling of security data in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2837)

An exploitable denial of service vulnerability exists within the handling of challenge packets in  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'freerdp' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.2~6.1.h4", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~1.0.2~6.1.h4", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-plugins", rpm:"freerdp-plugins~1.0.2~6.1.h4", rls:"EULEROS-2.0SP2"))) {
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