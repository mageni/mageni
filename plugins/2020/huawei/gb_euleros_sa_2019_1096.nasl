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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1096");
  script_version("2020-01-23T11:31:01+0000");
  script_cve_id("CVE-2018-15126", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20022", "CVE-2018-20024", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-6307");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:31:01 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:31:01 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for libvncserver (EulerOS-SA-2019-1096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1096");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'libvncserver' package(s) announced via the EulerOS-SA-2019-1096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibVNC before 0.9.12 contains multiple heap out-of-bounds write vulnerabilities in libvncclient/rfbproto.c. The fix for CVE-2018-20019 was incomplete.(CVE-2018-20748)

LibVNC before 0.9.12 contains a heap out-of-bounds write vulnerability in libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.(CVE-2018-20749)

LibVNC through 0.9.12 contains a heap out-of-bounds write vulnerability in libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.(CVE-2018-20750)

LibVNC before commit 7b1ef0ffc4815cab9a96c7278394152bdc89dc4d contains heap out-of-bound write vulnerability inside structure in VNC client code that can result remote code execution(CVE-2018-20020)

LibVNC before commit ca2a5ac02fbbadd0a21fabba779c1ea69173d10b contains heap use-after-free vulnerability in server code of file transfer extension that can result remote code execution.(CVE-2018-6307)

LibVNC before commit 73cb96fec028a576a5a24417b57723b55854ad7b contains heap use-after-free vulnerability in server code of file transfer extension that can result remote code execution(CVE-2018-15126)

LibVNC before commit a83439b9fbe0f03c48eb94ed05729cb016f8b72f contains multiple heap out-of-bound write vulnerabilities in VNC client code that can result remote code execution(CVE-2018-20019)

LibVNC before 2f5b2ad1c6c99b1ac6482c95844a84d66bb52838 contains multiple weaknesses CWE-665: Improper Initialization vulnerability in VNC client code that allows attacker to read stack memory and can be abuse for information disclosure. Combined with another vulnerability, it can be used to leak stack memory layout and in bypassing ASLR(CVE-2018-20022)

LibVNC before commit 4a21bbd097ef7c44bb000c3bd0907f96a10e4ce7 contains null pointer dereference in VNC client code that can result DoS.(CVE-2018-20024)");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.9~12.h10", rls:"EULEROS-2.0SP3"))) {
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