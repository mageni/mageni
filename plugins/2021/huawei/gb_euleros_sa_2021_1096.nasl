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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1096");
  script_version("2021-01-19T10:11:10+0000");
  script_cve_id("CVE-2018-0618", "CVE-2018-13796", "CVE-2020-12108", "CVE-2020-12137", "CVE-2020-15011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-01-20 11:07:43 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 10:11:10 +0000 (Tue, 19 Jan 2021)");
  script_name("Huawei EulerOS: Security Advisory for mailman (EulerOS-SA-2021-1096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"EulerOS-SA", value:"2021-1096");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1096");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'mailman' package(s) announced via the EulerOS-SA-2021-1096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting vulnerability in Mailman 2.1.26 and earlier allows remote authenticated attackers to inject arbitrary web script or HTML via unspecified vectors.(CVE-2018-0618)

An issue was discovered in GNU Mailman before 2.1.28. A crafted URL can cause arbitrary text to be displayed on a web page from a trusted site.(CVE-2018-13796)

/options/mailman in GNU Mailman before 2.1.31 allows Arbitrary Content Injection.(CVE-2020-12108)

GNU Mailman 2.x before 2.1.30 uses the .obj extension for scrubbed application/octet-stream MIME parts. This behavior may contribute to XSS attacks against list-archive visitors, because an HTTP reply from an archive web server may lack a MIME type, and a web browser may perform MIME sniffing, conclude that the MIME type should have been text/html, and execute JavaScript code.(CVE-2020-12137)

GNU Mailman before 2.1.33 allows arbitrary content injection via the Cgi/private.py private archive login page.(CVE-2020-15011)");

  script_tag(name:"affected", value:"'mailman' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.15~26.1.h2", rls:"EULEROS-2.0SP3"))) {
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