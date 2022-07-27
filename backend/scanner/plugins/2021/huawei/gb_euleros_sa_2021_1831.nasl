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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1831");
  script_version("2021-05-03T06:22:44+0000");
  script_cve_id("CVE-2019-10146", "CVE-2019-10179", "CVE-2019-10221", "CVE-2019-11358", "CVE-2020-1721", "CVE-2020-25715", "CVE-2021-20179");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-05-03 10:25:12 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 06:22:44 +0000 (Mon, 03 May 2021)");
  script_name("Huawei EulerOS: Security Advisory for pki-core (EulerOS-SA-2021-1831)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1831");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1831");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'pki-core' package(s) announced via the EulerOS-SA-2021-1831 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The highest threat from this vulnerability is to data confidentiality and integrity.(CVE-2021-20179)

A Reflected Cross Site Scripting flaw was found in all pki-core 10.x.x versions module from the pki-core server due to the CA Agent Service not properly sanitizing the certificate request page. An attacker could inject a specially crafted value that will be executed on the victim's browser.(CVE-2019-10146)

A vulnerability was found in all pki-core 10.x.x versions, where the Key Recovery Authority (KRA) Agent Service did not properly sanitize recovery request search page, enabling a Reflected Cross Site Scripting (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted Javascript code.(CVE-2019-10179)

A flaw was found in pki-core. A specially crafted POST request can be used to reflect a DOM-based cross-site scripting (XSS) attack to inject code into the search query form which can get automatically executed. The highest threat from this vulnerability is to data integrity.(CVE-2020-25715)

A Reflected Cross Site Scripting vulnerability was found in all pki-core 10.x.x versions, where the pki-ca module from the pki-core server. This flaw is caused by missing sanitization of the GET URL parameters. An attacker could abuse this flaw to trick an authenticated user into clicking a specially crafted link which can execute arbitrary code when viewed in a browser.(CVE-2019-10221)

jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.(CVE-2019-11358)

A flaw was found in the Key Recovery Authority (KRA) Agent Service where it did not properly sanitize the recovery ID during a key recovery request, enabling a Reflected Cross-Site Scripting (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted Javascript code.(CVE-2020-1721)");

  script_tag(name:"affected", value:"'pki-core' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"pki-base", rpm:"pki-base~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-base-java", rpm:"pki-base-java~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-kra", rpm:"pki-kra~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-server", rpm:"pki-server~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-tools", rpm:"pki-tools~10.4.1~11.h7", rls:"EULEROS-2.0SP3"))) {
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