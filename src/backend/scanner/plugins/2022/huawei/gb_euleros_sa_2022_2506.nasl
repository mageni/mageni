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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2506");
  script_cve_id("CVE-2021-44790", "CVE-2022-22719", "CVE-2022-22720", "CVE-2022-22721", "CVE-2022-23943", "CVE-2022-26377", "CVE-2022-28614", "CVE-2022-28615", "CVE-2022-29404", "CVE-2022-30522");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-18 18:01:00 +0000 (Fri, 18 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2022-2506)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2506");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2506");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'httpd' package(s) announced via the EulerOS-SA-2022-2506 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerability though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.(CVE-2021-44790)

An out-of-bounds read vulnerability was found in httpd. A very large input to the ap_strcmp_match function can lead to an integer overflow and result in an out-of-bounds read.(CVE-2022-28615)

An HTTP request smuggling vulnerability was found in the mod_proxy_ajp module of httpd. This flaw allows an attacker to smuggle requests to the AJP server, where it forwards requests.(CVE-2022-26377)

An out-of-bounds read vulnerability was found in httpd. A very large input to the ap_rputs and ap_rwrite functions can lead to an integer overflow and result in an out-of-bounds read.(CVE-2022-28614)

A flaw was found in the mod_lua module of httpd. A malicious request to a Lua script that calls parsebody(0) can lead to a denial of service due to no default limit on the possible input size.(CVE-2022-29404)

A flaw was found in the mod_sed module of httpd. A very large input to the mod_sed module can result in a denial of service due to excessively large memory allocations.(CVE-2022-30522)

Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data.This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions.(CVE-2022-23943)

A carefully crafted request body can cause a read to a random memory area which could cause the process to crash.This issue affects Apache HTTP Server 2.4.52 and earlier.(CVE-2022-22719)

If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems an integer overflow happens which later causes out of bounds writes.This issue affects Apache HTTP Server 2.4.52 and earlier.(CVE-2022-22721)

Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling.(CVE-2022-22720)");

  script_tag(name:"affected", value:"'httpd' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~80.1.h17.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
