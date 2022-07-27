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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1564");
  script_cve_id("CVE-2020-11017", "CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11058", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11521", "CVE-2020-11523", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13397", "CVE-2020-15103", "CVE-2020-4030");
  script_tag(name:"creation_date", value:"2022-04-25 07:33:45 +0000 (Mon, 25 Apr 2022)");
  script_version("2022-04-25T07:33:45+0000");
  script_tag(name:"last_modification", value:"2022-04-25 10:10:30 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 10:15:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2022-1564)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1564");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1564");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freerdp' package(s) announced via the EulerOS-SA-2022-1564 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libfreerdp/cache/bitmap.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Out of bounds read.(CVE-2020-11525)

In FreeRDP less than or equal to 2.0.0, a possible resource exhaustion vulnerability can be performed. Malicious clients could trigger out of bound reads causing memory allocation with random size.(CVE-2020-11018)

In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_AuthenticateMessage.(CVE-2020-11087)

In FreeRDP less than or equal to 2.0.0, when running with logger set to 'WLOG_TRACE', a possible crash of application could occur due to a read of an invalid array index. Data could be printed as string to local terminal.(CVE-2020-11019)

In FreeRDP less than or equal to 2.0.0, there is an out-of-bound data read from memory in clear_decompress_subcode_rlex, visualized on screen as color.(CVE-2020-11040)

In FreeRDP after 1.1 and before 2.0.0, a stream out-of-bounds seek in rdp_read_font_capability_set could lead to a later out-of-bounds read. As a result, a manipulated client or server might force a disconnect due to an invalid data read.(CVE-2020-11058)

In FreeRDP less than or equal to 2.0.0, an Integer Overflow to Buffer Overflow exists. When using /video redirection, a manipulated server can instruct the client to allocate a buffer with a smaller size than requested due to an integer overflow in size calculation. With later messages, the server can manipulate the client to write data out of bound to the previously allocated buffer.(CVE-2020-11038)

In FreeRDP before version 2.1.2, there is an out of bounds read in TrioParse. Logging might bypass string length checks due to an integer overflow.(CVE-2020-4030)

libfreerdp/gdi/region.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Integer Overflow.(CVE-2020-11523)

libfreerdp/codec/planar.c in FreeRDP version > 1.0 through 2.0.0-rc4 has an Out-of-bounds Write.(CVE-2020-11521)

An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been detected in security_fips_decrypt in libfreerdp/core/security.c due to an uninitialized value.(CVE-2020-13397)

In FreeRDP less than or equal to 2.0.0, by providing manipulated input a malicious client can create a double free condition and crash the server.(CVE-2020-11017)

In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_NegotiateMessage.(CVE-2020-11088)

In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_ntlm_v2_client_challenge that reads up to 28 bytes out-of-bound to an internal structure.(CVE-2020-11086)

In FreeRDP less than or equal to 2.0.0, an outside controlled array index is used unchecked for data used as configuration for sound backend (alsa, oss, pulse, ...). The most likely outcome is a crash of the client instance followed by no or distorted sound or a session disconnect. If a user cannot upgrade to the patched version, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freerdp' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~44.rc3.h11.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~2.0.0~44.rc3.h11.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~2.0.0~44.rc3.h11.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
