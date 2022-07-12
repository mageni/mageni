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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0160");
  script_cve_id("CVE-2018-19565", "CVE-2018-19566", "CVE-2018-19567", "CVE-2018-19568", "CVE-2018-5805", "CVE-2018-5806", "CVE-2021-3624");
  script_tag(name:"creation_date", value:"2022-05-09 04:28:10 +0000 (Mon, 09 May 2022)");
  script_version("2022-05-09T04:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-09 10:04:03 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 15:45:00 +0000 (Mon, 25 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0160");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0160.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24107");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/11/27/1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YDVWQ5ZUMZUOMBBPVXPXX6XNCBNZ2BMJ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcraw' package(s) announced via the MGASA-2022-0160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer over-read in crop_masked_pixels in dcraw through 9.28 could be
used by attackers able to supply malicious files to crash an application
that bundles the dcraw code or leak private information. (CVE-2018-19565)

A heap buffer over-read in parse_tiff_ifd in dcraw through 9.28 could be
used by attackers able to supply malicious files to crash an application
that bundles the dcraw code or leak private information. (CVE-2018-19566)

A floating point exception in parse_tiff_ifd in dcraw through 9.28 could
be used by attackers able to supply malicious files to crash an application
that bundles the dcraw code. (CVE-2018-19567)

A floating point exception in kodak_radc_load_raw in dcraw through 9.28
could be used by attackers able to supply malicious files to crash an
application that bundles the dcraw code. (CVE-2018-19568)

A boundary error within the 'quicktake_100_load_raw()' function
(internal/dcraw_common.cpp) in LibRaw versions prior to 0.18.8 can be
exploited to cause a stack-based buffer overflow and subsequently cause a
crash. (CVE-2018-5805)

An error within the 'leaf_hdr_load_raw()' function
(internal/dcraw_common.cpp) in LibRaw versions prior to 0.18.8 can be
exploited to trigger a NULL pointer dereference. (CVE-2018-5806)

There is an integer overflow vulnerability in dcraw. When the victim runs
dcraw with a maliciously crafted X3F input image, arbitrary code may be
executed in the victim's system. (CVE-2021-3624)");

  script_tag(name:"affected", value:"'dcraw' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dcraw", rpm:"dcraw~9.28.0~6.1.mga8", rls:"MAGEIA8"))) {
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
