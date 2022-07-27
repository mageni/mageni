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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0012");
  script_cve_id("CVE-2014-6395", "CVE-2014-6396", "CVE-2014-9376", "CVE-2014-9377", "CVE-2014-9378", "CVE-2014-9379", "CVE-2014-9380", "CVE-2014-9381");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:35:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0012");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0012.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14919");
  script_xref(name:"URL", value:"https://www.obrela.com/home/security-labs/advisories/osi-advisory-osi-1402/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ettercap' package(s) announced via the MGASA-2015-0012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ettercap package fixes security vulnerabilities:

Heap-based buffer overflow in the dissector_postgresql function in
dissectors/ec_postgresql.c in Ettercap before 8.1 allows remote attackers to
cause a denial of service or possibly execute arbitrary code via a crafted
password length value that is inconsistent with the actual length of the
password (CVE-2014-6395).

The dissector_postgresql function in dissectors/ec_postgresql.c in Ettercap
before 8.1 allows remote attackers to cause a denial of service and possibly
execute arbitrary code via a crafted password length, which triggers a 0
character to be written to an arbitrary memory location (CVE-2014-6396).

Integer underflow in Ettercap 8.1 allows remote attackers to cause a denial
of service (out-of-bounds write) and possibly execute arbitrary code via a
small size variable value in the dissector_dhcp function in
dissectors/ec_dhcp.c, length value to the dissector_gg function in
dissectors/ec_gg.c, or string length to the get_decode_len function in
ec_utils.c or a request without a username or password to the
dissector_TN3270 function in dissectors/ec_TN3270.c (CVE-2014-9376).

Heap-based buffer overflow in the nbns_spoof function in
plug-ins/nbns_spoof/nbns_spoof.c in Ettercap 8.1 allows remote attackers to
cause a denial of service or possibly execute arbitrary code via a large
netbios packet (CVE-2014-9377).

Ettercap 8.1 does not validate certain return values, which allows remote
attackers to cause a denial of service (crash) or possibly execute arbitrary
code via a crafted name to the parse_line function in mdns_spoof/mdns_spoof.c
or base64 encoded password to the dissector_imap function in
dissectors/ec_imap.c (CVE-2014-9378).

The radius_get_attribute function in dissectors/ec_radius.c in Ettercap 8.1
performs an incorrect cast, which allows remote attackers to cause a denial
of service (crash) or possibly execute arbitrary code via unspecified
vectors, which triggers a stack-based buffer overflow (CVE-2014-9379).

The dissector_cvs function in dissectors/ec_cvs.c in Ettercap 8.1 allows
remote attackers to cause a denial of service (out-of-bounds read) via a
packet containing only a CVS_LOGIN signature (CVE-2014-9380).

Integer signedness error in the dissector_cvs function in dissectors/ec_cvs.c
in Ettercap 8.1 allows remote attackers to cause a denial of service (crash)
via a crafted password, which triggers a large memory allocation
(CVE-2014-9381).");

  script_tag(name:"affected", value:"'ettercap' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ettercap", rpm:"ettercap~0.8.0~3.1.mga4", rls:"MAGEIA4"))) {
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
