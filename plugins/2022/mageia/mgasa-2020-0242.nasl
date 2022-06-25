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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0242");
  script_cve_id("CVE-2014-6053", "CVE-2018-7225", "CVE-2019-15681");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0242.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25786");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2014");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vino' package(s) announced via the MGASA-2020-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated vino packages fix security vulnerabilities:

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c in
LibVNCServer did not properly handle attempts to send a large amount of
ClientCutText data, which allowed remote attackers to cause a denial of
service (memory consumption or daemon crash) via a crafted message that
was processed by using a single unchecked malloc (CVE-2014-6053).

An issue was discovered in LibVNCServer. rfbProcessClientNormalMessage()
in rfbserver.c did not sanitize msg.cct.length, leading to access to
uninitialized and potentially sensitive data or possibly unspecified other
impact (e.g., an integer overflow) via specially crafted VNC packets
(CVE-2018-7225).

LibVNC contained a memory leak in VNC server code, which allowed an
attacker to read stack memory and could be abused for information
disclosure. Combined with another vulnerability, it could be used to
leak stack memory and bypass ASLR. This attack appeared to be exploitable
via network connectivity (CVE-2019-15681).

The bundled libvncserver code in vino has been patched to fix these issues.");

  script_tag(name:"affected", value:"'vino' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"vino", rpm:"vino~3.22.0~3.1.mga7", rls:"MAGEIA7"))) {
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
