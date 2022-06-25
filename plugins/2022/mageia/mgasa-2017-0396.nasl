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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0396");
  script_cve_id("CVE-2017-13089", "CVE-2017-13090");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0396");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0396.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21947");
  script_xref(name:"URL", value:"https://www.viestintavirasto.fi/en/cybersecurity/vulnerabilities/2017/haavoittuvuus-2017-037.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wget, wget' package(s) announced via the MGASA-2017-0396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The http.c:skip_short_body() function is called in some circumstances,
such as when processing redirects. When the response is sent chunked,
the chunk parser uses strtol() to read each chunk's length, but
doesn't check that the chunk length is a non-negative number. The
code then tries to skip the chunk in pieces of 512 bytes by using the
MIN() macro, but ends up passing the negative chunk length to
connect.c:fd_read(). As fd_read() takes an int argument, the high
32 bits of the chunk length are discarded, leaving fd_read() with
a completely attacker controlled length argument (CVE-2017-13089).

The retr.c:fd_read_body() function is called when processing OK
responses. When the response is sent chunked, the chunk parser uses
strtol() to read each chunk's length, but doesn't check that the chunk
length is a non-negative number. The code then tries to read the chunk
in pieces of 8192 bytes by using the MIN() macro, but ends up passing
the negative chunk length to retr.c:fd_read(). As fd_read() takes an
int argument, the high 32 bits of the chunk length are discarded,
leaving fd_read() with a completely attacker controlled length
argument. The attacker can corrupt malloc metadata after the allocated
buffer (CVE-2017-13090).");

  script_tag(name:"affected", value:"'wget, wget' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"wget", rpm:"wget~1.15~5.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"wget", rpm:"wget~1.19.2~1.mga6", rls:"MAGEIA6"))) {
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
