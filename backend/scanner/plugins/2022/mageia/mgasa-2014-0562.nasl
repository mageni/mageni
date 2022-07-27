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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0562");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 20:50:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0562)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0562");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0562.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14872");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2014-011.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1174844");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1174851");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1174856");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/12/22/12");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the MGASA-2014-0562 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated unzip package fix security vulnerabilities:

The unzip command line tool is affected by heap-based buffer overflows within
the CRC32 verification (CVE-2014-8139), the test_compr_eb() (CVE-2014-8140)
and the getZip64Data() (CVE-2014-8141) functions. The input errors may result
in arbitrary code execution. A specially crafted zip file, passed to the
command unzip -t, can be used to trigger the vulnerability.

OOB access (both read and write) issues also exist in test_compr_eb()
that can result in application crash or other unspecified impact. A
specially crafted zip file, passed to the command unzip -t, can be used to
trigger the issues.");

  script_tag(name:"affected", value:"'unzip' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.0~7.2.mga4", rls:"MAGEIA4"))) {
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
