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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0090");
  script_cve_id("CVE-2022-0824", "CVE-2022-0829");
  script_tag(name:"creation_date", value:"2022-03-08 04:09:07 +0000 (Tue, 08 Mar 2022)");
  script_version("2022-03-08T04:09:07+0000");
  script_tag(name:"last_modification", value:"2022-03-08 11:27:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-03-08 04:09:07 +0000 (Tue, 08 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0090");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0090.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30116");
  script_xref(name:"URL", value:"https://www.webmin.com/security.html");
  script_xref(name:"URL", value:"https://www.webmin.com/changes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webmin' package(s) announced via the MGASA-2022-0090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Less privileged Webmin users who do not have any File Manager module
restrictions configured can access files with root privileges, if using
the default Authentic theme (CVE-2022-0824, CVE-2022-0829).");

  script_tag(name:"affected", value:"'webmin' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"webmin", rpm:"webmin~1.990~1.mga8", rls:"MAGEIA8"))) {
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
