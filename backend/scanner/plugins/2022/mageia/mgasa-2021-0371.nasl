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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0371");
  script_cve_id("CVE-2021-28363", "CVE-2021-33503", "CVE-2021-3572");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-15 07:15:00 +0000 (Thu, 15 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0371");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0371.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29010");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29041");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4S65ZQVZ2ODGB52IC7VJDBUK4M5INCXL/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/3L3JUBMPJJ7WYXI6JHX6KKYPPX676PR6/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009129.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the MGASA-2021-0371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in python-pip in the way it handled Unicode separators in git
references. A remote attacker could possibly use this issue to install a
different revision on a repository (CVE-2021-3572).

The bundled python-urllib3 was also vulnerable to:
The urllib3 library 1.26.x before 1.26.4 for Python omits SSL certificate
validation in some cases involving HTTPS to HTTPS proxies. The initial
connection to the HTTPS proxy (if an SSLContext isn't given via proxy_config)
doesn't verify the hostname of the certificate. This means certificates for
different servers that still validate properly with the default urllib3
SSLContext will be silently accepted (CVE-2021-28363).

An issue was discovered in urllib3 before 1.26.5. When provided with a URL
containing many @ characters in the authority component, the authority regular
expression exhibits catastrophic backtracking, causing a denial of service if a
URL were passed as a parameter or redirected to via an HTTP redirect
(CVE-2021-33503).");

  script_tag(name:"affected", value:"'python-pip' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~20.3.3~3.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~20.3.3~3.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~20.3.3~3.3.mga8", rls:"MAGEIA8"))) {
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
