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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0006");
  script_cve_id("CVE-2021-29136", "CVE-2021-32635", "CVE-2021-41190");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 14:22:00 +0000 (Thu, 10 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0006)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0006");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0006.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29027");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/BMX7XV7YNNNOVKKIOOPNENIXY64H4ZEY/");
  script_xref(name:"URL", value:"https://github.com/sylabs/singularity/releases/tag/v3.7.4");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U5WJLLGD3LSUWRS73C4NPIWYTMST4QO5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/D2IU6GJMCV5CQKUQZLHBP6EHSIZZXC3X/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/L3AGIEOXZIUUEYYMWKJCJCQI7V235UTR/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'singularity' package(s) announced via the MGASA-2022-0006 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A dependency used to extract docker/OCI image layers can be tricked into
modifying host files by creating a malicious layer that has a symlink with
the name '.' (or '/'), when running as root. (CVE-2021-29136)
Dde to incorrect use of a default URL, `singularity` action commands
(`run`/`shell`/`exec`) specifying a container using a `library://` URI
will always attempt to retrieve the container from the default remote
endpoint (`cloud.sylabs.io`) rather than the configured remote endpoint.
An attacker may be able to push a malicious container to the default
remote endpoint with a URI that is identical to the URI used by a victim
with a non-default remote endpoint, thus executing the malicious container.
Only action commands (`run`/`shell`/`exec`) against `library://` URIs are
affected. Other commands such as `pull` / `push` respect the configured
remote endpoint. (CVE-2021-32635)
If a Content-Type header changed between two pulls of the same digest, a
client may interpret the resulting content differently. (CVE-2021-41190)");

  script_tag(name:"affected", value:"'singularity' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"singularity", rpm:"singularity~3.8.5~1.mga8", rls:"MAGEIA8"))) {
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
