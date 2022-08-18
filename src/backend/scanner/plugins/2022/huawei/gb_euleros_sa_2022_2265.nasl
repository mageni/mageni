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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2265");
  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092");
  script_tag(name:"creation_date", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_version("2022-08-18T04:37:33+0000");
  script_tag(name:"last_modification", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 18:57:00 +0000 (Thu, 07 Oct 2021)");

  script_name("Huawei EulerOS: Security Advisory for docker (EulerOS-SA-2022-2265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2265");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker' package(s) announced via the EulerOS-SA-2022-2265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A confidential data leak vulnerability was found in Docker CLI. The execution of docker login to a private registry may send provided credentials in a misconfigured docker credentials store to the registry-1.docker.io rather than the specified private registry. This flaw allows an attacker to steal private registry credentials. The highest threat from this vulnerability is to confidentiality.(CVE-2021-41092)

A file permissions vulnerability was found in the Moby (Docker Engine). The Moby data directory (usually /var/lib/docker) contains subdirectories with insufficiently restricted permissions, allowing unprivileged Linux users to traverse directory contents and execute programs. When the running container contains executable programs with the extended permission bits (like setuid), unprivileged Linux users can discover and execute those programs. Additionally, when the UID of an unprivileged Linux user on the host collides with the file owner or group inside a container, the unprivileged Linux user on the host can discover, read, and modify those files. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2021-41091)

A file permissions vulnerability was found in Moby (Docker Engine). Copying files by using docker cp into a specially-crafted container can result in Unix file permission changes for existing files in the host's filesystem, which might lead to permissions escalation and allow an attacker access to restricted data.(CVE-2021-41089)");

  script_tag(name:"affected", value:"'docker' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0.101~1.h55.23.12.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
