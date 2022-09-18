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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2311");
  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092");
  script_tag(name:"creation_date", value:"2022-09-14 04:42:02 +0000 (Wed, 14 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 18:57:00 +0000 (Thu, 07 Oct 2021)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2022-2311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2311");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2311");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2022-2311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Docker CLI is the command line interface for the docker container runtime. A bug was found in the Docker CLI where running `docker login my-private-registry.example.com` with a misconfigured configuration file (typically `~/.docker/config.json`) listing a `credsStore` or `credHelpers` that could not be executed would result in any provided credentials being sent to `registry-1.docker.io` rather than the intended private registry. This bug has been fixed in Docker CLI 20.10.9. Users should update to this version as soon as possible. For users unable to update ensure that any configured credsStore or credHelpers entries in the configuration file reference an installed credential helper that is executable and on the PATH.(CVE-2021-41092)

Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. When containers included executable programs with extended permission bits (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade limit access to the host to trusted users. Limit access to host volumes to trusted containers.(CVE-2021-41091)

Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where attempting to copy files using `docker cp` into a specially-crafted container can result in Unix file permission changes for existing files in the host's filesystem, widening access to others. This bug does not directly allow files to be read, modified, or executed without an additional cooperating process. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running containers do not need to be restarted.(CVE-2021-41089)");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0.129~1.h62.30.15.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
