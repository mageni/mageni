# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4770.1");
  script_cve_id("CVE-2014-3619", "CVE-2018-10841", "CVE-2018-1088", "CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10924", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930", "CVE-2018-14651", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14654", "CVE-2018-14659", "CVE-2018-14660", "CVE-2018-14661");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 22:13:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-4770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4770-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4770-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glusterfs' package(s) announced via the USN-4770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GlusterFS incorrectly handled network requests. An
attacker could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 14.04 ESM. (CVE-2014-3619)

It was discovered that GlusterFS incorrectly handled user permissions. An
authenticated attacker could possibly use this to add himself to a trusted
storage pool and perform privileged operations on volumes. This issue only
affected Ubuntu 16.04 ESM and Ubuntu 18.04 ESM. (CVE-2018-10841)

It was discovered that GlusterFS incorrectly handled mounting gluster
volumes. An attacker could possibly use this issue to also mount shared
gluster volumes and escalate privileges through malicious cronjobs. This
issue only affected Ubuntu 16.04 ESM and Ubuntu 18.04 ESM. (CVE-2018-1088)

It was discovered that GlusterFS incorrectly handled file paths. An
attacker could possibly use this issue to create arbitrary files and
execute arbitrary code. (CVE-2018-10904)

It was discovered that GlusterFS incorrectly handled mounting volumes. An
attacker could possibly use this issue to cause a denial of service or run
arbitrary code. (CVE-2018-10907)

It was discovered that GlusterFS incorrectly handled negative key length
values. An attacker could possibly use this issue to obtain sensitive
information. (CVE-2018-10911)

It was discovered that GlusterFS incorrectly handled FUSE requests. An
attacker could use this issue to obtain sensitive information.
(CVE-2018-10913, CVE-2018-10914)

It was discovered that GlusterFS incorrectly handled the file creation
process. An authenticated attacker could possibly use this issue to create
arbitrary files and obtain sensitive information. (CVE-2018-10923)

It was discovered that GlusterFS incorrectly handled certain inputs. An
authenticated attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 18.04 ESM. (CVE-2018-10924)

It was discovered that GlusterFS incorrectly handled RPC requests. An
attacker could possibly use this issue to write files to an arbitrary
location and execute arbitrary code. (CVE-2018-10926, CVE-2018-10927,
CVE-2018-10928, CVE-2018-10929, CVE-2018-10930)

It was discovered that the fix for CVE-2018-10926, CVE-2018-10927,
CVE-2018-10928, CVE-2018-10929, CVE-2018-10930 was incomplete. A remote
authenticated attacker could possibly use this issue to execute arbitrary
code or cause a denial of service. (CVE-2018-14651)

It was discovered that GlusterFS incorrectly handled certain files. A
remote authenticated attacker could possibly use this issue to cause a
denial of service. (CVE-2018-14652)

It was discovered that GlusterFS incorrectly handled RPC requests. A remote
authenticated attacker could possibly use this issue to cause a denial of
service or other unspecified impact. (CVE-2018-14653)

It was discovered that GlusterFS incorrectly handled mount volumes
operation. A remote attacker ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-client", ver:"3.4.2-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-common", ver:"3.4.2-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-server", ver:"3.4.2-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-client", ver:"3.7.6-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-common", ver:"3.7.6-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-server", ver:"3.7.6-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-client", ver:"3.13.2-1ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-common", ver:"3.13.2-1ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-server", ver:"3.13.2-1ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
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
