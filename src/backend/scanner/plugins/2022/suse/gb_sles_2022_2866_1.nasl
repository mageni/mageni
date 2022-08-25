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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2866.1");
  script_cve_id("CVE-2022-1706");
  script_tag(name:"creation_date", value:"2022-08-24 07:59:30 +0000 (Wed, 24 Aug 2022)");
  script_version("2022-08-24T07:59:30+0000");
  script_tag(name:"last_modification", value:"2022-08-24 07:59:30 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 03:15:00 +0000 (Thu, 26 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2866-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2866-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222866-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd-presets-common-SUSE' package(s) announced via the SUSE-SU-2022:2866-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd-presets-common-SUSE fixes the following issues:

CVE-2022-1706: Fixed accessible configs from unprivileged containers in
 VMs running on VMware products (bsc#1199524).

The following non-security bugs were fixed:

Modify branding-preset-states to fix systemd-presets-common-SUSE not
 enabling new user systemd service preset configuration just as it
 handles system service presets. By passing an (optional) second
 parameter 'user', the save/apply-changes commands now work with user
 services instead of system ones (bsc#1200485)

Add the wireplumber user service preset to enable it by default in
 SLE15-SP4 where it replaced pipewire-media-session, but keep
 pipewire-media-session preset so we don't have to branch the
 systemd-presets-common-SUSE package for SP4 (bsc#1200485)");

  script_tag(name:"affected", value:"'systemd-presets-common-SUSE' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"systemd-presets-common-SUSE", rpm:"systemd-presets-common-SUSE~15~150100.8.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"systemd-presets-common-SUSE", rpm:"systemd-presets-common-SUSE~15~150100.8.17.1", rls:"SLES15.0SP4"))) {
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
