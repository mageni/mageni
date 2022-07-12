###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0406_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for docker, openSUSE-SU-2018:0406-1 (docker,)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851696");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-10 07:53:50 +0100 (Sat, 10 Feb 2018)");
  script_cve_id("CVE-2017-14992", "CVE-2017-16539");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for docker, openSUSE-SU-2018:0406-1 (docker, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for docker, docker-runc, containerd,
  golang-github-docker-libnetwork fixes several issues.

  These security issues were fixed:

  - CVE-2017-16539: The DefaultLinuxSpec function in oci/defaults.go docker
  did not block /proc/scsi pathnames, which allowed attackers to trigger
  data loss (when certain older Linux kernels are used) by leveraging
  Docker container access to write a 'scsi remove-single-device' line to
  /proc/scsi/scsi, aka SCSI MICDROP (bnc#1066801)

  - CVE-2017-14992: Lack of content verification in docker allowed a remote
  attacker to cause a Denial of Service via a crafted image layer payload,
  aka gzip bombing. (bnc#1066210)

  These non-security issues were fixed:

  - bsc#1059011: The systemd service helper script used a timeout of 60
  seconds to start the daemon, which is insufficient in cases where the
  daemon takes longer to start. Instead, set the service type from
  'simple' to 'notify' and remove the now superfluous helper script.

  - bsc#1057743: New requirement with new version of docker-libnetwork.

  - bsc#1032287: Missing docker systemd configuration.

  - bsc#1057743: New 'symbol' for libnetwork requirement.

  - bsc#1057743: Update secrets patch to handle 'old' containers that have
  orphaned secret data no longer available on the host.

  - bsc#1055676: Update patches to correctly handle volumes and mounts when
  Docker is running with user namespaces enabled.

  - bsc#1045628:: Add patch to make the dm storage driver remove a
  container's rootfs mountpoint before attempting to do libdm operations
  on it. This helps avoid complications when live mounts will leak into
  containers.

  - bsc#1069758: Upgrade Docker to v17.09.1_ce (and obsolete
  docker-image-migrator).

  - bsc#1021227: bsc#1029320 bsc#1058173 -- Enable docker devicemapper
  support for deferred removal/deletion within Containers module.

  - bsc#1046024: Correct interaction between Docker and SuSEFirewall2, to
  avoid breaking Docker networking after boot.

  - bsc#1048046: Build with -buildmode=pie to make all binaries PIC.

  - bsc#1072798: Remove dependency on obsolete bridge-utils.

  - bsc#1064926: Set --start-timeout=2m by default to match upstream.

  - bsc#1065109, bsc#1053532: Use the upstream makefile so that Docker can
  get the commit ID in `docker info`.

  Please note that the 'docker-runc' package is just a rename of the old
  'runc' package to match that we now ship the Docker fork of runc.

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"docker, on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00012.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"containerd", rpm:"containerd~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-ctr-debuginfo", rpm:"containerd-ctr-debuginfo~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-debuginfo", rpm:"containerd-debuginfo~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-debugsource", rpm:"containerd-debugsource~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2066_7b2b1feb1de4~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2066_7b2b1feb1de4~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc4+gitr3338_3f2f8b84a77f~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc4+gitr3338_3f2f8b84a77f~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-debugsource", rpm:"docker-runc-debugsource~1.0.0rc4+gitr3338_3f2f8b84a77f~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2066_7b2b1feb1de4~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-github-docker-libnetwork-debugsource", rpm:"golang-github-docker-libnetwork-debugsource~0.7.0.1+gitr2066_7b2b1feb1de4~5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker", rpm:"docker~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-test", rpm:"containerd-test~0.2.9+gitr706_06b9cb351610~16.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-test", rpm:"docker-runc-test~1.0.0rc4+gitr3338_3f2f8b84a77f~2.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~17.09.1_ce~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
