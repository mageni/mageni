# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1094.1");
  script_cve_id("CVE-2021-21261");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:40 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:02+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-27 19:34:00 +0000 (Wed, 27 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1094-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211094-1/");
  script_xref(name:"URL", value:"https://ostreedev.github.io/ostree/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak, libostree, xdg-desktop-portal, xdg-desktop-portal-gtk' package(s) announced via the SUSE-SU-2021:1094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flatpak, libostree, xdg-desktop-portal,
xdg-desktop-portal-gtk fixes the following issues:

libostree:

Update to version 2020.8

Enable LTO. (bsc#1133120)

This update contains scalability improvements and bugfixes.

Caching-related HTTP headers are now supported on summaries and
 signatures, so that they do not have to be re-downloaded if not changed
 in the meanwhile.

Summaries and delta have been reworked to allow more fine-grained
 fetching.

Fixes several bugs related to atomic variables, HTTP timeouts, and
 32-bit architectures.

Static deltas can now be signed to more easily support offline
 verification.

There's now support for multiple initramfs images, Is it possible to
 have a 'main' initramfs image and a secondary one which represents local
 configuration.

The documentation is now moved to [link moved to references]

Fix for an assertion failure when upgrading from systems before ostree
 supported devicetree.

ostree no longer hardlinks zero sized files to avoid hitting filesystem
 maximum link counts.

ostree now supports `/` and `/boot` being on the same filesystem.

Improvements to the GObject Introspection metadata, some (cosmetic)
 static analyzer fixes, a fix for the immutable bit on s390x, dropping a
 deprecated bit in the systemd unit file.

Fix a regression 2020.4 where the 'readonly sysroot' changes incorrectly
 left the sysroot read-only
 on systems that started out with a read-only `/` (most of them, e.g.
 Fedora Silverblue/IoT at least).

The default dracut config now enables reproducibility.

There is a new ostree admin unlock `--transient`. This should to be a
 foundation for further support for 'live' updates.

New `ed25519` signing support, powered by `libsodium`.

stree commit gained a new `--base` argument, which significantly
 simplifies constructing 'derived' commits, particularly for systems
 using SELinux.

Handling of the read-only sysroot was reimplemented to run in the
 initramfs and be more reliable. Enabling the `readonly=true` flag in the
 repo config is recommended.

Several fixes in locking for the temporary 'staging' directories OSTree
 creates, particularly on NFS.

A new `timestamp-check-from-rev` option was added for pulls, which makes
 downgrade protection more reliable and will be used by Fedora CoreOS.

Several fixes and enhancements made for 'collection' pulls including a
 new `--mirror` option.

The ostree commit command learned a new `--mode-ro-executables` which
 enforces `W^R` semantics
 on all executables.

Added a new commit metadata key `OSTREE_COMMIT_META_KEY_ARCHITECTURE`
 to help standardize the architecture of the OSTree commit. This could be
 used on the client side for example to sanity-check that the commit
 matches the architecture of the machine before deploying.

Stop invalid usage of `%_libexecdir`:
 + Use `%{_prefix}/lib` where appropriate.
 + Use `_systemdgeneratordir` for t... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'flatpak, libostree, xdg-desktop-portal, xdg-desktop-portal-gtk' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2");

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

if(release == "SLES15.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debuginfo", rpm:"flatpak-debuginfo~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debugsource", rpm:"flatpak-debugsource~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-zsh-completion", rpm:"flatpak-zsh-completion~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0-debuginfo", rpm:"libflatpak0-debuginfo~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree", rpm:"libostree~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debuginfo", rpm:"libostree-debuginfo~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debugsource", rpm:"libostree-debugsource~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-devel", rpm:"libostree-devel~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-flatpak", rpm:"system-user-flatpak~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Flatpak-1_0", rpm:"typelib-1_0-Flatpak-1_0~1.10.2~4.6.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-OSTree-1_0", rpm:"typelib-1_0-OSTree-1_0~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal", rpm:"xdg-desktop-portal~1.8.0~5.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-debuginfo", rpm:"xdg-desktop-portal-debuginfo~1.8.0~5.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-debugsource", rpm:"xdg-desktop-portal-debugsource~1.8.0~5.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-devel", rpm:"xdg-desktop-portal-devel~1.8.0~5.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-gtk", rpm:"xdg-desktop-portal-gtk~1.8.0~3.3.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-gtk-debuginfo", rpm:"xdg-desktop-portal-gtk-debuginfo~1.8.0~3.3.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-gtk-debugsource", rpm:"xdg-desktop-portal-gtk-debugsource~1.8.0~3.3.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-gtk-lang", rpm:"xdg-desktop-portal-gtk-lang~1.8.0~3.3.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-lang", rpm:"xdg-desktop-portal-lang~1.8.0~5.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-1-1", rpm:"libostree-1-1~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-1-1-debuginfo", rpm:"libostree-1-1-debuginfo~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debuginfo", rpm:"libostree-debuginfo~2020.8~3.3.2", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debugsource", rpm:"libostree-debugsource~2020.8~3.3.2", rls:"SLES15.0SP2"))){
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
