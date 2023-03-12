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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2015");
  script_cve_id("CVE-2010-0747");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 19:54:00 +0000 (Thu, 07 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-2015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2015");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2015");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drbd8, linux-modules-extra-2.6' package(s) announced via the DSA-2015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A local vulnerability has been discovered in drbd8.

Philipp Reisner fixed an issue in the drbd kernel module that allows local users to send netlink packets to perform actions that should be restricted to users with CAP_SYS_ADMIN privileges. This is a similar issue to those described by CVE-2009-3725.

This update also fixes an ABI compatibility issue which was introduced by linux-2.6 (2.6.26-21lenny3). The prebuilt drbd module packages listed in this advisory require a linux-image package version 2.6.26-21lenny3 or greater.

For the stable distribution (lenny), this problem has been fixed in drbd8 (2:8.0.14-2+lenny1).

We recommend that you upgrade your drbd8 packages.

The linux-modules-extra-2.6 package has been rebuilt against the updated drbd8 package to provide fixed prebuilt drbd8-modules packages. If, instead of using the prebuilt drbd8-modules packages, you have built and installed a local copy of the drbd module from the drbd8-source package (e.g., using module-assistant), you will need to follow the same steps you originally used to rebuild your module after upgrading the drbd8-source package.

Note: After upgrading a kernel module you must reload the module for the changes to take effect:

Shutdown all services that make use of the drbd module

Unload the previous drbd module (modprobe -r drbd)

Load the updated drbd module (modprobe drbd)

Restart any services that make use of the drbd module

A system reboot will also cause the updated module to be used.");

  script_tag(name:"affected", value:"'drbd8, linux-modules-extra-2.6' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-486", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-4kc-malta", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-5kc-malta", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-686-bigmem", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-686", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-alpha-generic", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-alpha-smp", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-amd64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-footbridge", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-iop32x", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-itanium", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-ixp4xx", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-mckinley", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-openvz-686", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-orion5x", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-parisc-smp", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-parisc", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-parisc64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-powerpc", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-powerpc64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-sparc64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-versatile", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-686", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"atl2-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+2.0.5-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-486", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-4kc-malta", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-5kc-malta", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-686-bigmem", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-686", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-alpha-generic", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-alpha-smp", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-amd64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-footbridge", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-iop32x", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-itanium", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-ixp4xx", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-mckinley", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-openvz-686", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-orion5x", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-parisc-smp", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-parisc", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-parisc64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-powerpc", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-powerpc64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-s390", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-s390x", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-sparc64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-versatile", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-686", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-xen-686", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aufs-modules-2.6.26-2-xen-amd64", ver:"2.6.26+0+20080719-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-486", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-686-bigmem", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-686", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-amd64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-footbridge", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-iop32x", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-itanium", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-ixp4xx", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-mckinley", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-openvz-686", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-orion5x", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-parisc-smp", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-parisc", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-parisc64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-powerpc", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-powerpc64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-s390", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-s390x", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-sparc64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-versatile", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-686", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-xen-686", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-modules-2.6.26-2-xen-amd64", ver:"2.6.26+8.0.14-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-source", ver:"2:8.0.14-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drbd8-utils", ver:"2:8.0.14-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-486", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-4kc-malta", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-5kc-malta", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-686-bigmem", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-686", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-alpha-generic", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-alpha-smp", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-amd64", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-footbridge", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-iop32x", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-itanium", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-ixp4xx", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-mckinley", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-openvz-686", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-orion5x", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-parisc-smp", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-parisc", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-parisc64", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-powerpc", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-powerpc64", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-sparc64", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"et131x-modules-2.6.26-2-versatile", ver:"2.6.26+1.2.3-2-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-486", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-686-bigmem", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-686", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-amd64", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-openvz-686", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-powerpc", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-powerpc64", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-vserver-686", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gspca-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+01.00.20-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-486", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-686-bigmem", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-686", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-amd64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-footbridge", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-iop32x", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-itanium", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-ixp4xx", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-mckinley", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-openvz-686", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-orion5x", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-powerpc", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-powerpc64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-s390", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-s390x", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-sparc64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-versatile", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-686", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-xen-686", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iscsitarget-modules-2.6.26-2-xen-amd64", ver:"2.6.26+0.4.16+svn162-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-486", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-4kc-malta", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-5kc-malta", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-686-bigmem", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-686", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-alpha-generic", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-alpha-smp", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-amd64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-footbridge", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-iop32x", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-itanium", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-ixp4xx", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-mckinley", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-openvz-686", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-orion5x", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-parisc-smp", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-parisc", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-parisc64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-powerpc", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-powerpc64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-s390", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-s390x", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-sparc64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-versatile", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-686", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-xen-686", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-modules-2.6.26-2-xen-amd64", ver:"2.6.26+3.2c-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-486", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-4kc-malta", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-5kc-malta", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-686-bigmem", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-686", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-alpha-generic", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-alpha-smp", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-amd64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-footbridge", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-iop32x", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-itanium", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-ixp4xx", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-mckinley", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-openvz-686", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-orion5x", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-parisc-smp", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-parisc", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-parisc64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-powerpc", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-powerpc64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-s390", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-s390x", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-sparc64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-versatile", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-686", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-xen-686", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lzma-modules-2.6.26-2-xen-amd64", ver:"2.6.26+4.43-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+0.9.72.1~dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6.26-2-powerpc", ver:"2.6.26+0.9.72.1~dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mol-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+0.9.72.1~dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-486", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-4kc-malta", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-5kc-malta", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-686-bigmem", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-686", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-alpha-generic", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-alpha-smp", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-amd64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-footbridge", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-iop32x", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-itanium", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-ixp4xx", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-mckinley", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-openvz-686", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-orion5x", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-parisc-smp", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-parisc", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-parisc64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-powerpc", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-powerpc64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-s390", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-s390x", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-sparc64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-versatile", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-686", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-xen-686", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nilfs2-modules-2.6.26-2-xen-amd64", ver:"2.6.26+2.0.4-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-486", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-4kc-malta", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-5kc-malta", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-686-bigmem", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-686", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-alpha-generic", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-alpha-smp", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-amd64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-footbridge", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-iop32x", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-itanium", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-ixp4xx", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-mckinley", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-openvz-686", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-orion5x", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-parisc-smp", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-parisc", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-parisc64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-powerpc", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-powerpc64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-s390", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-s390x", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-sparc64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-versatile", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-686", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-xen-686", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redhat-cluster-modules-2.6.26-2-xen-amd64", ver:"2.6.26+2.20081102-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-parisc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-parisc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-parisc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-parisc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-486", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-4kc-malta", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-5kc-malta", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-686-bigmem", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-686", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-alpha-generic", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-alpha-smp", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-amd64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-footbridge", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-iop32x", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-itanium", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-ixp4xx", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-mckinley", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-openvz-686", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-orion5x", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-parisc-smp", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-parisc", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-parisc64-smp", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-parisc64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-powerpc", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-powerpc64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-sparc64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-versatile", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-686", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-xen-686", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-2.6.26-2-xen-amd64", ver:"2.6.26+3.0.3+git20080724.dfsg.1-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-4kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-5kc-malta", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-alpha-generic", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-alpha-legacy", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-alpha-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-footbridge", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-iop32x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-ixp4xx", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-orion5x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-powerpc-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-r4k-ip22", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-r5k-cobalt", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-r5k-ip32", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-s390", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-sb1-bcm91250a", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-sb1a-bcm91480b", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-sparc64-smp", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-versatile", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-itanium", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-mckinley", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-powerpc", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-powerpc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-s390x", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-vserver-sparc64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-486", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-4kc-malta", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-5kc-malta", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-686-bigmem", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-686", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-alpha-generic", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-alpha-legacy", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-alpha-smp", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-amd64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-footbridge", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-iop32x", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-itanium", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-ixp4xx", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-mckinley", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-openvz-686", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-orion5x", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-powerpc-smp", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-powerpc", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-powerpc64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-r4k-ip22", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-r5k-cobalt", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-r5k-ip32", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-s390", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-s390x", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-sb1-bcm91250a", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-sparc64-smp", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-sparc64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-versatile", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-686", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-itanium", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-mckinley", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-powerpc", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-powerpc64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-s390x", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-vserver-sparc64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-xen-686", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-2.6.26-2-xen-amd64", ver:"2.6.26+3.3-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-xen-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6-xen-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-486", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-686-bigmem", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-686", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-amd64", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-openvz-686", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-vserver-686", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-xen-686", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tp-smapi-modules-2.6.26-2-xen-amd64", ver:"2.6.26+0.37-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-486", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-686-bigmem", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-openvz-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-modules-2.6.26-2-vserver-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-486", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-openvz-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-openvz-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-vserver-686-bigmem", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-vserver-686", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6-vserver-amd64", ver:"2:2.6.26-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-486", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-686-bigmem", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-amd64", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-openvz-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-openvz-amd64", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-vserver-686-bigmem", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-vserver-686", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-modules-2.6.26-2-vserver-amd64", ver:"2.6.26+1.6.6-dfsg-6+lenny3", rls:"DEB5"))) {
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
