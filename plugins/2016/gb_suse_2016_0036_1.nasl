###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0036_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for grub2 openSUSE-SU-2016:0036-1 (grub2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851189");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-02 17:17:23 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for grub2 openSUSE-SU-2016:0036-1 (grub2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Fix buffer overflows when reading username
  and password. (bsc#956631, CVE-2015-8370)

  - Check MS-DOS header to find PE file header. (bsc#954126)

  - Use dirname for copying Xen kernel and initrd to esp. (bsc#955493)

  - Fix reading password by grub2-mkpasswd-pbdk2 without controlling tty.
  (bsc#954519)

  - Add luks, gcry_rijndael and gcry_sha1 to signed EFI image to support
  LUKS partition in default setup. (bsc#917427, bsc#955609)

  - Expand list of grub.cfg search path in PV Xen guests for systems
  installed on btrfs snapshots. (bsc#946148, bsc#952539) This update was
  imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name:"affected", value:"grub2 on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-branding-upstream", rpm:"grub2-branding-upstream~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-debuginfo", rpm:"grub2-debuginfo~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-x86_64-xen", rpm:"grub2-x86_64-xen~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub2-i386-efi", rpm:"grub2-i386-efi~2.02~beta2~76.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
