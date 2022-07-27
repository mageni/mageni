###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0914_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2016:0914-1 (xen)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851262");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-11 12:47:20 +0530 (Mon, 11 Apr 2016)");
  script_cve_id("CVE-2013-4533", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539",
                "CVE-2014-0222", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718",
                "CVE-2015-1779", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512",
                "CVE-2015-8345", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743",
                "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1570",
                "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2391",
                "CVE-2016-2392", "CVE-2016-2538");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2016:0914-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"xen was updated to fix 26 security issues.

  These security issues were fixed:

  - CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load function in
  hw/arm/pxa2xx.c allowed remote attackers to cause a denial of service or
  possibly execute arbitrary code via a crafted s- rx_level value in a
  savevm image (bsc#864655).

  - CVE-2013-4537: The ssi_sd_transfer function in hw/sd/ssi-sd.c allowed
  remote attackers to execute arbitrary code via a crafted arglen value in
  a savevm image (bsc#864391).

  - CVE-2013-4538: Multiple buffer overflows in the ssd0323_load function in
  hw/display/ssd0323.c allowed remote attackers to cause a denial of
  service (memory corruption) or possibly execute arbitrary code via
  crafted (1) cmd_len, (2) row, or (3) col values  (4) row_start and
  row_end values  or (5) col_star and col_end values in a savevm image
  (bsc#864769).

  - CVE-2013-4539: Multiple buffer overflows in the tsc210x_load function in
  hw/input/tsc210x.c might have allowed remote attackers to execute
  arbitrary code via a crafted (1) precision, (2) nextprecision, (3)
  function, or (4) nextfunction value in a savevm image (bsc#864805).

  - CVE-2014-0222: Integer overflow in the qcow_open function in
  block/qcow.c allowed remote attackers to cause a denial of service
  (crash) via a large L2 table in a QCOW version 1 image (bsc#877642).

  - CVE-2014-3689: The vmware-vga driver (hw/display/vmware_vga.c) allowed
  local guest users to write to qemu memory locations and gain privileges
  via unspecified parameters related to rectangle handling (bsc#901508).

  - CVE-2014-7815: The set_pixel_format function in ui/vnc.c allowed remote
  attackers to cause a denial of service (crash) via a small
  bytes_per_pixel value (bsc#902737).

  - CVE-2014-9718: The (1) BMDMA and (2) AHCI HBA interfaces in the IDE
  functionality had multiple interpretations of a function's return value,
  which allowed guest OS users to cause a host OS denial of service
  (memory consumption or infinite loop, and system crash) via a PRDT with
  zero complete sectors, related to the bmdma_prepare_buf and
  ahci_dma_prepare_buf functions (bsc#928393).

  - CVE-2015-1779: The VNC websocket frame decoder allowed remote attackers
  to cause a denial of service (memory and CPU consumption) via a large
  (1) websocket payload or (2) HTTP headers section (bsc#924018).

  - CVE-2015-5278: Infinite loop in ne2000_receive() function (bsc#945989).

  - CVE-2015-6855: hw/ide/core.c did not properly restrict the commands
  accepted by an ATAPI device, which allowed guest users to cause a denial
  of service or possibly have unspeci ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"xen on openSUSE Leap 42.1");
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

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.2_06_k4.1.15_8~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.5.2_06_k4.1.15_8~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.5.2_06~12.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
