###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ti-omap4 USN-2967-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.842735");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-10 05:20:13 +0200 (Tue, 10 May 2016)");
  script_cve_id("CVE-2013-4312", "CVE-2015-7515", "CVE-2015-7566", "CVE-2015-7833",
 		"CVE-2015-8767", "CVE-2015-8812", "CVE-2016-0723", "CVE-2015-1805",
 		"CVE-2016-0774", "CVE-2016-0821", "CVE-2016-2069", "CVE-2016-2543",
	 	"CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547",
 		"CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-ti-omap4 USN-2967-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the Linux kernel
  did not properly enforce rlimits for file descriptors sent over UNIX domain
  sockets. A local attacker could use this to cause a denial of service.
  (CVE-2013-4312)

  Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7515)

  Ralf Spenneberg discovered that the USB driver for Clie devices in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7566)

  Ralf Spenneberg discovered that the usbvision driver in the Linux kernel
  did not properly sanity check the interfaces and endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7833)

  It was discovered that a race condition existed when handling heartbeat-
  timeout events in the SCTP implementation of the Linux kernel. A remote
  attacker could use this to cause a denial of service. (CVE-2015-8767)

  Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
  kernel's CXGB3 driver. A local attacker could use this to cause a denial of
  service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

  It was discovered that a race condition existed in the ioctl handler for
  the TTY driver in the Linux kernel. A local attacker could use this to
  cause a denial of service (system crash) or expose sensitive information.
  (CVE-2016-0723)

  It was discovered that the Linux kernel did not keep accurate track of pipe
  buffer details when error conditions occurred, due to an incomplete fix for
  CVE-2015-1805. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code with administrative
  privileges. (CVE-2016-0774)

  Zach Riggle discovered that the Linux kernel's list poison feature did not
  take into account the mmap_min_addr value. A local attacker could use this
  to bypass the kernel's poison-pointer protection mechanism while attempting
  to exploit an existing kernel vulnerability. (CVE-2016-0821)

  Andy Lutomirski discovered a race condition in the Linux kernel's
  translation lookaside buffer (TLB) handling of flush events. A local
  attacker could use this to cause a denial of service or possibly leak
  sensitive information. (CVE-2016-2069)

  Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
  framework did not verify that a FIFO was attached to a c ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux-ti-omap4 on Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2967-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-1480-omap4", ver:"3.2.0-1480.106", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
