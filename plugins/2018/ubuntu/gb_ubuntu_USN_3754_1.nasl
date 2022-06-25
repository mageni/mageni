###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3754_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux USN-3754-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843628");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-25 06:48:47 +0200 (Sat, 25 Aug 2018)");
  script_cve_id("CVE-2016-10208", "CVE-2017-11472", "CVE-2017-11473", "CVE-2017-14991",
                "CVE-2017-15649", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529",
                "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535",
                "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16643",
                "CVE-2017-16644", "CVE-2017-16645", "CVE-2017-16650", "CVE-2017-16911",
                "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-17558",
                "CVE-2017-18255", "CVE-2017-18270", "CVE-2017-2583", "CVE-2017-2584",
                "CVE-2017-5549", "CVE-2017-5897", "CVE-2017-6345", "CVE-2017-6348",
                "CVE-2017-7518", "CVE-2017-7645", "CVE-2017-8831", "CVE-2017-9984",
                "CVE-2017-9985", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10323",
                "CVE-2018-10675", "CVE-2018-10877", "CVE-2018-10881", "CVE-2018-1092",
                "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-12233", "CVE-2018-13094",
                "CVE-2018-13405", "CVE-2018-13406", "CVE-2017-2671", "CVE-2018-1000204",
                "CVE-2018-10021");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3754-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ralf Spenneberg discovered that the ext4 implementation in the Linux kernel
did not properly validate meta block groups. An attacker with physical
access could use this to specially craft an ext4 image that causes a denial
of service (system crash). (CVE-2016-10208)

It was discovered that an information disclosure vulnerability existed in
the ACPI implementation of the Linux kernel. A local attacker could use
this to expose sensitive information (kernel memory addresses).
(CVE-2017-11472)

It was discovered that a buffer overflow existed in the ACPI table parsing
implementation in the Linux kernel. A local attacker could use this to
construct a malicious ACPI table that, when loaded, caused a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-11473)

It was discovered that the generic SCSI driver in the Linux kernel did not
properly initialize data returned to user space in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2017-14991)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-15649)

Andrey Konovalov discovered that the Ultra Wide Band driver in the Linux
kernel did not properly check for an error condition. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-16526)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16527)

Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel did
not properly validate USB audio buffer descriptors. A physically proximate
attacker could use this cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16529)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB interface association descriptors. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16531)

Andrey Konovalov discovered that the usbtest device driver in the Linux
kernel did not properly validate endpoint metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2017-16532)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB HID ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3754-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-generic", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-generic-lpae", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-lowlatency", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-powerpc-e500", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-powerpc-e500mc", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-powerpc-smp", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-powerpc64-emb", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-157-powerpc64-smp", ver:"3.13.0-157.207", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"3.13.0.157.167", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
