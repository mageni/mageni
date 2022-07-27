###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2375_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-ec2 USN-2375-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841997");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-10 06:09:42 +0200 (Fri, 10 Oct 2014)");
  script_cve_id("CVE-2014-3184", "CVE-2014-3185", "CVE-2014-6410");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ec2 USN-2375-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ben Hawkes reported some off by one errors for report descriptors in the
Linux kernel's HID stack. A physically proximate attacker could exploit
these flaws to cause a denial of service (out-of-bounds write) via a
specially crafted device. (CVE-2014-3184)

Several bounds check flaws allowing for buffer overflows were discovered in
the Linux kernel's Whiteheat USB serial driver. A physically proximate
attacker could exploit these flaws to cause a denial of service (system
crash) via a specially crafted device. (CVE-2014-3185)

A flaw was discovered in the Linux kernel's UDF filesystem (used on some
CD-ROMs and DVDs) when processing indirect ICBs. An attacker who can cause
CD, DVD or image file with a specially crafted inode to be mounted can
cause a denial of service (infinite loop or stack consumption).
(CVE-2014-6410)");
  script_tag(name:"affected", value:"linux-ec2 on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2375-1/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-371-ec2", ver:"2.6.32-371.87", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}