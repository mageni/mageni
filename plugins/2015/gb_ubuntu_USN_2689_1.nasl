###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-utopic USN-2689-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842389");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-30 05:13:46 +0200 (Thu, 30 Jul 2015)");
  script_cve_id("CVE-2015-3290", "CVE-2015-1333", "CVE-2015-3291", "CVE-2015-5157");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-lts-utopic USN-2689-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Andy Lutomirski discovered a flaw in the
Linux kernel's handling of nested NMIs (non-maskable interrupts). An unprivileged
local user could exploit this flaw to cause a denial of service (system crash)
or potentially escalate their privileges. (CVE-2015-3290)

Colin King discovered a flaw in the add_key function of the Linux kernel's
keyring subsystem. A local user could exploit this flaw to cause a denial
of service (memory exhaustion). (CVE-2015-1333)

Andy Lutomirski discovered a flaw that allows user to cause the Linux
kernel to ignore some NMIs (non-maskable interrupts). A local unprivileged
user could exploit this flaw to potentially cause the system to miss
important NMIs resulting in unspecified effects. (CVE-2015-3291)

Andy Lutomirski and Petr Matousek discovered that an NMI (non-maskable
interrupt) that interrupts userspace and encounters an IRET fault is
incorrectly handled by the Linux kernel. An unprivileged local user could
exploit this flaw to cause a denial of service (kernel OOPs), corruption,
or potentially escalate privileges on the system. (CVE-2015-5157)");
  script_tag(name:"affected", value:"linux-lts-utopic on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2689-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-generic", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-generic-lpae", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-lowlatency", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-powerpc-e500mc", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-powerpc-smp", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-powerpc64-emb", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-45-powerpc64-smp", ver:"3.16.0-45.60~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
