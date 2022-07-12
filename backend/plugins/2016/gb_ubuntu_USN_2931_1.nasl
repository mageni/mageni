###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-utopic USN-2931-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842687");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-15 06:36:20 +0100 (Tue, 15 Mar 2016)");
  script_cve_id("CVE-2016-3134", "CVE-2013-4312", "CVE-2015-8767", "CVE-2016-2069",
		"CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545",
		"CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-lts-utopic USN-2931-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ben Hawkes discovered that the Linux
  netfilter implementation did not correctly perform validation when handling
  IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code
  with administrative privileges. (CVE-2016-3134)

  It was discovered that the Linux kernel did not properly enforce rlimits
  for file descriptors sent over UNIX domain sockets. A local attacker could
  use this to cause a denial of service. (CVE-2013-4312)

  It was discovered that a race condition existed when handling heartbeat-
  timeout events in the SCTP implementation of the Linux kernel. A remote
  attacker could use this to cause a denial of service. (CVE-2015-8767)

  Andy Lutomirski discovered a race condition in the Linux kernel's
  translation lookaside buffer (TLB) handling of flush events. A local
  attacker could use this to cause a denial of service or possibly leak
  sensitive information. (CVE-2016-2069)

  Andrey Konovalov discovered that the ALSA USB MIDI driver incorrectly
  performed a double-free. A local attacker with physical access could use
  this to cause a denial of service (system crash) or possibly execute
  arbitrary code with administrative privileges. (CVE-2016-2384)

  Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
  framework did not verify that a FIFO was attached to a client before
  attempting to clear it. A local attacker could use this to cause a denial
  of service (system crash). (CVE-2016-2543)

  Dmitry Vyukov discovered that a race condition existed in the Advanced
  Linux Sound Architecture (ALSA) framework between timer setup and closing
  of the client, resulting in a use-after-free. A local attacker could use
  this to cause a denial of service. (CVE-2016-2544)

  Dmitry Vyukov discovered a race condition in the timer handling
  implementation of the Advanced Linux Sound Architecture (ALSA) framework,
  resulting in a use-after-free. A local attacker could use this to cause a
  denial of service (system crash). (CVE-2016-2545)

  Dmitry Vyukov discovered race conditions in the Advanced Linux Sound
  Architecture (ALSA) framework's timer ioctls leading to a use-after-free. A
  local attacker could use this to cause a denial of service (system crash)
  or possibly execute arbitrary code. (CVE-2016-2546)

  Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
  framework's handling of high resolution timers did not properly manage its
  data structures. A local attacker could use this to cause a denial of
  service (system hang or crash) or possibly execute arbitrary code.
  CVE-2016-2547

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux-lts-utopic on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2931-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-generic", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-generic-lpae", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-lowlatency", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-powerpc-e500mc", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-powerpc-smp", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-powerpc64-emb", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-67-powerpc64-smp", ver:"3.16.0-67.87~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
