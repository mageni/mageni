###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1497_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for deluge openSUSE-SU-2017:1497-1 (deluge)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851563");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-06-07 06:48:00 +0200 (Wed, 07 Jun 2017)");
  script_cve_id("CVE-2017-7178", "CVE-2017-9031");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for deluge openSUSE-SU-2017:1497-1 (deluge)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'deluge'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for deluge fixes two security
  issues: - CVE-2017-9031: A remote attacker may have used a directory traversal
  vulnerability in the web interface (bsc#1039815) - CVE-2017-7178: A remote
  attacher could have exploited a CSRF vulnerability to trick a logged-in user to
  perform actions in the WebUI (bsc#1039958) In addition, deluge was updated to
  1.3.15 with the following fixes and changes: - Core: Fix issues with displaying
  libtorrent-rasterbar single proxy. - Core: Fix libtorrent-rasterbar 1.2 trackers
  crashing Deluge UIs. - Core: Fix an error in torrent priorities causing file
  priority mismatch in UIs. - GtkUI: Fix column sort state not saved in Thinclient
  mode. - GtkUI: Fix a connection manager error with malformed ip. - GtkUI: Rename
  SystemTray/Indicator 'Pause/Resume All' to 'Pause/Resume Session'. - GtkUI:
  Workaround libtorrent-rasterbar single proxy by greying out unused proxy types.

  - Notification Plugin: Fix webui passing string for int port value. - AutoAdd
  Plugin: Add WebUI preferences page detailing lack of configuration via WebUI. -
  Label Plugin: Add WebUI preferences page detailing how to configure plugin. -
  Core: Fix 'Too many files open' errors. - Core: Add support for python-GeoIP for
  use with libtorrent 1.1. - Core: Fix a single proxy entry being overwritten
  resulting in no proxy set. - UI: Add the tracker_status translation to UIs. -
  GtkUI: Strip whitespace from infohash before checks. - GtkUI: Add a missed
  feature autofill infohash entry from clipboard. - WebUI: Backport bind interface
  option for server. - ConsoleUI: Fix a decode error comparing non-ascii (str)
  torrent names. - AutoAdd Plugin: Fixes for splitting magnets from file. - Remove
  the duplicate magnet extension when splitting. - Remove
  deluge-libtorrent-1.1-geoip.patch: fixed upstream.");
  script_tag(name:"affected", value:"deluge on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"deluge", rpm:"deluge~1.3.15~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"deluge-lang", rpm:"deluge-lang~1.3.15~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}