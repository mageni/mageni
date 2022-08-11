###############################################################################
# OpenVAS Vulnerability Test
#
# TorrentVolve archive.php XSS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900577");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2101");
  script_name("TorrentVolve archive.php XSS Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8931");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51088");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_torrentvolve_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("torrentvolve/detected");

  script_tag(name:"affected", value:"TorrentVolve 1.4 and prior.");

  script_tag(name:"insight", value:"The flaw occurs because archive.php does not sanitise the data
  passed into 'deleteTorrent' parameter before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running TorrentVolve and is prone to Cross Site
  Scripting vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to delete arbitrary
  files on the affected system if register_globals is enabled.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

tvPort = get_http_port(default:80);

tvVer = get_kb_item("www/" + tvPort + "/TorrentVolve");
tvVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tvVer);
if(tvVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:tvVer[1], test_version:"1.4")){
  security_message(tvPort);
}
