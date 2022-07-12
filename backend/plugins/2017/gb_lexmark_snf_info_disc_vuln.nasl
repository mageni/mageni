###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lexmark_snf_info_disc_vuln.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Lexmark Scan To Network Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:lexmark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140358");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-06 08:42:19 +0700 (Wed, 06 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-13771");

  script_tag(name:"qod_type", value:"exploit");

  script_name("Lexmark Scan To Network Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printers_detect.nasl");
  script_mandatory_keys("lexmark_printer/installed");

  script_tag(name:"summary", value:"Lexmark Scan to Network <= 3.2.9 is prone to an information disclosure
  vulnerability.");

  script_tag(name:"insight", value:"Scan To Network application supports the configuration of network
  credentials and if used they will be stored in plaintext and transmitted in every request to the configuration tab.
  It is possible to obatain these credentials which could be used later to escalate privileges in the network or
  get access to scanned documents.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Aug/46");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/cgi-bin/direct/printer/prtappauth/apps/ImportExportServlet?exportButton=clicked';

if (http_vuln_check(port: port, url: url, pattern: 'cifs.pwd "', check_header: TRUE,
                    extra_check: 'cifs.uName "')) {
  report = "It was possible to obtain network credentials over the following url:\n\n" +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
