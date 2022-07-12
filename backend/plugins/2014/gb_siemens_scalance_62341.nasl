###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_scalance_62341.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Siemens Scalance X-200 Series Switches Insufficient Entropy Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
CPE = "cpe:/h:siemens:scalance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103907");
  script_bugtraq_id(62341);
  script_cve_id("CVE-2013-5709");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");

  script_name("Siemens Scalance X-200 Series Switches Insufficient Entropy Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62341");
  script_xref(name:"URL", value:"http://subscriber.communications.siemens.com/");
  script_xref(name:"URL", value:"http://blog.ioactive.com/2014/02/the-password-is-irrelevant-too.html");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-17 17:18:56 +0100 (Mon, 17 Feb 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_siemens_scalance_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("siemens_scalance/installed");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to hijack web sessions over
the network without authentication. Other attacks are also possible.");
  script_tag(name:"vuldetect", value:"Check if it is possible to read the configuration with a HTTP GET request.");
  script_tag(name:"insight", value:"By requesting /fs/cfgFile.cfg it is possible to read the config of the remote device.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Siemens Scalance X-200 Series switches are prone to a vulnerability in
the entropy of random number generator.");
  script_tag(name:"affected", value:"Siemens Scalance X-200 Series switches running firmware versions prior
to 5.0.0 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE) ) exit( 0 );

url = "/fs/cfgFile.cfg";

if( http_vuln_check( port:port, url:url, pattern:"CLI\\SYSTEM" ) )
{
  security_message(port:port);
  exit(0);
}

exit(0);

