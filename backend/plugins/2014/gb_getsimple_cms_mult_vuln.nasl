###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# GetSimple CMS Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:getsimple:getsimple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804225");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2012-6621", "CVE-2013-7243");
  script_bugtraq_id(53501);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 17:46:37 +0530 (Tue, 21 Jan 2014)");
  script_name("GetSimple CMS Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_getsimple_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GetSimple_cms/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75534");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75535");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124711");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/112643");

  script_tag(name:"summary", value:"This host is running GetSimple CMS and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted string via HTTP GET request and check whether it
  is able to inject HTML code.");

  script_tag(name:"insight", value:"Flaw exists in upload.php, theme.php, pages.php, settings.php and index.php
  scripts, which fail to properly sanitize user-supplied input to 'path',
  'err', 'error' and 'success' parameter and 'Custom Permalink Structure',
  'Display name', 'Email Address' fields");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject HTML code or
  steal the victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"GetSimple CMS 3.1, 3.1.2, 3.2.3, Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/admin/index.php?success=>"<iframe%20src=http://www.example.com>';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"http://www.example.com" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
