###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuuo_nvrmini.nasl 11516 2018-09-21 11:15:17Z asteins $
#
# NUUO NVRmini 2 3.0.8 - Remote Root Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:nuuo:nuuo';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107042");
  script_version("$Revision: 11516 $");
  script_cve_id("CVE-2016-5674", "CVE-2016-5675", "CVE-2016-5676", "CVE-2016-5677",
                "CVE-2016-5678", "CVE-2016-5679", "CVE-2016-5680");
  script_bugtraq_id(92318);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 13:15:17 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 13:16:06 +0200 (Tue, 23 Aug 2016)");
  script_name("NUUO NVRmini 2 3.0.8 - Remote Root Vulnerability");

  script_tag(name:"summary", value:"This host is running NUUO NVRmini and is
  affected by a remote root exploit vulnerability.");

  script_tag(name:"vuldetect", value:"This check tries to execute a command
  on the remote target as a root user");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The hideen page '__debugging_center_utils__.php' fails to properly validate
    the log parameter.

  - The 'handle_daylightsaving.php' page does not sanitise the NTPServer
    parameter.

  - An error in cgi-bin/cgi_system binary.

  - The hideen page '__nvr_status___.php' fails to properly validate
    the parameter.

  - The sn parameter of the 'transfer_license' command in cgi_main does
    not properly validate user-provided input.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code as the root user and send
  a specially crafted request to stack-based buffer overflow.");

  script_tag(name:"affected", value:"NUUO NVRmini Versions 2.3.0.8 and below");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138220/NUUO-3.0.8-Remote-Root.html");
  script_xref(name:"URL", value:"http://www.vfocus.net/art/20160809/12861.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40200");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/856152");

  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE, service:'www' )) exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))  exit(0);

url = dir + '__debugging_center_utils___.php?log=;id';

if( http_vuln_check( port:http_port, url:url, pattern:'uid=[0-9]+.*gid=[0-9]+' ) )
{
 report = report_vuln_url( port:http_port, url:url );
 security_message ( data: report, port: http_port ) ;
 exit( 0 );
}

exit( 99 );
